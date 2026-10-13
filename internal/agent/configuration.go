package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/AS214933/derpers-contorller/internal/model"
)

var hostnamePattern = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)
var containerNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
var imagePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/@:+-]*$`)
var digestPattern = regexp.MustCompile(`@sha256:[a-f0-9]{64}$`)

func (a *Agent) validateNodeConfig(c model.NodeConfig) error {
	if c.NodeID != a.identity.NodeID {
		return errors.New("config belongs to a different node")
	}
	if c.Revision < 1 || !hostnamePattern.MatchString(c.Hostname) || strings.Contains(c.Hostname, "..") {
		return errors.New("invalid node hostname or revision")
	}
	if c.HTTPSPort < 1 || c.HTTPSPort > 65535 || (c.STUNEnabled && (c.STUNPort < 1 || c.STUNPort > 65535)) {
		return errors.New("invalid node listening port")
	}
	if c.HTTPEnabled && c.HTTPSPort == 80 {
		return errors.New("HTTPS and HTTP probe ports must differ")
	}
	if c.ControllerURL != "" && strings.TrimRight(c.ControllerURL, "/") != strings.TrimRight(a.cfg.ControllerURL, "/") {
		return errors.New("node config cannot redirect the agent's controller identity")
	}
	if !imagePattern.MatchString(c.DerperImage) || !imagePattern.MatchString(c.CaddyImage) {
		return errors.New("node images must be explicit valid image references")
	}
	if a.applied != nil {
		for component, images := range map[string][2]string{"derper": {a.applied.DerperImage, c.DerperImage}, "caddy": {a.applied.CaddyImage, c.CaddyImage}} {
			if images[0] != images[1] && !a.allowedUpgrade(images[1], component) && !a.knownRollbackImage(images[1], component) {
				return errors.New("configuration image change requires an allowed repository and sha256 digest")
			}
		}
	}
	pair, err := tls.X509KeyPair([]byte(c.CertificatePEM), []byte(c.CertificateKeyPEM))
	if err != nil {
		return fmt.Errorf("invalid DERP server certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	if err := leaf.VerifyHostname(c.Hostname); err != nil {
		return fmt.Errorf("DERP certificate hostname: %w", err)
	}
	if time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
		return errors.New("DERP server certificate is not currently valid")
	}
	if c.CAPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(c.CAPEM)) {
			return errors.New("invalid additional server CA")
		}
	}
	for _, name := range []string{a.derperName(), a.caddyName()} {
		if !containerNamePattern.MatchString(name) {
			return errors.New("invalid configured container name")
		}
	}
	return nil
}

func (a *Agent) derperName() string {
	if a.cfg.DerperContainer != "" {
		return a.cfg.DerperContainer
	}
	return "derpers-" + a.identity.NodeID + "-derper"
}
func (a *Agent) caddyName() string {
	if a.cfg.CaddyContainer != "" {
		return a.cfg.CaddyContainer
	}
	return "derpers-" + a.identity.NodeID + "-caddy"
}

func derperArguments(c model.NodeConfig) []string {
	return []string{"-certmode", "manual", "-certdir", "/certs", "-hostname", c.Hostname, "-a", ":" + strconv.Itoa(c.HTTPSPort), "-http-port", "-1", "-stun=" + strconv.FormatBool(c.STUNEnabled), "-stun-port", strconv.Itoa(c.STUNPort), "-c", "/state/derper.key", "-verify-client-url", "http://caddy:9080/verify", "-verify-client-url-fail-open=false", "-verify-clients=false"}
}

func caddyConfiguration(c model.NodeConfig, controllerURL string) string {
	controllerURL = strings.TrimRight(controllerURL, "/")
	config := fmt.Sprintf(`{
	admin off
	auto_https off
	persist_config off
}

:9080 {
	handle /healthz {
		respond "ok" 200
	}
	@admission {
		method POST
		path /verify
	}
	handle @admission {
		rewrite * /admission/v1/verify
		reverse_proxy %s {
			transport http {
				tls_client_auth /agent-state/client.crt /agent-state/client.key
				tls_trust_pool file /agent-state/server-ca.crt
				dial_timeout 2s
				response_header_timeout 4s
			}
		}
	}
	handle {
		respond "Not Found" 404
	}
}
`, strconv.Quote(controllerURL))
	if c.HTTPEnabled {
		config += fmt.Sprintf(`
:80 {
	handle /generate_204 {
		reverse_proxy https://derper:%d {
			transport http {
				tls_server_name %s
				tls_trust_pool file /node/certs/ca.crt
				dial_timeout 2s
				response_header_timeout 4s
			}
		}
	}
	handle {
		respond "Not Found" 404
	}
}
`, c.HTTPSPort, strconv.Quote(c.Hostname))
	}
	return config
}

func (a *Agent) configurationFiles(c model.NodeConfig) (map[string][]byte, error) {
	args, err := json.Marshal(derperArguments(c))
	if err != nil {
		return nil, err
	}
	previous := a.applied
	a.applied = &c
	_, rootsPEM, err := a.tlsRoots()
	a.applied = previous
	if err != nil {
		return nil, err
	}
	if len(rootsPEM) == 0 {
		return nil, errors.New("no server CA bundle available for Caddy")
	}
	files := map[string][]byte{
		filepath.Join(a.cfg.ConfigDir, "derper-args.json"):         args,
		filepath.Join(a.cfg.ConfigDir, "Caddyfile"):                []byte(caddyConfiguration(c, a.cfg.ControllerURL)),
		filepath.Join(a.cfg.ConfigDir, "certs", c.Hostname+".crt"): []byte(c.CertificatePEM),
		filepath.Join(a.cfg.ConfigDir, "certs", c.Hostname+".key"): []byte(c.CertificateKeyPEM),
		filepath.Join(a.cfg.ConfigDir, "certs", "ca.crt"):          rootsPEM,
		filepath.Join(a.cfg.StateDir, "server-ca.crt"):             rootsPEM,
	}
	if c.DerperKey != "" {
		key := strings.TrimSpace(c.DerperKey)
		var value struct {
			PrivateKey string `json:"PrivateKey"`
		}
		if strings.HasPrefix(key, "{") {
			if err := json.Unmarshal([]byte(key), &value); err != nil {
				return nil, errors.New("invalid imported DERP key config")
			}
		} else {
			value.PrivateKey = key
		}
		if !regexp.MustCompile(`^privkey:[a-f0-9]{64}$`).MatchString(value.PrivateKey) {
			return nil, errors.New("invalid imported DERP private key")
		}
		file := filepath.Join(a.cfg.ConfigDir, "derper-state", "derper.key")
		if existing, err := os.ReadFile(file); err == nil {
			var old struct {
				PrivateKey string `json:"PrivateKey"`
			}
			if json.Unmarshal(existing, &old) != nil || old.PrivateKey != value.PrivateKey {
				return nil, errors.New("refusing to overwrite an existing DERP identity")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		} else {
			body, _ := json.Marshal(value)
			files[file] = body
		}
	}
	return files, nil
}

type fileBackup struct {
	data    []byte
	existed bool
}

type configurationJournal struct {
	Revision   int64         `json:"revision"`
	ConfigHash string        `json:"config_hash"`
	Files      []journalFile `json:"files"`
}
type journalFile struct {
	Path    string `json:"path"`
	Data    []byte `json:"data,omitempty"`
	Existed bool   `json:"existed"`
}

// The journal makes a multi-file update recoverable even when the process or
// machine stops between atomic file replacements. Persisted state is the commit
// record; an uncommitted revision is restored before any reconciliation.
func (a *Agent) beginConfiguration(config model.NodeConfig, files map[string][]byte) (func() error, error) {
	journal := configurationJournal{Revision: config.Revision, ConfigHash: configurationDigest(config)}
	for file := range files {
		data, err := os.ReadFile(file)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		journal.Files = append(journal.Files, journalFile{Path: file, Data: data, Existed: err == nil})
	}
	encoded, err := json.Marshal(journal)
	if err != nil {
		return nil, err
	}
	journalPath := filepath.Join(a.cfg.StateDir, "configuration.pending.json")
	if err := atomicWrite(journalPath, encoded, 0600); err != nil {
		return nil, err
	}
	rollbackFiles, err := applyFiles(files)
	if err != nil {
		restoreErr := a.restoreJournal(journal)
		if restoreErr == nil {
			_ = os.Remove(journalPath)
		}
		return nil, errors.Join(err, restoreErr)
	}
	return func() error {
		if err := rollbackFiles(); err != nil {
			return err
		}
		return os.Remove(journalPath)
	}, nil
}

func (a *Agent) restoreJournal(journal configurationJournal) error {
	var errs []error
	for _, file := range journal.Files {
		rel, err := filepath.Rel(a.cfg.ConfigDir, file.Path)
		insideConfig := err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
		if !insideConfig && file.Path != filepath.Join(a.cfg.StateDir, "server-ca.crt") {
			return errors.New("configuration journal contains an unmanaged path")
		}
		if file.Existed {
			errs = append(errs, atomicWrite(file.Path, file.Data, 0600))
		} else if err := os.Remove(file.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (a *Agent) recoverConfiguration() error {
	file := filepath.Join(a.cfg.StateDir, "configuration.pending.json")
	data, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var journal configurationJournal
	if err := json.Unmarshal(data, &journal); err != nil {
		return fmt.Errorf("invalid configuration journal: %w", err)
	}
	if a.disk.Applied == nil || configurationDigest(*a.disk.Applied) != journal.ConfigHash {
		if err := a.restoreJournal(journal); err != nil {
			return err
		}
	}
	return os.Remove(file)
}

func applyFiles(files map[string][]byte) (func() error, error) {
	backup := map[string]fileBackup{}
	for file := range files {
		data, err := os.ReadFile(file)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		backup[file] = fileBackup{data: data, existed: err == nil}
	}
	rollback := func() error {
		var errs []error
		for file, old := range backup {
			if old.existed {
				errs = append(errs, atomicWrite(file, old.data, 0600))
			} else if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	for file, data := range files {
		if err := atomicWrite(file, data, 0600); err != nil {
			_ = rollback()
			return nil, err
		}
	}
	return rollback, nil
}

func (a *Agent) applyConfig(ctx context.Context, c model.NodeConfig) error {
	if c.ControllerURL == "" {
		c.ControllerURL = a.cfg.ControllerURL
	}
	if c.DerperImage == "" {
		c.DerperImage = a.cfg.DerperImage
	}
	if c.CaddyImage == "" {
		c.CaddyImage = a.cfg.CaddyImage
	}
	if err := a.validateNodeConfig(c); err != nil {
		return err
	}
	files, err := a.configurationFiles(c)
	if err != nil {
		return err
	}
	rollback, err := a.beginConfiguration(c, files)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(a.cfg.ConfigDir, "derper-state"), 0700); err != nil {
		_ = rollback()
		return err
	}
	previous := a.applied
	a.applied = &c
	if err := a.authenticatedClient(); err != nil {
		a.applied = previous
		_ = rollback()
		return err
	}
	if a.cfg.ManageContainers {
		for _, component := range []string{"caddy", "derper"} {
			if err = a.docker.RecoverReplacement(ctx, a.componentName(component), a.identity.NodeID, "reconcile"); err != nil {
				break
			}
			spec := a.containerSpec(c, component)
			err = a.docker.Ensure(ctx, a.componentName(component), a.identity.NodeID, spec, a.healthCheck(component, c))
			if err != nil {
				break
			}
		}
	}
	if err != nil {
		a.applied = previous
		rollbackErr := rollback()
		_ = a.authenticatedClient()
		// File contents are shared bind mounts. Restart originals after restoring
		// them so both processes load the previous certificate and configuration.
		if previous != nil && a.cfg.ManageContainers {
			recoveryCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			for _, component := range []string{"caddy", "derper"} {
				_ = a.docker.Ensure(recoveryCtx, a.componentName(component), a.identity.NodeID, a.containerSpec(*previous, component), a.healthCheck(component, *previous))
				_ = a.docker.Restart(recoveryCtx, a.componentName(component), a.identity.NodeID)
			}
			cancel()
		}
		if rollbackErr != nil {
			return fmt.Errorf("%w; restore configuration: %v", err, rollbackErr)
		}
		return err
	}
	a.disk.Applied = &c
	if err := a.saveDisk(); err != nil {
		a.disk.Applied = previous
		a.applied = previous
		rollbackErr := rollback()
		_ = a.authenticatedClient()
		if previous != nil && a.cfg.ManageContainers {
			recoveryCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			for _, component := range []string{"caddy", "derper"} {
				_ = a.docker.Ensure(recoveryCtx, a.componentName(component), a.identity.NodeID, a.containerSpec(*previous, component), a.healthCheck(component, *previous))
				_ = a.docker.Restart(recoveryCtx, a.componentName(component), a.identity.NodeID)
			}
			cancel()
		}
		return errors.Join(fmt.Errorf("commit node configuration: %w", err), rollbackErr)
	}
	if err := os.Remove(filepath.Join(a.cfg.StateDir, "configuration.pending.json")); err != nil {
		a.logger.Warn("remove committed configuration journal", "error", err)
	}
	return nil
}

func configurationDigest(c model.NodeConfig) string {
	body, _ := json.Marshal(c)
	hash := sha256.Sum256(body)
	return hex.EncodeToString(hash[:])
}

func (a *Agent) componentName(component string) string {
	if component == "caddy" {
		return a.caddyName()
	}
	return a.derperName()
}

func (a *Agent) containerSpec(c model.NodeConfig, component string) containerSpec {
	body, _ := json.Marshal(c)
	configHash := sha256.Sum256(body)
	spec := containerSpec{containerConfig: containerConfig{
		Image: c.DerperImage, Env: []string{"DERPER_ARGS_FILE=/node/derper-args.json"},
		Labels:       map[string]string{"derpers.node_id": c.NodeID, "derpers.component": component, "derpers.config_hash": hex.EncodeToString(configHash[:])},
		ExposedPorts: map[string]struct{}{},
	}, HostConfig: map[string]any{
		"Binds":         []string{a.cfg.HostConfigDir + ":/node:ro", path.Join(a.cfg.HostConfigDir, "certs") + ":/certs:ro", path.Join(a.cfg.HostConfigDir, "derper-state") + ":/state:rw"},
		"RestartPolicy": map[string]string{"Name": "unless-stopped"}, "SecurityOpt": []string{"no-new-privileges:true"},
		"NetworkMode": a.cfg.DockerNetwork,
		"LogConfig":   map[string]any{"Type": "json-file", "Config": map[string]string{"max-size": "10m", "max-file": "3"}},
	}}
	aliases := []string{"derper", c.Hostname}
	ports := map[string][]map[string]string{}
	if component == "caddy" {
		if len(a.identity.Certificate.Certificate) > 0 {
			identityHash := sha256.Sum256(a.identity.Certificate.Certificate[0])
			spec.Labels["derpers.identity_hash"] = hex.EncodeToString(identityHash[:])
		}
		spec.Image = c.CaddyImage
		spec.Env = nil
		spec.Cmd = []string{"caddy", "run", "--config", "/node/Caddyfile", "--adapter", "caddyfile"}
		spec.HostConfig["Binds"] = []string{a.cfg.HostConfigDir + ":/node:ro", a.cfg.HostStateDir + ":/agent-state:ro"}
		aliases = []string{"caddy"}
		spec.ExposedPorts["9080/tcp"] = struct{}{}
		if c.HTTPEnabled {
			spec.ExposedPorts["80/tcp"] = struct{}{}
			ports["80/tcp"] = []map[string]string{{"HostPort": "80"}}
		}
	} else {
		port := strconv.Itoa(c.HTTPSPort) + "/tcp"
		spec.ExposedPorts[port] = struct{}{}
		ports[port] = []map[string]string{{"HostPort": strconv.Itoa(c.HTTPSPort)}}
		if c.STUNEnabled {
			port = strconv.Itoa(c.STUNPort) + "/udp"
			spec.ExposedPorts[port] = struct{}{}
			ports[port] = []map[string]string{{"HostPort": strconv.Itoa(c.STUNPort)}}
		}
	}
	if a.cfg.PublishPorts {
		spec.HostConfig["PortBindings"] = ports
	}
	spec.NetworkingConfig.EndpointsConfig = map[string]endpoint{a.cfg.DockerNetwork: {Aliases: aliases}}
	encoded, _ := json.Marshal(spec)
	hash := sha256.Sum256(encoded)
	spec.Labels["derpers.spec_hash"] = hex.EncodeToString(hash[:])
	return spec
}

func (a *Agent) healthCheck(component string, c model.NodeConfig) func(context.Context) error {
	return func(parent context.Context) error {
		ctx, cancel := context.WithTimeout(parent, a.cfg.HealthTimeout)
		defer cancel()
		var last error
		for {
			info, err := a.docker.Inspect(ctx, a.componentName(component), a.identity.NodeID)
			if err == nil && info.State.Running && (info.State.Health == nil || info.State.Health.Status == "healthy") {
				if component == "caddy" {
					_, err = a.docker.Exec(ctx, a.caddyName(), a.identity.NodeID, []string{"caddy", "validate", "--config", "/node/Caddyfile", "--adapter", "caddyfile"})
				} else {
					roots, _, rootErr := a.tlsRoots()
					if rootErr != nil {
						return rootErr
					}
					client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: rejectRedirect, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}}
					req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+c.Hostname+":"+strconv.Itoa(c.HTTPSPort)+"/derp/probe", nil)
					resp, probeErr := client.Do(req)
					if probeErr == nil {
						resp.Body.Close()
						if resp.StatusCode != http.StatusOK {
							probeErr = fmt.Errorf("probe HTTP %d", resp.StatusCode)
						}
					}
					client.CloseIdleConnections()
					err = probeErr
				}
				if err == nil {
					return nil
				}
			} else if err == nil {
				err = fmt.Errorf("container state is %s", info.State.Status)
			}
			last = err
			select {
			case <-ctx.Done():
				return fmt.Errorf("%s health check: %w (last error: %v)", component, ctx.Err(), last)
			case <-time.After(500 * time.Millisecond):
			}
		}
	}
}
