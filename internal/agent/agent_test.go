package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AS214933/derpers-contorller/internal/model"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, name string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca testCA) sign(t *testing.T, public any, server bool) []byte {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "test-node"}, NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if server {
		template.DNSNames = []string{"localhost", "derp.e2e.test"}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, public, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestEnrollmentAndRenewalPreserveSeparateServerTrust(t *testing.T) {
	serverCA := newTestCA(t, "server CA")
	nodeCA := newTestCA(t, "node CA")
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverKeyDER, _ := x509.MarshalPKCS8PrivateKey(serverKey)
	serverPair, err := tls.X509KeyPair(serverCA.sign(t, serverKey.Public(), true), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER}))
	if err != nil {
		t.Fatal(err)
	}
	clientRoots := x509.NewCertPool()
	clientRoots.AppendCertsFromPEM(nodeCA.pem)
	var enrolls, renewals, authenticated int
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/node-enroll", "/node/v1/renew":
			var request model.EnrollmentRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
				http.Error(w, "bad request", 400)
				return
			}
			if r.URL.Path == "/api/v1/node-enroll" {
				enrolls++
				if request.Token != "one-use-secret" {
					t.Error("missing enrollment token")
				}
			} else {
				renewals++
				if len(r.TLS.VerifiedChains) == 0 {
					t.Error("renewal lacks mTLS")
				}
			}
			block, _ := pem.Decode([]byte(request.CSR))
			if block == nil {
				t.Error("invalid CSR")
				return
			}
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				t.Error(err)
				return
			}
			if err := csr.CheckSignature(); err != nil {
				t.Error(err)
				return
			}
			json.NewEncoder(w).Encode(model.EnrollmentResponse{NodeID: "node-1", ClientCertificate: string(nodeCA.sign(t, csr.PublicKey, false)), CACertificate: string(nodeCA.pem)})
		case "/node/v1/config":
			if len(r.TLS.VerifiedChains) == 0 {
				http.Error(w, "mTLS required", 401)
				return
			}
			authenticated++
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		default:
			http.NotFound(w, r)
		}
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverPair}, ClientCAs: clientRoots, ClientAuth: tls.VerifyClientCertIfGiven, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	dir := t.TempDir()
	caFile := filepath.Join(dir, "server-ca.pem")
	os.WriteFile(caFile, serverCA.pem, 0600)
	cfg := Config{ControllerURL: server.URL, EnrollmentToken: "one-use-secret", ControllerCAFile: caFile, StateDir: filepath.Join(dir, "identity"), ConfigDir: filepath.Join(dir, "node"), DockerHost: "http://127.0.0.1:9", PollInterval: time.Second, HeartbeatInterval: time.Second, HealthTimeout: time.Second}
	a, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.cfg.EnrollmentToken != "" {
		t.Fatal("enrollment token retained after use")
	}
	var result map[string]string
	if err := a.request(context.Background(), a.client, http.MethodGet, "/node/v1/config", nil, &result); err != nil {
		t.Fatal(err)
	}
	if err := a.renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.request(context.Background(), a.client, http.MethodGet, "/node/v1/config", nil, &result); err != nil {
		t.Fatal(err)
	}
	if enrolls != 1 || renewals != 1 || authenticated != 2 {
		t.Fatalf("unexpected API counts: enroll=%d renew=%d auth=%d", enrolls, renewals, authenticated)
	}
	restarted, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.identity.NodeID != "node-1" {
		t.Fatal("node identity was not persisted")
	}
	if err := restarted.request(context.Background(), restarted.client, http.MethodGet, "/node/v1/config", nil, &result); err != nil {
		t.Fatal(err)
	}
}

func TestDockerRefusesUnownedContainerBeforeMutation(t *testing.T) {
	mutations := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			mutations++
		}
		json.NewEncoder(w).Encode(containerInfo{Config: containerConfig{Labels: map[string]string{"derpers.node_id": "other", "derpers.component": "derper"}}})
	}))
	defer server.Close()
	docker, err := NewDocker(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := docker.Restart(context.Background(), "derper", "node-1"); err == nil {
		t.Fatal("unowned container was accepted")
	}
	if mutations != 0 {
		t.Fatalf("made %d mutations before ownership check", mutations)
	}
}

func TestFailedUpgradeRestoresOriginalContainer(t *testing.T) {
	old := containerInfo{ID: "old-id", Config: containerConfig{Image: "old@sha256:abc", Labels: map[string]string{"derpers.node_id": "node-1", "derpers.component": "derper"}}, HostConfig: map[string]any{}}
	old.State.Running = true
	containers := map[string]containerInfo{"derper": old}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1.47/images/") {
			w.WriteHeader(200)
			io.WriteString(w, "{}")
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/v1.47/containers/")
		if name == "create" {
			var spec containerSpec
			json.NewDecoder(r.Body).Decode(&spec)
			containers[r.URL.Query().Get("name")] = containerInfo{ID: "new-id", Config: spec.containerConfig, HostConfig: spec.HostConfig}
			w.WriteHeader(201)
			io.WriteString(w, `{"Id":"new-id"}`)
			return
		}
		parts := strings.SplitN(name, "/", 2)
		name = parts[0]
		item, ok := containers[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodDelete {
			delete(containers, name)
			w.WriteHeader(204)
			return
		}
		if len(parts) < 2 {
			t.Errorf("unexpected request %s", r.URL.Path)
			return
		}
		switch parts[1] {
		case "json":
			json.NewEncoder(w).Encode(item)
		case "stop":
			item.State.Running = false
			containers[name] = item
			w.WriteHeader(204)
		case "start":
			item.State.Running = true
			containers[name] = item
			w.WriteHeader(204)
		case "rename":
			delete(containers, name)
			containers[r.URL.Query().Get("name")] = item
			w.WriteHeader(204)
		default:
			t.Errorf("unexpected endpoint %s", parts[1])
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	docker, _ := NewDocker(server.URL)
	err := docker.Upgrade(context.Background(), "derper", "node-1", "task-123", "new@sha256:def", func(context.Context) error { return errors.New("new version unhealthy") })
	if err == nil || !strings.Contains(err.Error(), "unhealthy") {
		t.Fatalf("unexpected upgrade result %v", err)
	}
	got := containers["derper"]
	if got.ID != "old-id" || !got.State.Running || len(containers) != 1 {
		t.Fatalf("original not restored: %+v", containers)
	}
}

func TestRestartTaskIsNotRepeatedAfterAgentRestart(t *testing.T) {
	restarts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/restart"):
			restarts++
			w.WriteHeader(204)
		case strings.HasSuffix(r.URL.Path, "/exec"):
			io.WriteString(w, `{"Id":"exec-1"}`)
		case strings.HasPrefix(r.URL.Path, "/v1.47/exec/") && strings.HasSuffix(r.URL.Path, "/start"):
			io.WriteString(w, "valid")
		case strings.HasPrefix(r.URL.Path, "/v1.47/exec/"):
			io.WriteString(w, `{"ExitCode":0,"Running":false}`)
		default:
			info := containerInfo{Config: containerConfig{Labels: map[string]string{"derpers.node_id": "node-1", "derpers.component": "caddy"}}}
			info.State.Running = true
			json.NewEncoder(w).Encode(info)
		}
	}))
	defer server.Close()
	docker, _ := NewDocker(server.URL)
	dir := t.TempDir()
	makeAgent := func() *Agent {
		return &Agent{cfg: Config{StateDir: dir, ManageContainers: true, HealthTimeout: time.Second, CaddyContainer: "caddy"}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), docker: docker, identity: identity{NodeID: "node-1"}, applied: &model.NodeConfig{}, disk: diskState{Tasks: map[string]taskRecord{}}}
	}
	a := makeAgent()
	task := model.Task{ID: "restart-once", NodeID: "node-1", Type: "restart", Status: "pending", Payload: json.RawMessage(`{"component":"caddy"}`)}
	a.executeTask(context.Background(), task)
	if restarts != 1 || a.disk.Tasks[task.ID].Result.Status != "succeeded" {
		t.Fatalf("task did not succeed: %+v", a.disk.Tasks)
	}
	restarted := makeAgent()
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &restarted.disk); err != nil {
		t.Fatal(err)
	}
	restarted.executeTask(context.Background(), task)
	if restarts != 1 {
		t.Fatalf("restart was repeated %d times", restarts)
	}
}

func TestDockerLogMultiplexingAndConfigurationRollback(t *testing.T) {
	var body bytes.Buffer
	for _, text := range []string{"stdout\n", "stderr\n"} {
		header := []byte{1, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(header[4:], uint32(len(text)))
		body.Write(header)
		body.WriteString(text)
	}
	got, err := readDockerStream(&body)
	if err != nil || got != "stdout\nstderr\n" {
		t.Fatalf("decode logs: %q %v", got, err)
	}
	dir := t.TempDir()
	existing := filepath.Join(dir, "cert.key")
	created := filepath.Join(dir, "Caddyfile")
	os.WriteFile(existing, []byte("old-secret"), 0600)
	rollback, err := applyFiles(map[string][]byte{existing: []byte("new-secret"), created: []byte("config")})
	if err != nil {
		t.Fatal(err)
	}
	if err := rollback(); err != nil {
		t.Fatal(err)
	}
	old, _ := os.ReadFile(existing)
	if string(old) != "old-secret" {
		t.Fatal("old private key not restored")
	}
	if _, err := os.Stat(created); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("new config not removed")
	}
}

func TestUpgradeRequiresDigestAndCorrectRepository(t *testing.T) {
	a := &Agent{applied: &model.NodeConfig{DerperImage: "ghcr.io/example/derper:old"}}
	digest := "@sha256:" + strings.Repeat("a", 64)
	if a.allowedUpgrade("ghcr.io/example/derper:latest", "derper") {
		t.Fatal("floating tag allowed")
	}
	if a.allowedUpgrade("evil.invalid/derper"+digest, "derper") {
		t.Fatal("unapproved registry allowed")
	}
	if !a.allowedUpgrade("ghcr.io/example/derper"+digest, "derper") {
		t.Fatal("same repository digest rejected")
	}
}

func TestUncommittedConfigurationIsRecoveredAfterCrash(t *testing.T) {
	dir := t.TempDir()
	a := &Agent{cfg: Config{StateDir: filepath.Join(dir, "state"), ConfigDir: filepath.Join(dir, "config")}}
	os.MkdirAll(a.cfg.StateDir, 0700)
	os.MkdirAll(a.cfg.ConfigDir, 0700)
	file := filepath.Join(a.cfg.ConfigDir, "Caddyfile")
	os.WriteFile(file, []byte("old working config"), 0600)
	config := model.NodeConfig{NodeID: "node-1", Revision: 2}
	if _, err := a.beginConfiguration(config, map[string][]byte{file: []byte("partial new config")}); err != nil {
		t.Fatal(err)
	}
	// Simulate a process stop before its durable applied-state commit.
	restarted := &Agent{cfg: a.cfg, disk: diskState{Applied: &model.NodeConfig{NodeID: "node-1", Revision: 1}}}
	if err := restarted.recoverConfiguration(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(file)
	if string(data) != "old working config" {
		t.Fatalf("uncommitted file survived recovery: %s", data)
	}
	if _, err := a.beginConfiguration(config, map[string][]byte{file: []byte("committed new config")}); err != nil {
		t.Fatal(err)
	}
	restarted.disk.Applied = &config
	if err := restarted.recoverConfiguration(); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(file)
	if string(data) != "committed new config" {
		t.Fatalf("committed config was reverted: %s", data)
	}
}

func TestReportBatchesAndAcknowledgesTaskResults(t *testing.T) {
	reports := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report model.Report
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&report); err != nil {
			t.Error(err)
			http.Error(w, "invalid", 400)
			return
		}
		if len(report.Results) > 100 || len(report.Metrics) > 64 {
			t.Error("report exceeds controller bounds")
			http.Error(w, "too large", 400)
			return
		}
		reports++
		w.WriteHeader(204)
	}))
	defer server.Close()
	a := &Agent{cfg: Config{ControllerURL: server.URL, StateDir: t.TempDir()}, client: server.Client(), logger: slog.New(slog.NewTextHandler(io.Discard, nil)), disk: diskState{Tasks: map[string]taskRecord{}}}
	for i := 0; i < 150; i++ {
		id := strconv.Itoa(i)
		a.disk.Tasks[id] = taskRecord{Result: model.TaskResult{TaskID: id, Status: "succeeded", Logs: strings.Repeat("x", 8<<10)}}
	}
	for range 3 {
		a.report(context.Background())
	}
	for id, record := range a.disk.Tasks {
		if !record.Reported || record.Result.Logs != "" {
			t.Fatalf("task %s not acknowledged", id)
		}
	}
	if reports != 3 {
		t.Fatalf("unexpected reports: %d", reports)
	}
}

func TestFailedUpgradeReportsOldRevisionAndAwaitsDesiredRollback(t *testing.T) {
	dir := t.TempDir()
	old := &model.NodeConfig{NodeID: "node-1", Revision: 1, Hostname: "derp.e2e.test", HTTPSPort: 443, DerperImage: "ghcr.io/example/derper:old", CaddyImage: "caddy:2.11.7"}
	a := &Agent{cfg: Config{StateDir: dir, ConfigDir: filepath.Join(dir, "node"), ControllerURL: "https://controller.test", ManageContainers: true}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), identity: identity{NodeID: "node-1"}, applied: old, disk: diskState{Applied: old, Tasks: map[string]taskRecord{}}}
	config := *old
	config.Revision = 2
	config.DerperImage = "ghcr.io/example/derper@sha256:" + strings.Repeat("a", 64)
	// The desired image is eligible, but a bad accompanying certificate makes
	// the entire transaction fail before changing a running component.
	payload, _ := json.Marshal(taskPayload{Component: "derper", Image: config.DerperImage, PreviousImage: old.DerperImage, TargetRevision: 2})
	task := model.Task{ID: "upgrade-1", NodeID: "node-1", Type: "upgrade", Status: "pending", Payload: payload}
	if err := a.applyConfigurationWithTasks(context.Background(), config, []model.Task{task}); err == nil {
		t.Fatal("invalid configuration was applied")
	}
	if a.applied.Revision != 1 || a.disk.Applied.Revision != 1 || a.disk.Tasks[task.ID].Result.Status != "failed" {
		t.Fatalf("failed transaction advanced state: %+v", a.disk)
	}
	if err := a.applyConfigurationWithTasks(context.Background(), config, []model.Task{task}); err == nil || !strings.Contains(err.Error(), "awaits controller rollback") {
		t.Fatalf("failed image was retried: %v", err)
	}
}

func TestManagedCaddyUsesOfficialImageCommandAndPrivatePorts(t *testing.T) {
	a := &Agent{cfg: Config{DockerNetwork: "node-network", HostConfigDir: "/opt/node", HostStateDir: "/opt/identity", PublishPorts: true}}
	spec := a.containerSpec(model.NodeConfig{NodeID: "node-1", Hostname: "derp.test", CaddyImage: "caddy:2.11.7", HTTPEnabled: true}, "caddy")
	// The official image has CMD, not ENTRYPOINT. Replacing CMD must retain the
	// executable name, otherwise Docker tries to execute a binary named "run".
	if len(spec.Cmd) < 2 || spec.Cmd[0] != "caddy" || spec.Cmd[1] != "run" {
		t.Fatalf("Caddy cannot start: %#v", spec.Cmd)
	}
	if spec.HostConfig["NetworkMode"] != "node-network" {
		t.Fatal("managed container is not attached to its explicit node network")
	}
	bindings := spec.HostConfig["PortBindings"].(map[string][]map[string]string)
	if len(bindings) != 1 || bindings["80/tcp"] == nil {
		t.Fatalf("internal Caddy port exposed: %#v", bindings)
	}
}
