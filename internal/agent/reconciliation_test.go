package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AS214933/derpers-contorller/internal/model"
)

func TestReconciliationFingerprintsAreIsolatedByComponent(t *testing.T) {
	a := &Agent{cfg: Config{ControllerURL: "https://controller.example.test", StateDir: t.TempDir(), ConfigDir: t.TempDir(), HostConfigDir: "/opt/node", HostStateDir: "/opt/identity", DockerNetwork: "node-network", PublishPorts: true}, identity: identity{Certificate: tlsCertificateForFingerprint([]byte("identity-a"))}}
	base := model.NodeConfig{NodeID: "node-1", Revision: 1, Hostname: "derp.example.test", HTTPSPort: 443, STUNEnabled: true, STUNPort: 3478, HTTPEnabled: true, CertificatePEM: "certificate-a", CertificateKeyPEM: "key-a", CAPEM: "trust-a", DerperImage: "derper@sha256:" + strings.Repeat("a", 64), CaddyImage: "caddy@sha256:" + strings.Repeat("b", 64)}
	hash := func(c model.NodeConfig, component string) string {
		return a.containerSpec(c, component).Labels["derpers.spec_hash"]
	}
	for _, test := range []struct {
		name                        string
		modify                      func(*model.NodeConfig)
		derperChanged, caddyChanged bool
	}{
		{"global revision", func(c *model.NodeConfig) { c.Revision++ }, false, false},
		{"Caddy upgrade", func(c *model.NodeConfig) { c.CaddyImage = "caddy@sha256:" + strings.Repeat("c", 64); c.Revision++ }, false, true},
		{"DERP upgrade", func(c *model.NodeConfig) { c.DerperImage = "derper@sha256:" + strings.Repeat("d", 64); c.Revision++ }, true, false},
		{"HTTP probe switch", func(c *model.NodeConfig) { c.HTTPEnabled = false; c.Revision++ }, false, true},
		{"STUN port", func(c *model.NodeConfig) { c.STUNPort = 3479; c.Revision++ }, true, false},
		{"STUN switch", func(c *model.NodeConfig) { c.STUNEnabled = false; c.Revision++ }, true, false},
		{"DERP certificate renewal", func(c *model.NodeConfig) {
			c.CertificatePEM = "certificate-b"
			c.CertificateKeyPEM = "key-b"
			c.Revision++
		}, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			test.modify(&candidate)
			if got := hash(candidate, "derper") != hash(base, "derper"); got != test.derperChanged {
				t.Fatalf("DERP restart changed=%v want=%v", got, test.derperChanged)
			}
			if got := hash(candidate, "caddy") != hash(base, "caddy"); got != test.caddyChanged {
				t.Fatalf("Caddy restart changed=%v want=%v", got, test.caddyChanged)
			}
		})
	}
	derperBefore, caddyBefore := hash(base, "derper"), hash(base, "caddy")
	a.identity.Certificate = tlsCertificateForFingerprint([]byte("identity-b"))
	if hash(base, "derper") != derperBefore || hash(base, "caddy") != caddyBefore {
		t.Fatal("node request-signing identity renewal restarted a relay component")
	}
	caddyBefore = hash(base, "caddy")
	if err := os.MkdirAll(filepath.Join(a.cfg.ConfigDir, "certs"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.cfg.ConfigDir, "certs", "ca.crt"), []byte("new root bundle"), 0600); err != nil {
		t.Fatal(err)
	}
	if hash(base, "derper") != derperBefore || hash(base, "caddy") == caddyBefore {
		t.Fatal("server trust update changed DERP or failed to reload Caddy")
	}
	disabledHTTP := base
	disabledHTTP.HTTPEnabled = false
	caddyBefore = hash(disabledHTTP, "caddy")
	if err := os.WriteFile(filepath.Join(a.cfg.ConfigDir, "certs", "ca.crt"), []byte("another root bundle"), 0600); err != nil {
		t.Fatal(err)
	}
	if hash(disabledHTTP, "caddy") != caddyBefore {
		t.Fatal("unused DERP HTTP probe trust restarted Caddy")
	}
}

func tlsCertificateForFingerprint(raw []byte) tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{raw}}
}

func TestRollbackFailurePreservesJournalAndPreviousConfiguration(t *testing.T) {
	dockerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "Docker unavailable", 503) }))
	defer dockerServer.Close()
	docker, _ := NewDocker(dockerServer.URL)
	dir := t.TempDir()
	journal := filepath.Join(dir, "configuration.pending.json")
	original := []byte("retained previous configuration and private key")
	if err := os.WriteFile(journal, original, 0600); err != nil {
		t.Fatal(err)
	}
	previous := &model.NodeConfig{NodeID: "node-1", Revision: 1, DerperImage: "old-derper", CaddyImage: "old-caddy", CertificateKeyPEM: "old-key"}
	a := &Agent{cfg: Config{StateDir: dir, ConfigDir: filepath.Join(dir, "node"), ControllerURL: "https://controller.example.test", ManageContainers: true, HealthTimeout: time.Second}, docker: docker, identity: identity{NodeID: "node-1"}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	err := a.configurationFailed(errors.New("new configuration failed health"), previous, func() error { return nil })
	var rollbackErr *rollbackFailure
	if !errors.As(err, &rollbackErr) {
		t.Fatalf("rollback error was lost: %v", err)
	}
	for _, component := range []string{"restore caddy container", "restore derper container"} {
		if !strings.Contains(err.Error(), component) {
			t.Fatalf("rollback did not aggregate %s: %v", component, err)
		}
	}
	if a.applied != previous || a.disk.Applied != previous {
		t.Fatal("previous applied configuration was discarded")
	}
	got, readErr := os.ReadFile(journal)
	if readErr != nil || string(got) != string(original) {
		t.Fatal("failed recovery discarded or rewrote the journal")
	}
	if err := a.applyConfig(context.Background(), model.NodeConfig{}); !errors.As(err, &rollbackErr) {
		t.Fatal("a later reconciliation overwrote an unrecovered journal")
	}
}

func TestRollbackRequiresHealthyProcessesAfterRestart(t *testing.T) {
	for _, failAfterRestart := range []bool{false, true} {
		name := "healthy restoration"
		if failAfterRestart {
			name = "failed final health retains journal"
		}
		t.Run(name, func(t *testing.T) {
			var mu sync.Mutex
			events := []string{}
			event := func(value string) { mu.Lock(); events = append(events, value); mu.Unlock() }
			var derperRestarted atomic.Bool
			relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				event("derper-health")
				if !derperRestarted.Load() {
					w.WriteHeader(503)
					return
				}
				w.WriteHeader(200)
			}))
			defer relay.Close()
			origin, _ := url.Parse(relay.URL)
			port, _ := strconv.Atoi(origin.Port())
			previous := &model.NodeConfig{NodeID: "node-1", Revision: 1, Hostname: origin.Hostname(), HTTPSPort: port, CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: relay.Certificate().Raw})), DerperImage: "old-derper", CaddyImage: "old-caddy"}
			dir := t.TempDir()
			journal := filepath.Join(dir, "configuration.pending.json")
			os.WriteFile(journal, []byte("journal"), 0600)
			a := &Agent{cfg: Config{StateDir: dir, ControllerURL: "https://controller.example.test", DerperContainer: "derper", CaddyContainer: "caddy", ManageContainers: true, HealthTimeout: 150 * time.Millisecond}, identity: signingIdentityForTest(t), applied: previous, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			var caddyRestarted atomic.Bool
			dockerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/restart"):
					component := "derper"
					if strings.Contains(r.URL.Path, "/caddy/") {
						component = "caddy"
						caddyRestarted.Store(true)
					} else {
						derperRestarted.Store(true)
					}
					event(component + "-restart")
					w.WriteHeader(204)
				case strings.HasSuffix(r.URL.Path, "/exec"):
					io.WriteString(w, `{"Id":"caddy-validate"}`)
				case strings.HasPrefix(r.URL.Path, "/v1.47/exec/") && strings.HasSuffix(r.URL.Path, "/start"):
					event("caddy-health")
					io.WriteString(w, "valid configuration")
				case strings.HasPrefix(r.URL.Path, "/v1.47/exec/"):
					code := 0
					if failAfterRestart && caddyRestarted.Load() {
						code = 1
					}
					json.NewEncoder(w).Encode(map[string]any{"ExitCode": code, "Running": false})
				default:
					component := "derper"
					if strings.Contains(r.URL.Path, "/caddy/") {
						component = "caddy"
					}
					info := containerInfo{Config: a.containerSpec(*previous, component).containerConfig}
					info.State.Running = true
					json.NewEncoder(w).Encode(info)
				}
			}))
			defer dockerServer.Close()
			a.docker, _ = NewDocker(dockerServer.URL)
			err := a.configurationFailed(errors.New("new image was unhealthy"), previous, func() error { return nil })
			var rollbackErr *rollbackFailure
			if failAfterRestart {
				if !errors.As(err, &rollbackErr) || !strings.Contains(err.Error(), "verify restored caddy") {
					t.Fatalf("failed post-restart health was hidden: %v", err)
				}
				if _, err := os.Stat(journal); err != nil {
					t.Fatal("failed final health deleted recovery journal")
				}
			} else {
				if errors.As(err, &rollbackErr) || !strings.Contains(err.Error(), "restored and health checked") {
					t.Fatalf("healthy rollback incorrectly failed: %v", err)
				}
				if _, err := os.Stat(journal); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("successful recovery left a blocking journal")
				}
			}
			mu.Lock()
			defer mu.Unlock()
			for _, component := range []string{"caddy", "derper"} {
				restart, lastHealth := -1, -1
				for i, value := range events {
					if value == component+"-restart" {
						restart = i
					}
					if value == component+"-health" {
						lastHealth = i
					}
				}
				if restart < 0 || lastHealth <= restart {
					t.Fatalf("%s was not checked after restart: %v", component, events)
				}
			}
		})
	}
}
