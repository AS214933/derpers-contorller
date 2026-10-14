package config

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Isolate Load from the invoking shell without racing process-wide environment
// mutations. Setenv registers restoration even when the test needs a variable
// genuinely absent, rather than present with an empty override value.
func clearConfigEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"DATABASE_URL", "MASTER_KEY", "HTTP_ADDR", "TLS_ADDR", "TLS_CERT_FILE", "TLS_KEY_FILE",
		"NODE_CA_CERT_FILE", "NODE_CA_KEY_FILE", "NODE_AUTH_MODE", "NODE_IDENTITY_TTL", "METRICS_TOKEN",
		"CONTROLLER_URL", "PUBLIC_URL", "WEB_DIR", "HEADSCALE_ALLOWED_CIDRS", "OIDC_ISSUER", "OIDC_CLIENT_ID",
		"OIDC_CLIENT_SECRET", "OIDC_GROUPS_CLAIM", "OIDC_ADMIN_GROUPS", "OIDC_SCOPES", "GRAFANA_URL", "PROMETHEUS_URL",
		"DERPER_IMAGE", "AGENT_IMAGE", "CADDY_IMAGE", "ACME_EMAIL", "ACME_DIRECTORY",
	} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
}

func configMasterKey(value byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}

func validConfigEnvironment(t *testing.T) {
	t.Helper()
	clearConfigEnvironment(t)
	t.Setenv("DATABASE_URL", "postgres://test:test@database.example.test/derpers")
	t.Setenv("MASTER_KEY", configMasterKey(0x31))
}

func configYAML(t *testing.T, extra string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "controller.yaml")
	body := "database_url: postgres://yaml:yaml@database.example.test/derpers\nmaster_key: " + configMasterKey(0x32) + "\n" + extra
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadDefaultsToHTTPOnlyAndCertificateRequestProof(t *testing.T) {
	validConfigEnvironment(t)
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTPAddr != ":8080" || c.TLSAddr != "" || c.TLSCertFile != "" || c.TLSKeyFile != "" {
		t.Fatalf("default deployment unexpectedly requires a native TLS listener: http=%q tls=%q cert=%q key=%q", c.HTTPAddr, c.TLSAddr, c.TLSCertFile, c.TLSKeyFile)
	}
	if c.NodeAuthMode != "proof" || c.NodeIdentityTTL != 168*time.Hour {
		t.Fatalf("unsafe or incompatible node identity defaults: mode=%q ttl=%s", c.NodeAuthMode, c.NodeIdentityTTL)
	}
	if c.MetricsToken != "" || c.NodeCACertFile != "" || c.NodeCAKeyFile != "" {
		t.Fatal("Load invented credentials or local CA paths instead of requiring operator configuration")
	}
}

func TestLoadYAMLDurationHybridAndOptionalNativeTLS(t *testing.T) {
	for _, tc := range []struct {
		name, mode, duration string
		nativeTLS            bool
		want                 time.Duration
	}{
		{"proof behind TLS termination", "proof", "30m", false, 30 * time.Minute},
		{"proof with optional native TLS", "proof", "6h", true, 6 * time.Hour},
		{"explicit legacy migration", "hybrid", "168h", true, 168 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearConfigEnvironment(t)
			yaml := "http_addr: ':18080'\nnode_auth_mode: " + tc.mode + "\nnode_identity_ttl: " + tc.duration + "\n" +
				"controller_url: https://node-api.example.test\npublic_url: https://portal.example.test\n" +
				"node_ca_cert_file: /secrets/node-ca.crt\nnode_ca_key_file: /secrets/node-ca.key\nmetrics_token: yaml-metrics-secret\n"
			if tc.nativeTLS {
				yaml += "tls_addr: ':19443'\ntls_cert_file: /secrets/server.crt\ntls_key_file: /secrets/server.key\n"
			}
			c, err := Load(configYAML(t, yaml))
			if err != nil {
				t.Fatal(err)
			}
			if c.NodeAuthMode != tc.mode || c.NodeIdentityTTL != tc.want || c.HTTPAddr != ":18080" {
				t.Fatalf("YAML identity/listener settings were lost: mode=%q ttl=%s http=%q", c.NodeAuthMode, c.NodeIdentityTTL, c.HTTPAddr)
			}
			if tc.nativeTLS && (c.TLSAddr != ":19443" || c.TLSCertFile != "/secrets/server.crt" || c.TLSKeyFile != "/secrets/server.key") {
				t.Fatal("explicit native TLS settings were not preserved")
			}
			if !tc.nativeTLS && (c.TLSAddr != "" || c.TLSCertFile != "" || c.TLSKeyFile != "") {
				t.Fatal("HTTP-only proof configuration unexpectedly gained TLS settings")
			}
			if c.ControllerURL != "https://node-api.example.test" || c.PublicURL != "https://portal.example.test" || c.MetricsToken != "yaml-metrics-secret" || c.NodeCACertFile != "/secrets/node-ca.crt" || c.NodeCAKeyFile != "/secrets/node-ca.key" {
				t.Fatal("YAML origins, metrics credential or existing node issuer settings were lost")
			}
		})
	}
}

func TestLoadEnvironmentOverridesYAMLAndCanDisableNativeTLS(t *testing.T) {
	clearConfigEnvironment(t)
	path := configYAML(t, "node_auth_mode: hybrid\nnode_identity_ttl: 60m\nhttp_addr: ':18080'\ntls_addr: ':19443'\ntls_cert_file: /yaml/server.crt\ntls_key_file: /yaml/server.key\nmetrics_token: yaml-token\ncontroller_url: https://yaml-node.example.test\npublic_url: https://yaml-portal.example.test\noidc_scopes: [openid, groups]\nheadscale_allowed_cidrs: ['192.0.2.0/24']\n")
	overrides := map[string]string{
		"DATABASE_URL": "postgres://environment:environment@database.example.test/derpers",
		"MASTER_KEY":   configMasterKey(0x33), "HTTP_ADDR": ":28080", "TLS_ADDR": "", "TLS_CERT_FILE": "", "TLS_KEY_FILE": "",
		"NODE_AUTH_MODE": "proof", "NODE_IDENTITY_TTL": "5m", "METRICS_TOKEN": "environment-token",
		"CONTROLLER_URL": "https://edge.example.test", "PUBLIC_URL": "https://cdn.example.test",
		"NODE_CA_CERT_FILE": "/environment/node-ca.crt", "NODE_CA_KEY_FILE": "/environment/node-ca.key",
		"OIDC_GROUPS_CLAIM": "realm_access.roles", "OIDC_SCOPES": "openid, profile, , email", "OIDC_ADMIN_GROUPS": " operators, , admins ",
		"HEADSCALE_ALLOWED_CIDRS": "127.0.0.1/32, , 2001:db8::/32", "AGENT_IMAGE": "ghcr.io/example/agent@sha256:" + strings.Repeat("a", 64),
	}
	for name, value := range overrides {
		t.Setenv(name, value)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.DatabaseURL != overrides["DATABASE_URL"] || c.MasterKey != overrides["MASTER_KEY"] || c.NodeAuthMode != "proof" || c.NodeIdentityTTL != 5*time.Minute || c.MetricsToken != "environment-token" {
		t.Fatal("environment did not override YAML credentials or proof identity settings")
	}
	if c.HTTPAddr != ":28080" || c.TLSAddr != "" || c.TLSCertFile != "" || c.TLSKeyFile != "" {
		t.Fatal("explicit empty TLS overrides failed to select HTTP-only mode")
	}
	if c.ControllerURL != overrides["CONTROLLER_URL"] || c.PublicURL != overrides["PUBLIC_URL"] || c.NodeCACertFile != overrides["NODE_CA_CERT_FILE"] || c.NodeCAKeyFile != overrides["NODE_CA_KEY_FILE"] || c.AgentImage != overrides["AGENT_IMAGE"] {
		t.Fatal("origin, node issuer or image overrides were lost")
	}
	if c.OIDCGroupsClaim != "realm_access.roles" || !reflect.DeepEqual(c.OIDCScopes, []string{"openid", "profile", "email"}) || !reflect.DeepEqual(c.OIDCAdminGroups, []string{"operators", "admins"}) || !reflect.DeepEqual(c.AllowedCIDRs, []string{"127.0.0.1/32", "2001:db8::/32"}) {
		t.Fatal("OIDC or trusted-network environment lists were not parsed correctly")
	}
}

func TestLoadRejectsUnsupportedNodeAuthenticationModes(t *testing.T) {
	for _, mode := range []string{"mtls", "bearer", "none", "Proof", " proof "} {
		t.Run(mode, func(t *testing.T) {
			validConfigEnvironment(t)
			t.Setenv("NODE_AUTH_MODE", mode)
			if _, err := Load(""); err == nil || !strings.Contains(err.Error(), "NODE_AUTH_MODE") {
				t.Fatalf("unsupported authentication mode %q was accepted: %v", mode, err)
			}
		})
	}
	for _, mode := range []string{"", "proof", "hybrid"} {
		t.Run("supported "+mode, func(t *testing.T) {
			validConfigEnvironment(t)
			t.Setenv("NODE_AUTH_MODE", mode)
			c, err := Load("")
			if err != nil {
				t.Fatal(err)
			}
			want := mode
			if want == "" {
				want = "proof"
			}
			if c.NodeAuthMode != want {
				t.Fatalf("mode=%q want=%q", c.NodeAuthMode, want)
			}
		})
	}
}

func TestLoadNodeIdentityDurationBounds(t *testing.T) {
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{"5m", true}, {"168h", true}, {"5m0.5s", true}, {"4m59.999s", false}, {"168h0m0.001s", false},
		{"0s", false}, {"-5m", false}, {"7d", false}, {"invalid", false}, {"", false},
	} {
		t.Run("environment "+tc.value, func(t *testing.T) {
			validConfigEnvironment(t)
			t.Setenv("NODE_IDENTITY_TTL", tc.value)
			c, err := Load("")
			if !tc.valid {
				if err == nil || !strings.Contains(err.Error(), "NODE_IDENTITY_TTL") {
					t.Fatalf("invalid duration %q was accepted: %v", tc.value, err)
				}
				return
			}
			want, _ := time.ParseDuration(tc.value)
			if err != nil || c.NodeIdentityTTL != want {
				t.Fatalf("duration=%s want=%s error=%v", c.NodeIdentityTTL, want, err)
			}
		})
	}
	for _, value := range []string{"4m59s", "168h1s", "0s", "-1m", "7d"} {
		t.Run("YAML "+value, func(t *testing.T) {
			clearConfigEnvironment(t)
			if _, err := Load(configYAML(t, "node_identity_ttl: "+value+"\n")); err == nil {
				t.Fatalf("invalid YAML identity lifetime %q was accepted", value)
			}
		})
	}
	for _, mode := range []string{"none", "mtls"} {
		t.Run("YAML mode "+mode, func(t *testing.T) {
			clearConfigEnvironment(t)
			if _, err := Load(configYAML(t, "node_auth_mode: "+mode+"\n")); err == nil {
				t.Fatalf("unsupported YAML authentication mode %q was accepted", mode)
			}
		})
	}
}
