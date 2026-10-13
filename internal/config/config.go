package config

import (
	"encoding/base64"
	"errors"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DatabaseURL      string   `yaml:"database_url"`
	MasterKey        string   `yaml:"master_key"`
	HTTPAddr         string   `yaml:"http_addr"`
	TLSAddr          string   `yaml:"tls_addr"`
	TLSCertFile      string   `yaml:"tls_cert_file"`
	TLSKeyFile       string   `yaml:"tls_key_file"`
	NodeCACertFile   string   `yaml:"node_ca_cert_file"`
	NodeCAKeyFile    string   `yaml:"node_ca_key_file"`
	ControllerURL    string   `yaml:"controller_url"`
	PublicURL        string   `yaml:"public_url"`
	WebDir           string   `yaml:"web_dir"`
	AllowedCIDRs     []string `yaml:"headscale_allowed_cidrs"`
	OIDCIssuer       string   `yaml:"oidc_issuer"`
	OIDCClientID     string   `yaml:"oidc_client_id"`
	OIDCClientSecret string   `yaml:"oidc_client_secret"`
	OIDCAdminGroups  []string `yaml:"oidc_admin_groups"`
	OIDCGroupsClaim  string   `yaml:"oidc_groups_claim"`
	OIDCScopes       []string `yaml:"oidc_scopes"`
	GrafanaURL       string   `yaml:"grafana_url"`
	PrometheusURL    string   `yaml:"prometheus_url"`
	DerperImage      string   `yaml:"derper_image"`
	AgentImage       string   `yaml:"agent_image"`
	CaddyImage       string   `yaml:"caddy_image"`
	ACMEEmail        string   `yaml:"acme_email"`
	ACMEDirectory    string   `yaml:"acme_directory"`
}

func Load(path string) (Config, error) {
	c := Config{HTTPAddr: ":8080", TLSAddr: ":8443", WebDir: "web/dist", OIDCGroupsClaim: "groups", OIDCScopes: []string{"openid", "profile", "email", "groups"}, AgentImage: "ghcr.io/as214933/derpers-contorller-agent:edge", DerperImage: "ghcr.io/as214933/derpers-contorller-derper:edge", CaddyImage: "caddy:2.11.7", ACMEDirectory: "https://acme-v02.api.letsencrypt.org/directory"}
	if path != "" {
		b, e := os.ReadFile(path)
		if e != nil {
			return c, e
		}
		if e = yaml.Unmarshal(b, &c); e != nil {
			return c, e
		}
	}
	env := map[string]*string{"DATABASE_URL": &c.DatabaseURL, "MASTER_KEY": &c.MasterKey, "HTTP_ADDR": &c.HTTPAddr, "TLS_ADDR": &c.TLSAddr, "TLS_CERT_FILE": &c.TLSCertFile, "TLS_KEY_FILE": &c.TLSKeyFile, "NODE_CA_CERT_FILE": &c.NodeCACertFile, "NODE_CA_KEY_FILE": &c.NodeCAKeyFile, "CONTROLLER_URL": &c.ControllerURL, "PUBLIC_URL": &c.PublicURL, "WEB_DIR": &c.WebDir, "OIDC_ISSUER": &c.OIDCIssuer, "OIDC_CLIENT_ID": &c.OIDCClientID, "OIDC_CLIENT_SECRET": &c.OIDCClientSecret, "OIDC_GROUPS_CLAIM": &c.OIDCGroupsClaim, "GRAFANA_URL": &c.GrafanaURL, "PROMETHEUS_URL": &c.PrometheusURL, "DERPER_IMAGE": &c.DerperImage, "CADDY_IMAGE": &c.CaddyImage, "ACME_EMAIL": &c.ACMEEmail, "ACME_DIRECTORY": &c.ACMEDirectory}
	for k, p := range env {
		if s, ok := os.LookupEnv(k); ok {
			*p = s
		}
	}
	if s, ok := os.LookupEnv("AGENT_IMAGE"); ok {
		c.AgentImage = s
	}
	if s, ok := os.LookupEnv("HEADSCALE_ALLOWED_CIDRS"); ok {
		c.AllowedCIDRs = split(s)
	}
	if s, ok := os.LookupEnv("OIDC_ADMIN_GROUPS"); ok {
		c.OIDCAdminGroups = split(s)
	}
	if s, ok := os.LookupEnv("OIDC_SCOPES"); ok {
		c.OIDCScopes = split(s)
	}
	if c.DatabaseURL == "" {
		return c, errors.New("DATABASE_URL is required")
	}
	key, e := base64.StdEncoding.DecodeString(c.MasterKey)
	if e != nil || len(key) != 32 {
		return c, errors.New("MASTER_KEY must be base64 encoding of 32 random bytes")
	}
	return c, nil
}
func split(s string) []string {
	var a []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			a = append(a, v)
		}
	}
	return a
}
