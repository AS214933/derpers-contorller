package model

import (
	"encoding/json"
	"time"
)

type User struct {
	ID      string   `json:"id"`
	Subject string   `json:"subject"`
	Email   string   `json:"email"`
	Name    string   `json:"name"`
	Groups  []string `json:"groups"`
	Admin   bool     `json:"admin"`
}

type Network struct {
	ID          string     `json:"id"`
	OwnerID     string     `json:"owner_id"`
	Name        string     `json:"name"`
	Kind        string     `json:"kind"`
	Status      string     `json:"status"`
	Health      string     `json:"health"`
	Revision    int64      `json:"revision"`
	Tailnet     string     `json:"tailnet,omitempty"`
	URL         string     `json:"url,omitempty"`
	DeviceCount int        `json:"device_count"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	Note        string     `json:"note,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

type Node struct {
	ID              string             `json:"id"`
	Name            string             `json:"name"`
	RegionID        int                `json:"region_id"`
	RegionCode      string             `json:"region_code"`
	RegionName      string             `json:"region_name"`
	Hostname        string             `json:"hostname"`
	IPv4            string             `json:"ipv4"`
	IPv6            string             `json:"ipv6"`
	HTTPSPort       int                `json:"https_port"`
	STUNPort        int                `json:"stun_port"`
	STUNEnabled     bool               `json:"stun_enabled"`
	HTTPEnabled     bool               `json:"http_enabled"`
	DNSAccountID    string             `json:"dns_account_id,omitempty"`
	Enabled         bool               `json:"enabled"`
	Published       bool               `json:"published"`
	Revision        int64              `json:"revision"`
	AppliedRevision int64              `json:"applied_revision"`
	Status          string             `json:"status"`
	LastSeen        *time.Time         `json:"last_seen,omitempty"`
	Metrics         map[string]float64 `json:"metrics,omitempty"`
	DerperImage     string             `json:"derper_image"`
	CaddyImage      string             `json:"caddy_image"`
}

type DNSAccount struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Provider  string `json:"provider"`
	Zone      string `json:"zone"`
	Suffix    string `json:"suffix"`
	Health    string `json:"health"`
	LastError string `json:"last_error,omitempty"`
}

type Task struct {
	ID        string          `json:"id"`
	NodeID    string          `json:"node_id"`
	Type      string          `json:"type"`
	Status    string          `json:"status"`
	Payload   json.RawMessage `json:"payload"`
	Message   string          `json:"message,omitempty"`
	Logs      string          `json:"logs,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

type Audit struct {
	ID         string    `json:"id"`
	Time       time.Time `json:"time"`
	Event      string    `json:"event"`
	Actor      string    `json:"actor"`
	NodeID     string    `json:"node_id,omitempty"`
	NetworkID  string    `json:"network_id,omitempty"`
	NodePublic string    `json:"node_public,omitempty"`
	Allow      *bool     `json:"allow,omitempty"`
	Detail     string    `json:"detail"`
}

type NodeConfig struct {
	NodeID            string `json:"node_id"`
	Revision          int64  `json:"revision"`
	Hostname          string `json:"hostname"`
	HTTPSPort         int    `json:"https_port"`
	STUNPort          int    `json:"stun_port"`
	STUNEnabled       bool   `json:"stun_enabled"`
	HTTPEnabled       bool   `json:"http_enabled"`
	ControllerURL     string `json:"controller_url"`
	CAPEM             string `json:"ca_pem"`
	CertificatePEM    string `json:"certificate_pem"`
	CertificateKeyPEM string `json:"certificate_key_pem"`
	DerperImage       string `json:"derper_image"`
	CaddyImage        string `json:"caddy_image"`
	DerperKey         string `json:"derper_key,omitempty"`
}

type EnrollmentRequest struct {
	Token string `json:"token"`
	CSR   string `json:"csr"`
}
type EnrollmentResponse struct {
	NodeID            string `json:"node_id"`
	ClientCertificate string `json:"client_certificate"`
	CACertificate     string `json:"ca_certificate"`
}
type TaskResult struct {
	TaskID  string `json:"task_id"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Logs    string `json:"logs,omitempty"`
}
type Report struct {
	Revision int64              `json:"revision"`
	Status   string             `json:"status"`
	Metrics  map[string]float64 `json:"metrics,omitempty"`
	Results  []TaskResult       `json:"results,omitempty"`
}
