package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/AS214933/derpers-contorller/internal/model"
	"github.com/AS214933/derpers-contorller/internal/store"
)

func (a *App) AddNode(ctx context.Context, n model.Node, sec map[string]string) (model.Node, error) {
	return a.addNode(ctx, n, sec, "operator")
}
func (a *App) addNode(ctx context.Context, n model.Node, sec map[string]string, actor string) (model.Node, error) {
	if n.HTTPSPort == 0 {
		n.HTTPSPort = 443
	}
	if n.STUNPort == 0 {
		n.STUNPort = 3478
	}
	if n.RegionCode == "" {
		n.RegionCode = n.Name
	}
	if n.RegionName == "" {
		n.RegionName = n.Name
	}
	if n.DerperImage == "" {
		n.DerperImage = a.Config.DerperImage
	}
	if n.CaddyImage == "" {
		n.CaddyImage = a.Config.CaddyImage
	}
	rows, e := a.Store.List(ctx, "node", "")
	if e != nil {
		return n, e
	}
	taken := map[int]bool{}
	for _, r := range rows {
		v, _ := store.Decode[model.Node](r)
		taken[v.RegionID] = true
		if strings.EqualFold(v.Hostname, n.Hostname) {
			return n, errors.New("hostname is already assigned")
		}
	}
	if n.RegionID == 0 {
		for i := 900; i <= 999; i++ {
			if !taken[i] {
				n.RegionID = i
				break
			}
		}
	}
	if taken[n.RegionID] {
		return n, errors.New("region ID is already assigned")
	}
	if e = validNode(n); e != nil {
		return n, e
	}
	if n.DNSAccountID != "" {
		account, _, e := a.dnsAccount(ctx, n.DNSAccountID)
		if e != nil {
			return n, errors.New("DNS account does not exist")
		}
		if !within(n.Hostname, account.Suffix) {
			return n, errors.New("hostname must be within DNS account suffix")
		}
	}
	if sec["certificate_pem"] != "" {
		if e = validCertificate(n.Hostname, sec["certificate_pem"], sec["certificate_key_pem"]); e != nil {
			return n, e
		}
	}
	n.ID = store.ID()
	n.Revision = 1
	n.Enabled = true
	n.Published = false
	n.Status = "awaiting_enrollment"
	n.AppliedRevision = 0
	n.LastSeen = nil
	n.Metrics = nil
	e = a.Store.Save(ctx, "node", n.ID, "", 1, n, sec)
	if e == nil {
		a.event(ctx, "node_created", actor, n.ID, "", "node configuration created")
	}
	return n, e
}
func validCertificate(host, cert, key string) error {
	c, e := tls.X509KeyPair([]byte(cert), []byte(key))
	if e != nil {
		return errors.New("invalid certificate/private key pair")
	}
	leaf, e := x509.ParseCertificate(c.Certificate[0])
	if e != nil {
		return e
	}
	if e = leaf.VerifyHostname(host); e != nil {
		return errors.New("certificate does not match node hostname")
	}
	if time.Now().Before(leaf.NotBefore) || time.Until(leaf.NotAfter) < time.Hour {
		return errors.New("certificate is not currently valid")
	}
	return nil
}
func (a *App) PublishNode(ctx context.Context, id string) (model.Node, error) {
	return a.publishNode(ctx, id, "operator")
}
func (a *App) publishNode(ctx context.Context, id, actor string) (model.Node, error) {
	r, e := a.Store.Get(ctx, "node", id)
	if e != nil {
		return model.Node{}, e
	}
	n, e := store.Decode[model.Node](r)
	if e != nil {
		return n, e
	}
	sec, e := a.Store.Secrets(r)
	if e != nil {
		return n, e
	}
	if !n.Enabled || n.AppliedRevision != n.Revision || n.LastSeen == nil || time.Since(*n.LastSeen) > time.Minute {
		return n, errors.New("node must apply the current configuration and report a recent heartbeat before publishing")
	}
	client := a.privateClient(sec["ca_pem"], 5*time.Second)
	defer client.CloseIdleConnections()
	u := "https://" + n.Hostname + ":" + strconv.Itoa(n.HTTPSPort) + "/derp/probe"
	req, e := http.NewRequestWithContext(ctx, "GET", u, nil)
	if e != nil {
		return n, e
	}
	res, e := client.Do(req)
	if e != nil {
		return n, errors.New("node TLS/probe health check failed")
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		return n, errors.New("node probe did not return HTTP 200")
	}
	n.Published = true
	e = a.Store.Patch(ctx, "node", id, n.Revision, map[string]any{"published": true})
	if e == nil {
		a.event(ctx, "node_published", actor, id, "", "TLS and probe validated")
	}
	return n, e
}
func (a *App) NodeConfig(ctx context.Context, id string) (model.NodeConfig, error) {
	r, e := a.Store.Get(ctx, "node", id)
	if e != nil {
		return model.NodeConfig{}, e
	}
	n, e := store.Decode[model.Node](r)
	if e != nil {
		return model.NodeConfig{}, e
	}
	sec, e := a.Store.Secrets(r)
	if e != nil {
		return model.NodeConfig{}, e
	}
	if e = validCertificate(n.Hostname, sec["certificate_pem"], sec["certificate_key_pem"]); e != nil {
		return model.NodeConfig{}, errors.New("node certificate is not provisioned or is expired")
	}
	return model.NodeConfig{NodeID: n.ID, Revision: n.Revision, Hostname: n.Hostname, HTTPSPort: n.HTTPSPort, STUNPort: n.STUNPort, STUNEnabled: n.STUNEnabled, HTTPEnabled: n.HTTPEnabled, ControllerURL: strings.TrimRight(a.Config.ControllerURL, "/"), CAPEM: sec["ca_pem"], CertificatePEM: sec["certificate_pem"], CertificateKeyPEM: sec["certificate_key_pem"], DerperImage: n.DerperImage, CaddyImage: n.CaddyImage, DerperKey: sec["derper_key"]}, nil
}
func (a *App) enroll(w http.ResponseWriter, r *http.Request) {
	// The public HTTPS edge may forward HTTP over the trusted origin network.
	// Enrollment authenticates its one-use token and CSR, not proxy headers.
	var v model.EnrollmentRequest
	if body(r, &v) != nil || v.Token == "" || len(v.CSR) > 16384 {
		failure(w, 400, "token and CSR required")
		return
	}
	p, _ := pem.Decode([]byte(v.CSR))
	if p == nil {
		failure(w, 400, "invalid CSR")
		return
	}
	csr, e := x509.ParseCertificateRequest(p.Bytes)
	if e != nil || csr.CheckSignature() != nil {
		failure(w, 400, "invalid CSR")
		return
	}
	id, e := a.Store.ConsumeEnrollment(r.Context(), v.Token)
	if e != nil {
		failure(w, 403, "invalid or expired enrollment token")
		return
	}
	rec, e := a.Store.Get(r.Context(), "node", id)
	if e != nil {
		failure(w, 403, "node unavailable")
		return
	}
	n, e := store.Decode[model.Node](rec)
	if e != nil || !n.Enabled {
		failure(w, 403, "node disabled")
		return
	}
	res, e := a.SignClient(r.Context(), id, v.CSR)
	if e != nil {
		failure(w, 503, "certificate issuance unavailable")
		return
	}
	a.event(r.Context(), "node_enrolled", "node", id, "", "one-time enrollment completed")
	jsonResponse(w, 200, res)
}
func (a *App) nodeAPI(w http.ResponseWriter, r *http.Request) {
	n, e := a.NodeIdentity(r)
	if e != nil {
		failure(w, 403, "authenticated active node identity required")
		return
	}
	ctx := r.Context()
	switch r.URL.Path {
	case "/node/v1/config":
		if r.Method != "GET" {
			break
		}
		c, e := a.NodeConfig(ctx, n.ID)
		if e != nil {
			failure(w, 503, e.Error())
			return
		}
		jsonResponse(w, 200, c)
		return
	case "/node/v1/tasks":
		if r.Method != "GET" {
			break
		}
		tasks, e := a.nodeTasks(ctx, n.ID, true)
		if e != nil {
			failure(w, 503, "tasks unavailable")
			return
		}
		jsonResponse(w, 200, tasks)
		return
	case "/node/v1/report":
		if r.Method != "POST" {
			break
		}
		var v model.Report
		if body(r, &v) != nil {
			failure(w, 400, "invalid report")
			return
		}
		if v.Revision < 0 || v.Revision > n.Revision || len(v.Results) > 100 || len(v.Metrics) > 64 || len(v.Status) > 64 {
			failure(w, 400, "invalid report bounds")
			return
		}
		e = a.Store.ReportNode(ctx, n.ID, v)
		if e != nil {
			failure(w, 503, "report storage failed")
			return
		}
		for _, result := range v.Results {
			if result.Status != "succeeded" && result.Status != "failed" && result.Status != "rolled_back" {
				continue
			}
			rec, e := a.Store.Get(ctx, "task", result.TaskID)
			if e != nil {
				continue
			}
			t, e := store.Decode[model.Task](rec)
			if e != nil || t.NodeID != n.ID || t.Type == "provision" || t.Status != "pending" {
				continue
			}
			msg := limit(result.Message, 2048)
			logs := limit(result.Logs, 128<<10)
			result.Message = msg
			result.Logs = logs
			if e = a.Store.CompleteNodeTask(ctx, t, result); e != nil {
				failure(w, 503, "task result storage failed")
				return
			}
			a.event(ctx, "node_task_"+result.Status, "node", n.ID, "", t.Type+": "+msg)
		}
		jsonResponse(w, 204, nil)
		return
	case "/node/v1/renew":
		if r.Method != "POST" {
			break
		}
		var v struct {
			CSR string `json:"csr"`
		}
		if body(r, &v) != nil {
			failure(w, 400, "invalid CSR")
			return
		}
		res, e := a.SignClient(ctx, n.ID, v.CSR)
		if e != nil {
			failure(w, 400, "certificate renewal failed")
			return
		}
		a.event(ctx, "node_identity_renewed", "node:"+n.ID, n.ID, "", "node identity certificate renewed")
		jsonResponse(w, 200, res)
		return
	}
	failure(w, 405, "unsupported node operation")
}
func limit(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
func (a *App) nodeTasks(ctx context.Context, id string, pendingOnly bool) ([]model.Task, error) {
	rows, e := a.Store.List(ctx, "task", "")
	if e != nil {
		return nil, e
	}
	out := []model.Task{}
	for _, r := range rows {
		t, e := store.Decode[model.Task](r)
		if e != nil {
			return nil, e
		}
		if t.NodeID == id && (!pendingOnly || t.Status == "pending" && t.Type != "provision") {
			out = append(out, t)
		}
	}
	return out, nil
}

var digestImage = regexp.MustCompile(`^[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}$`)

func (a *App) nodesAPI(w http.ResponseWriter, r *http.Request, u model.User, parts []string) {
	ctx := r.Context()
	if len(parts) == 0 && r.Method == "GET" {
		rows, e := a.Store.List(ctx, "node", "")
		if e != nil {
			failure(w, 503, "nodes unavailable")
			return
		}
		out := []model.Node{}
		for _, row := range rows {
			n, e := store.Decode[model.Node](row)
			if e != nil {
				continue
			}
			if u.Admin || n.Enabled && n.Published {
				if !u.Admin {
					n.DerperImage = ""
					n.CaddyImage = ""
					n.DNSAccountID = ""
					n.Metrics = publicHealthMetrics(n.Metrics)
				}
				if n.LastSeen != nil && time.Since(*n.LastSeen) > time.Minute {
					n.Status = "offline"
				}
				out = append(out, n)
			}
		}
		jsonResponse(w, 200, out)
		return
	}
	if !u.Admin {
		failure(w, 403, "administrator required")
		return
	}
	if len(parts) == 0 && r.Method == "POST" {
		var n model.Node
		if e := body(r, &n); e != nil {
			apiError(w, e)
			return
		}
		v, e := a.addNode(ctx, n, map[string]string{}, u.ID)
		if e != nil {
			apiError(w, e)
			return
		}
		jsonResponse(w, 201, v)
		return
	}
	if len(parts) == 0 {
		failure(w, 405, "unsupported operation")
		return
	}
	if (len(parts) == 1 && (r.Method == "PUT" || r.Method == "DELETE")) || (len(parts) == 2 && (parts[1] == "dns-import" || parts[1] == "dns-cleanup") && r.Method == "POST") {
		unlock, e := a.Store.Lock(ctx, "node-operation:"+parts[0])
		if e != nil {
			apiError(w, e)
			return
		}
		defer unlock()
	}
	rec, e := a.Store.Get(ctx, "node", parts[0])
	if e != nil {
		apiError(w, e)
		return
	}
	n, e := store.Decode[model.Node](rec)
	if e != nil {
		apiError(w, e)
		return
	}
	if len(parts) == 1 {
		switch r.Method {
		case "GET":
			jsonResponse(w, 200, n)
			return
		case "DELETE":
			if n.Published {
				failure(w, 409, "unpublish node before deleting")
				return
			}
			unlockZone, e := a.lockDNS(ctx, n)
			if e != nil {
				apiError(w, e)
				return
			}
			defer unlockZone()
			if e = a.RemoveDNS(ctx, n); e != nil {
				apiError(w, e)
				return
			}
			if e = a.Store.Delete(ctx, "node", n.ID); e != nil {
				apiError(w, e)
				return
			}
			a.event(ctx, "node_deleted", u.ID, n.ID, "", "node removed; credentials revoked")
			jsonResponse(w, 204, nil)
			return
		case "PUT":
			var v model.Node
			if body(r, &v) != nil {
				failure(w, 400, "invalid node")
				return
			}
			v.ID = n.ID
			v.Revision = n.Revision + 1
			v.AppliedRevision = n.AppliedRevision
			v.LastSeen = n.LastSeen
			v.Status = n.Status
			v.Published = n.Published
			v.RegionID = n.RegionID
			if v.DerperImage == "" {
				v.DerperImage = n.DerperImage
			}
			if v.CaddyImage == "" {
				v.CaddyImage = n.CaddyImage
			}
			if v.DerperImage != n.DerperImage || v.CaddyImage != n.CaddyImage {
				failure(w, 409, "change images through a digest-pinned upgrade task")
				return
			}
			if e = validNode(v); e != nil {
				apiError(w, e)
				return
			}
			if v.DNSAccountID != "" {
				account, _, e := a.dnsAccount(ctx, v.DNSAccountID)
				if e != nil {
					apiError(w, e)
					return
				}
				if !within(v.Hostname, account.Suffix) {
					failure(w, 400, "hostname must be within DNS account suffix")
					return
				}
			}
			if v.Hostname != n.Hostname {
				v.Published = false
			}
			if v.Hostname != n.Hostname || v.DNSAccountID != n.DNSAccountID {
				owned, e := a.ownedDNS(ctx, n.DNSAccountID, n.ID)
				if e != nil {
					apiError(w, e)
					return
				}
				if len(owned) > 0 {
					failure(w, 409, "clean up owned DNS records before changing hostname or account")
					return
				}
			}
			if e = a.Store.Save(ctx, "node", n.ID, "", v.Revision, v, nil); e != nil {
				apiError(w, e)
				return
			}
			a.event(ctx, "node_updated", u.ID, n.ID, "", "configuration revision updated")
			jsonResponse(w, 200, v)
			return
		}
	}
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	switch parts[1] {
	case "dns-import":
		if r.Method != "POST" {
			break
		}
		unlockZone, e := a.lockDNS(ctx, n)
		if e != nil {
			apiError(w, e)
			return
		}
		defer unlockZone()
		var v struct {
			RecordIDs []string `json:"record_ids"`
		}
		if body(r, &v) != nil {
			failure(w, 400, "record IDs required")
			return
		}
		if e = a.ImportDNS(ctx, n.ID, v.RecordIDs); e != nil {
			apiError(w, e)
			return
		}
		a.event(ctx, "dns_imported", u.ID, n.ID, "", "administrator imported record ownership")
		jsonResponse(w, 200, map[string]string{"status": "ok"})
		return
	case "dns-cleanup":
		if r.Method != "POST" {
			break
		}
		unlockZone, e := a.lockDNS(ctx, n)
		if e != nil {
			apiError(w, e)
			return
		}
		defer unlockZone()
		if n.Published {
			failure(w, 409, "unpublish before DNS cleanup")
			return
		}
		if e = a.RemoveDNS(ctx, n); e != nil {
			apiError(w, e)
			return
		}
		a.event(ctx, "dns_removed", u.ID, n.ID, "", "owned records removed")
		jsonResponse(w, 200, map[string]string{"status": "ok"})
		return
	case "token":
		if r.Method != "POST" {
			break
		}
		t, e := a.Store.NewEnrollment(ctx, n.ID)
		if e != nil {
			failure(w, 503, "token issuance failed")
			return
		}
		a.event(ctx, "node_token", u.ID, n.ID, "", "one-time token issued")
		jsonResponse(w, 200, map[string]string{"token": t, "node_id": n.ID})
		return
	case "publish":
		if r.Method != "POST" {
			break
		}
		v, e := a.publishNode(ctx, n.ID, u.ID)
		if e != nil {
			apiError(w, e)
			return
		}
		jsonResponse(w, 200, v)
		return
	case "unpublish":
		if r.Method != "POST" {
			break
		}
		if e = a.Store.Patch(ctx, "node", n.ID, n.Revision, map[string]any{"published": false}); e != nil {
			apiError(w, e)
			return
		}
		n.Published = false
		a.event(ctx, "node_unpublished", u.ID, n.ID, "", "removed from exported maps")
		jsonResponse(w, 200, n)
		return
	case "provision":
		if r.Method != "POST" {
			break
		}
		t, e := a.queueProvision(ctx, n.ID, u.ID)
		if e != nil {
			apiError(w, e)
			return
		}
		jsonResponse(w, 202, t)
		return
	case "deployment":
		if r.Method != "GET" {
			break
		}
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write([]byte(a.Deployment(n)))
		return
	case "tasks":
		if r.Method == "GET" {
			v, e := a.nodeTasks(ctx, n.ID, false)
			if e != nil {
				apiError(w, e)
				return
			}
			jsonResponse(w, 200, v)
			return
		}
		if r.Method != "POST" {
			break
		}
		if !n.Enabled {
			failure(w, 409, "enable node before queuing agent tasks")
			return
		}
		var t model.Task
		if body(r, &t) != nil {
			failure(w, 400, "invalid task")
			return
		}
		t, e = a.QueueAgentTask(ctx, n.ID, t, u.ID)
		if e != nil {
			apiError(w, e)
			return
		}
		jsonResponse(w, 201, t)
		return
	}
	failure(w, 405, "unsupported node operation")
}

func (a *App) NodeTasks(ctx context.Context, id string) ([]model.Task, error) {
	if _, err := a.Store.Get(ctx, "node", id); err != nil {
		return nil, err
	}
	return a.nodeTasks(ctx, id, false)
}

// QueueAgentTask is shared by the administrator API and local management CLI.
func (a *App) QueueAgentTask(ctx context.Context, id string, t model.Task, actor string) (model.Task, error) {
	rec, err := a.Store.Get(ctx, "node", id)
	if err != nil {
		return t, err
	}
	n, err := store.Decode[model.Node](rec)
	if err != nil {
		return t, err
	}
	if !n.Enabled {
		return t, store.ErrConflict
	}
	var p map[string]any
	if json.Unmarshal(t.Payload, &p) != nil {
		return t, errors.New("payload object required")
	}
	component, _ := p["component"].(string)
	if component != "derper" && component != "caddy" {
		return t, errors.New("component must be derper or caddy")
	}
	if t.Type != "restart" && t.Type != "upgrade" && t.Type != "logs" {
		return t, errors.New("unsupported task type")
	}
	if t.Type == "upgrade" {
		image, _ := p["image"].(string)
		if !digestImage.MatchString(image) {
			return t, errors.New("upgrade image must be pinned by sha256 digest")
		}
		if component == "derper" {
			p["previous_image"] = n.DerperImage
			n.DerperImage = image
		} else {
			p["previous_image"] = n.CaddyImage
			n.CaddyImage = image
		}
		n.Revision++
		p["target_revision"] = n.Revision
	}
	t.ID, t.NodeID, t.Status, t.CreatedAt = store.ID(), n.ID, "pending", time.Now().UTC()
	t.Message, t.Logs = "", ""
	t.Payload, _ = json.Marshal(p)
	if err = a.Store.QueueNodeTask(ctx, n, t); err != nil {
		return t, err
	}
	a.event(ctx, "node_task_queued", actor, n.ID, "", t.Type)
	return t, nil
}
func publicHealthMetrics(metrics map[string]float64) map[string]float64 {
	out := map[string]float64{}
	for _, k := range []string{"derper_up", "derper_process_up", "caddy_process_up", "derper_metrics_up", "derper_probe_timestamp_seconds"} {
		if v, ok := metrics[k]; ok {
			out[k] = v
		}
	}
	return out
}
func (a *App) Deployment(n model.Node) string {
	image := a.Config.AgentImage
	if image == "" {
		image = "ghcr.io/as214933/derpers-contorller-agent:edge"
	}
	network := "derpers-node-" + n.ID
	return fmt.Sprintf(`# Generate a short-lived enrollment token in the portal.
# Set NODE_DIR to an absolute directory on THIS node host, for example:
# NODE_DIR=/opt/derpers/%s
# mkdir -p "$NODE_DIR/agent" "$NODE_DIR/config" ./trust
# Save NODE_DIR and ENROLLMENT_TOKEN in .env beside this Compose file.
# For a private controller CA, put its public certificate in TRUST_DIR and
# set CONTROLLER_CA_FILE=/trust/controller-ca.crt before first enrollment.
services:
  agent:
    image: %q
    restart: unless-stopped
    environment:
      CONTROLLER_URL: %q
      ENROLLMENT_TOKEN: "${ENROLLMENT_TOKEN}"
      CONTROLLER_CA_FILE: "${CONTROLLER_CA_FILE:-}"
      NODE_ID: %q
      STATE_DIR: /var/lib/derpers-agent
      CONFIG_DIR: /node
      HOST_STATE_DIR: "${NODE_DIR:?set NODE_DIR to an absolute node directory}/agent"
      HOST_CONFIG_DIR: "${NODE_DIR:?set NODE_DIR to an absolute node directory}/config"
      DOCKER_NETWORK: %q
      MANAGE_CONTAINERS: "true"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - "${NODE_DIR:?set NODE_DIR to an absolute node directory}/agent:/var/lib/derpers-agent"
      - "${NODE_DIR:?set NODE_DIR to an absolute node directory}/config:/node"
      - "${TRUST_DIR:-./trust}:/trust:ro"
    networks: [node]
networks:
  node:
    name: %q
`, n.ID, image, a.Config.ControllerURL, n.ID, network, network)
}
