package controller

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	dnsapi "github.com/AS214933/derpers-contorller/internal/dns"
	"github.com/AS214933/derpers-contorller/internal/model"
	"github.com/AS214933/derpers-contorller/internal/store"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type acmeUser struct {
	email        string
	key          crypto.PrivateKey
	registration *registration.Resource
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.registration }

type contextualTransport struct {
	ctx  context.Context
	base http.RoundTripper
}

func (t contextualTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(t.ctx, cancel)
	res, e := t.base.RoundTrip(r.Clone(ctx))
	if e != nil {
		stop()
		cancel()
		return nil, e
	}
	res.Body = &cancelBody{ReadCloser: res.Body, finish: func() { stop(); cancel() }}
	return res, nil
}

type cancelBody struct {
	io.ReadCloser
	finish func()
}

func (b *cancelBody) Close() error { defer b.finish(); return b.ReadCloser.Close() }

func (a *App) queueProvision(ctx context.Context, id, actor string) (model.Task, error) {
	rec, e := a.Store.Get(ctx, "node", id)
	if e != nil {
		return model.Task{}, e
	}
	n, e := store.Decode[model.Node](rec)
	if e != nil {
		return model.Task{}, e
	}
	if !n.Enabled {
		return model.Task{}, errors.New("node is disabled")
	}
	account, _, e := a.dnsAccount(ctx, n.DNSAccountID)
	if e != nil {
		return model.Task{}, errors.New("configure a DNS account before provisioning")
	}
	if !within(n.Hostname, account.Suffix) {
		return model.Task{}, errors.New("hostname is outside DNS suffix")
	}
	if _, e = desiredDNS(n); e != nil {
		return model.Task{}, e
	}
	if a.Config.ACMEEmail == "" {
		return model.Task{}, errors.New("ACME_EMAIL must be configured")
	}
	// One controller instance is supported. The SQL lock also prevents duplicate UI requests.
	conn, e := a.Store.Pool.Acquire(ctx)
	if e != nil {
		return model.Task{}, e
	}
	defer conn.Release()
	_, e = conn.Exec(ctx, "SELECT pg_advisory_lock(hashtext($1))", "provision-queue:"+id)
	if e != nil {
		return model.Task{}, e
	}
	defer conn.Exec(context.Background(), "SELECT pg_advisory_unlock(hashtext($1))", "provision-queue:"+id)
	tasks, e := a.nodeTasks(ctx, id, false)
	if e != nil {
		return model.Task{}, e
	}
	for _, t := range tasks {
		if t.Type == "provision" && (t.Status == "pending" || t.Status == "running") {
			return t, nil
		}
	}
	t := model.Task{ID: store.ID(), NodeID: id, Type: "provision", Status: "pending", Payload: json.RawMessage(`{}`), CreatedAt: time.Now().UTC()}
	if e = a.Store.Save(ctx, "task", t.ID, "", 1, t, nil); e == nil {
		a.event(ctx, "certificate_queued", actor, id, "", "DNS and ACME task queued")
	}
	return t, e
}
func (a *App) certificateWorker(ctx context.Context) {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		rows, e := a.Store.List(ctx, "task", "")
		if e == nil {
			for _, r := range rows {
				if ctx.Err() != nil {
					return
				}
				t, e := store.Decode[model.Task](r)
				if e != nil || t.Type != "provision" || (t.Status != "pending" && t.Status != "running") {
					continue
				}
				a.runProvision(ctx, t)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
func (a *App) runProvision(parent context.Context, t model.Task) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Minute)
	defer cancel()
	rec, e := a.Store.Get(ctx, "node", t.NodeID)
	if e != nil {
		_ = a.Store.Patch(ctx, "task", t.ID, 0, map[string]string{"status": "failed", "message": "node no longer exists"})
		return
	}
	n, e := store.Decode[model.Node](rec)
	if e != nil {
		return
	}
	conn, e := a.Store.Pool.Acquire(ctx)
	if e != nil {
		return
	}
	defer conn.Release()
	lock := "acme:" + n.DNSAccountID
	var acquired bool
	e = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtext($1))", lock).Scan(&acquired)
	if e != nil || !acquired {
		return
	}
	defer conn.Exec(context.Background(), "SELECT pg_advisory_unlock(hashtext($1))", lock)
	if e = a.Store.Patch(ctx, "task", t.ID, 0, map[string]string{"status": "running", "message": "preparing DNS and certificate"}); e != nil {
		return
	}
	e = a.provision(ctx, n, rec)
	if parent.Err() != nil {
		return
	} // Keep a resumable running task on shutdown.
	status, msg := "succeeded", "DNS records and certificate ready"
	if e != nil {
		status = "failed"
		msg = e.Error()
		a.certificateFailures.Add(1)
	}
	_ = a.Store.Patch(ctx, "task", t.ID, 0, map[string]string{"status": status, "message": msg})
	a.event(ctx, "certificate_"+status, "system", n.ID, "", msg)
}
func (a *App) provision(ctx context.Context, n model.Node, rec store.Record) error {
	if !n.Enabled {
		return errors.New("node is disabled")
	}
	account, sec, e := a.dnsAccount(ctx, n.DNSAccountID)
	if e != nil {
		return errors.New("DNS account unavailable")
	}
	if e = a.applyDNS(ctx, n, account, sec); e != nil {
		return e
	}
	p, e := dnsapi.Challenge(account.Provider, sec)
	if e != nil {
		return errors.New("DNS challenge provider unavailable")
	}
	// Registration and its private key are persisted, separately for each directory/account/email.
	accountID := store.Hash(account.ID + "\x00" + a.Config.ACMEDirectory + "\x00" + a.Config.ACMEEmail)
	old, e := a.Store.Get(ctx, "acme", accountID)
	revision := int64(1)
	secrets := map[string]string{}
	if e == nil {
		revision = old.Revision + 1
		secrets, e = a.Store.Secrets(old)
	} else if errors.Is(e, store.ErrNotFound) {
		e = nil
	}
	if e != nil {
		return e
	}
	u := &acmeUser{email: a.Config.ACMEEmail}
	if secrets["key"] == "" {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return e
		}
		u.key = key
		b, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return e
		}
		secrets["key"] = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}))
		if e = a.Store.Save(ctx, "acme", accountID, "", revision, map[string]string{"directory": a.Config.ACMEDirectory, "email": a.Config.ACMEEmail}, secrets); e != nil {
			return e
		}
		revision++
	} else {
		b, _ := pem.Decode([]byte(secrets["key"]))
		if b == nil {
			return errors.New("ACME account key is invalid")
		}
		u.key, e = x509.ParsePKCS8PrivateKey(b.Bytes)
		if e != nil {
			return errors.New("ACME account key is invalid")
		}
	}
	if secrets["registration"] != "" {
		u.registration = &registration.Resource{}
		if json.Unmarshal([]byte(secrets["registration"]), u.registration) != nil {
			return errors.New("ACME registration is invalid")
		}
	}
	cfg := lego.NewConfig(u)
	cfg.CADirURL = a.Config.ACMEDirectory
	cfg.Certificate.KeyType = certcrypto.EC256
	cfg.Certificate.Timeout = 8 * time.Minute
	cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second, Transport: contextualTransport{ctx, http.DefaultTransport}}
	client, e := lego.NewClient(cfg)
	if e != nil {
		return errors.New("ACME directory initialization failed")
	}
	if e = client.Challenge.SetDNS01Provider(p); e != nil {
		return errors.New("ACME DNS challenge setup failed")
	}
	if u.registration == nil {
		u.registration, e = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if e != nil {
			return errors.New("ACME registration failed")
		}
		b, _ := json.Marshal(u.registration)
		secrets["registration"] = string(b)
	}
	if e = a.Store.Save(ctx, "acme", accountID, "", revision, map[string]string{"directory": a.Config.ACMEDirectory, "email": a.Config.ACMEEmail}, secrets); e != nil {
		return e
	}
	result, e := client.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{n.Hostname}, Bundle: true})
	if e != nil {
		return errors.New("ACME issuance failed; inspect controller challenge logs")
	}
	if e = validCertificate(n.Hostname, string(result.Certificate), string(result.PrivateKey)); e != nil {
		return e
	}
	// A node edited or disabled while ACME was running must not receive stale materials.
	latest, e := a.Store.Get(ctx, "node", n.ID)
	if e != nil || latest.Revision != rec.Revision {
		return store.ErrConflict
	}
	current, e := store.Decode[model.Node](latest)
	if e != nil || !current.Enabled {
		return store.ErrConflict
	}
	nodeSecrets, e := a.Store.Secrets(latest)
	if e != nil {
		return e
	}
	nodeSecrets["certificate_pem"] = string(result.Certificate)
	nodeSecrets["certificate_key_pem"] = string(result.PrivateKey)
	delete(nodeSecrets, "ca_pem")
	current.Revision++
	if e = a.Store.Save(ctx, "node", n.ID, "", current.Revision, current, nodeSecrets); e != nil {
		return e
	}
	_ = a.Store.Patch(ctx, "dns", account.ID, 0, map[string]string{"health": "healthy", "last_error": ""})
	return nil
}
func (a *App) RenewCertificates(ctx context.Context) {
	rows, e := a.Store.List(ctx, "node", "")
	if e != nil {
		return
	}
	for _, r := range rows {
		n, e := store.Decode[model.Node](r)
		if e != nil || !n.Enabled || n.DNSAccountID == "" {
			continue
		}
		s, e := a.Store.Secrets(r)
		if e != nil {
			continue
		}
		p, _ := pem.Decode([]byte(s["certificate_pem"]))
		if p == nil {
			continue
		}
		cert, e := x509.ParseCertificate(p.Bytes)
		if e != nil {
			continue
		}
		if needsRenewal(cert, time.Now()) {
			_, _ = a.queueProvision(ctx, n.ID, "system")
		}
	}
}
func needsRenewal(c *x509.Certificate, now time.Time) bool {
	return c.NotAfter.Sub(now) <= c.NotAfter.Sub(c.NotBefore)/3
}

func (a *App) metrics(w http.ResponseWriter, r *http.Request) {
	// HTTP is bound to the private application network and blocked at the public Caddy ingress.
	// Direct HTTPS access requires an administrator's OIDC session.
	if r.TLS != nil {
		u, e := a.currentUser(r)
		if e != nil || !u.Admin {
			failure(w, 403, "administrator required")
			return
		}
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	writeMetric(w, "derpers_admissions_allowed_total", float64(a.allowed.Load()), "")
	writeMetric(w, "derpers_admissions_denied_total", float64(a.denied.Load()), "")
	writeMetric(w, "derpers_admission_errors_total", float64(a.failures.Load()), "")
	writeMetric(w, "derpers_sync_errors_total", float64(a.syncFailures.Load()), "")
	writeMetric(w, "derpers_certificate_errors_total", float64(a.certificateFailures.Load()), "")
	rows, e := a.Store.List(r.Context(), "node", "")
	if e != nil {
		return
	}
	for _, rec := range rows {
		n, e := store.Decode[model.Node](rec)
		if e != nil {
			continue
		}
		labels := `node_id="` + n.ID + `"`
		online := float64(0)
		if n.LastSeen != nil && time.Since(*n.LastSeen) < time.Minute {
			online = 1
		}
		writeMetric(w, "derpers_node_online", online, labels)
		if sec, e := a.Store.Secrets(rec); e == nil {
			if p, _ := pem.Decode([]byte(sec["certificate_pem"])); p != nil {
				if cert, e := x509.ParseCertificate(p.Bytes); e == nil {
					writeMetric(w, "derpers_node_certificate_expires_seconds", float64(cert.NotAfter.Unix()), labels)
				}
			}
		}
		for k, v := range n.Metrics {
			if metricName(k) {
				writeMetric(w, "derpers_node_"+k, v, labels)
			}
		}
	}
}
func metricName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c != '_' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
func writeMetric(w http.ResponseWriter, name string, value float64, labels string) {
	if labels != "" {
		labels = "{" + labels + "}"
	}
	_, _ = w.Write([]byte(name + labels + " " + formatFloat(value) + "\n"))
}
func formatFloat(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }
