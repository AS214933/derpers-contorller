package controller

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AS214933/derpers-contorller/internal/config"
	"github.com/AS214933/derpers-contorller/internal/model"
	"github.com/AS214933/derpers-contorller/internal/store"
)

type snapshot struct {
	Revision int64
	Expires  time.Time
	Keys     map[string]time.Time
}
type App struct {
	Config                                                       config.Config
	Store                                                        *store.Store
	mu                                                           sync.RWMutex
	snapshots                                                    map[string]snapshot
	syncLocks                                                    sync.Map
	CA                                                           *x509.Certificate
	Signer                                                       crypto.Signer
	CAPEM                                                        []byte
	auth                                                         *authentication
	allowed, denied, failures, syncFailures, certificateFailures atomic.Uint64
}

func New(c config.Config, s *store.Store) (*App, error) {
	a := &App{Config: c, Store: s, snapshots: map[string]snapshot{}}
	if c.NodeCACertFile != "" {
		b, e := os.ReadFile(c.NodeCACertFile)
		if e != nil {
			return nil, e
		}
		p, _ := pem.Decode(b)
		if p == nil {
			return nil, errors.New("invalid node CA certificate")
		}
		a.CA, e = x509.ParseCertificate(p.Bytes)
		if e != nil {
			return nil, e
		}
		if !a.CA.IsCA {
			return nil, errors.New("node certificate issuer must be a CA")
		}
		a.CAPEM = b
		b, e = os.ReadFile(c.NodeCAKeyFile)
		if e != nil {
			return nil, e
		}
		p, _ = pem.Decode(b)
		if p == nil {
			return nil, errors.New("invalid node CA key")
		}
		var k any
		k, e = x509.ParsePKCS8PrivateKey(p.Bytes)
		if e != nil {
			k, e = x509.ParseECPrivateKey(p.Bytes)
		}
		if e != nil {
			k, e = x509.ParsePKCS1PrivateKey(p.Bytes)
		}
		if e != nil {
			return nil, e
		}
		var ok bool
		a.Signer, ok = k.(crypto.Signer)
		if !ok {
			return nil, errors.New("unsupported issuer key")
		}
		issuerPublic, e := x509.MarshalPKIXPublicKey(a.CA.PublicKey)
		if e != nil {
			return nil, e
		}
		signerPublic, e := x509.MarshalPKIXPublicKey(a.Signer.Public())
		if e != nil {
			return nil, e
		}
		if !bytes.Equal(issuerPublic, signerPublic) {
			return nil, errors.New("node CA certificate and private key do not match")
		}
	}
	return a, nil
}
func (a *App) InitAuth(ctx context.Context) error {
	if a.Config.OIDCIssuer == "" {
		return nil
	}
	b, e := newAuthentication(ctx, a)
	if e == nil {
		a.auth = b
	}
	return e
}
func (a *App) Background(ctx context.Context) {
	go a.certificateWorker(ctx)
	go func() {
		a.syncAll(ctx)
		tick := time.NewTicker(5 * time.Minute)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				a.syncAll(ctx)
			}
		}
	}()
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if e := a.Store.Cleanup(ctx); e != nil {
					slog.Error("cleanup failed")
				}
			}
		}
	}()
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			a.RenewCertificates(ctx)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}
func (a *App) invalidate(id string) { a.mu.Lock(); delete(a.snapshots, id); a.mu.Unlock() }
func (a *App) event(ctx context.Context, event, actor, nodeID, networkID, detail string) {
	if e := a.Store.Audit(ctx, model.Audit{Event: event, Actor: actor, NodeID: nodeID, NetworkID: networkID, Detail: detail}); e != nil {
		slog.Error("audit write failed", "event", event)
	} else {
		slog.Info(event, "actor", actor, "node_id", nodeID, "network_id", networkID, "detail", detail)
	}
}
func (a *App) SignClient(ctx context.Context, nodeID, csrPEM string) (model.EnrollmentResponse, error) {
	if a.CA == nil || a.Signer == nil {
		return model.EnrollmentResponse{}, errors.New("node CA is not configured")
	}
	p, _ := pem.Decode([]byte(csrPEM))
	if p == nil {
		return model.EnrollmentResponse{}, errors.New("invalid CSR")
	}
	csr, e := x509.ParseCertificateRequest(p.Bytes)
	if e != nil {
		return model.EnrollmentResponse{}, errors.New("invalid CSR")
	}
	if e = csr.CheckSignature(); e != nil {
		return model.EnrollmentResponse{}, errors.New("invalid CSR signature")
	}
	n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return model.EnrollmentResponse{}, e
	}
	u, _ := url.Parse("spiffe://derpers/node/" + nodeID)
	now := time.Now()
	until := now.Add(7 * 24 * time.Hour)
	if until.After(a.CA.NotAfter) {
		until = a.CA.NotAfter
	}
	if until.Before(now.Add(time.Hour)) {
		return model.EnrollmentResponse{}, errors.New("node CA needs renewal")
	}
	tmpl := &x509.Certificate{SerialNumber: n, NotBefore: now.Add(-time.Minute), NotAfter: until, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, a.CA, csr.PublicKey, a.Signer)
	if e != nil {
		return model.EnrollmentResponse{}, e
	}
	_, e = a.Store.Pool.Exec(ctx, "INSERT INTO node_serials(serial,node_id,expires) VALUES($1,$2,$3)", n.String(), nodeID, until)
	if e != nil {
		return model.EnrollmentResponse{}, e
	}
	return model.EnrollmentResponse{NodeID: nodeID, ClientCertificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), CACertificate: string(a.CAPEM)}, nil
}
func (a *App) NodeIdentity(r *http.Request) (model.Node, error) {
	var n model.Node
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return n, errors.New("verified node certificate required")
	}
	c := r.TLS.PeerCertificates[0]
	var id string
	for _, u := range c.URIs {
		if u.Scheme == "spiffe" && u.Host == "derpers" && strings.HasPrefix(u.Path, "/node/") {
			id = strings.TrimPrefix(u.Path, "/node/")
		}
	}
	if id == "" {
		return n, errors.New("invalid node identity")
	}
	var actual string
	e := a.Store.Pool.QueryRow(r.Context(), "SELECT node_id FROM node_serials WHERE serial=$1 AND expires>now()", c.SerialNumber.String()).Scan(&actual)
	if e != nil || actual != id {
		return n, errors.New("node certificate is revoked")
	}
	rec, e := a.Store.Get(r.Context(), "node", id)
	if e != nil {
		return n, e
	}
	n, e = store.Decode[model.Node](rec)
	if e != nil || !n.Enabled {
		return n, errors.New("node is disabled")
	}
	return n, nil
}
func (a *App) TLSConfig() (*tls.Config, error) {
	cert, e := tls.LoadX509KeyPair(a.Config.TLSCertFile, a.Config.TLSKeyFile)
	if e != nil {
		return nil, e
	}
	pool := x509.NewCertPool()
	if len(a.CAPEM) == 0 || !pool.AppendCertsFromPEM(a.CAPEM) {
		return nil, errors.New("node CA is required")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool}, nil
}
func (a *App) privateClient(extraCA string, timeout time.Duration) *http.Client {
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	if extraCA != "" {
		roots.AppendCertsFromPEM([]byte(extraCA))
	}
	prefixes := []netip.Prefix{}
	for _, s := range a.Config.AllowedCIDRs {
		if p, e := netip.ParsePrefix(s); e == nil {
			prefixes = append(prefixes, p)
		}
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, Proxy: nil}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(addr)
		if e != nil {
			return nil, e
		}
		ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if e != nil {
			return nil, e
		}
		if len(ips) == 0 {
			return nil, errors.New("host has no addresses")
		}
		for _, ip := range ips {
			if !allowedIP(ip, prefixes) {
				return nil, errors.New("destination address is not permitted")
			}
		}
		d := net.Dialer{Timeout: timeout}
		var last error
		for _, ip := range ips {
			c, e := d.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
			if e == nil {
				return c, nil
			}
			last = e
		}
		return nil, last
	}
	return &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are not permitted") }}
}
func allowedIP(ip netip.Addr, allowed []netip.Prefix) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	for _, p := range allowed {
		if p.Contains(ip) {
			return true
		}
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}
func validHTTPS(raw string) error {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("a valid HTTPS URL without embedded credentials is required")
	}
	return nil
}
func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if status != 204 {
		_ = json.NewEncoder(w).Encode(v)
	}
}
func failure(w http.ResponseWriter, status int, msg string) {
	jsonResponse(w, status, map[string]string{"error": msg})
}
func body(r *http.Request, v any) error {
	d := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	if e := d.Decode(v); e != nil {
		return errors.New("invalid JSON request")
	}
	var trailing any
	if e := d.Decode(&trailing); e != io.EOF {
		return errors.New("unexpected trailing JSON content")
	}
	return nil
}
func certRoots(extra string) (*x509.CertPool, error) {
	p, e := x509.SystemCertPool()
	if e != nil {
		p = x509.NewCertPool()
	}
	if extra != "" && !p.AppendCertsFromPEM([]byte(extra)) {
		return nil, fmt.Errorf("invalid CA PEM")
	}
	return p, nil
}
