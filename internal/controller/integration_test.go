package controller

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AS214933/derpers-contorller/internal/config"
	"github.com/AS214933/derpers-contorller/internal/model"
	"github.com/AS214933/derpers-contorller/internal/store"
	"github.com/jackc/pgx/v5"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// Integration tests use an isolated, uniquely named schema. No existing table or
// record in TEST_DATABASE_URL is changed, including when a test fails.
func integrationApp(t *testing.T) *App {
	t.Helper()
	raw := os.Getenv("TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	bootstrap, err := pgx.Connect(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	schema := "derpers_test_" + store.ID()
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = bootstrap.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		bootstrap.Close(context.Background())
		t.Fatal(err)
	}
	scoped := raw
	if strings.HasPrefix(raw, "postgres://") || strings.HasPrefix(raw, "postgresql://") {
		u, e := url.Parse(raw)
		if e != nil {
			t.Fatal(e)
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		scoped = u.String()
	} else {
		scoped += " search_path=" + schema
	}
	s, err := store.Open(ctx, scoped, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x39}, 32)))
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if s != nil {
			s.Close()
		}
		if _, e := bootstrap.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); e != nil {
			t.Errorf("isolated schema cleanup: %v", e)
		}
		bootstrap.Close(cleanup)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, err := New(config.Config{NodeAuthMode: "hybrid", PublicURL: "https://controller.example.test", ControllerURL: "https://controller.example.test", AllowedCIDRs: []string{"127.0.0.1/32", "::1/128"}, DerperImage: "ghcr.io/as214933/derpers-contorller-derper:edge", CaddyImage: "caddy:2.11.7"}, s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func saveTestNetwork(t *testing.T, a *App, n model.Network, sec map[string]string) model.Network {
	t.Helper()
	if n.ID == "" {
		n.ID = store.ID()
	}
	if n.OwnerID == "" {
		n.OwnerID = "owner"
	}
	if n.Revision == 0 {
		n.Revision = 1
	}
	if n.Status == "" {
		n.Status = "approved"
	}
	n.CreatedAt = time.Now().UTC()
	if err := a.Store.Save(context.Background(), "network", n.ID, n.OwnerID, n.Revision, n, sec); err != nil {
		t.Fatal(err)
	}
	return n
}
func headscaleFixture(t *testing.T, handler http.HandlerFunc) (string, string) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	return server.URL + "/verify", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
}

func TestIntegrationMultipleSourcesORAndFailureIsolation(t *testing.T) {
	a := integrationApp(t)
	pub := key.NewNode().Public()
	denial, denialCA := headscaleFixture(t, func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 200, tailcfg.DERPAdmitClientResponse{Allow: false})
	})
	good, goodCA := headscaleFixture(t, func(w http.ResponseWriter, r *http.Request) {
		var req tailcfg.DERPAdmitClientRequest
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			t.Error("invalid DERP request")
		}
		jsonResponse(w, 200, tailcfg.DERPAdmitClientResponse{Allow: req.NodePublic == pub})
	})
	failed, failedCA := headscaleFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) })
	saveTestNetwork(t, a, model.Network{Kind: "headscale", Name: "denies", URL: denial}, map[string]string{"ca_pem": denialCA})
	trusted := saveTestNetwork(t, a, model.Network{Kind: "headscale", Name: "allows", URL: good}, map[string]string{"ca_pem": goodCA})
	saveTestNetwork(t, a, model.Network{Kind: "headscale", Name: "unavailable", URL: failed}, map[string]string{"ca_pem": failedCA})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	allow, source, err := a.decide(ctx, tailcfg.DERPAdmitClientRequest{NodePublic: pub})
	if err != nil || !allow || source != trusted.ID {
		t.Fatalf("valid source must survive other denial/failure: allow=%v source=%q err=%v", allow, source, err)
	}
	allow, _, err = a.decide(ctx, tailcfg.DERPAdmitClientRequest{NodePublic: key.NewNode().Public()})
	if allow || err == nil {
		t.Fatalf("unknown key must fail closed when a source is unavailable: %v %v", allow, err)
	}
}

func TestIntegrationSnapshotExpiresAndChecksRevision(t *testing.T) {
	a := integrationApp(t)
	pub := key.NewNode().Public()
	n := saveTestNetwork(t, a, model.Network{Name: "official", Kind: "tailscale", Tailnet: "example.test"}, nil)
	put := func(expires, until time.Time, revision int64) {
		a.mu.Lock()
		a.snapshots[n.ID] = snapshot{Revision: revision, Expires: expires, Keys: map[string]time.Time{pub.String(): until}}
		a.mu.Unlock()
	}
	decide := func(want bool) {
		t.Helper()
		got, _, err := a.decide(context.Background(), tailcfg.DERPAdmitClientRequest{NodePublic: pub})
		if err != nil || got != want {
			t.Fatalf("allow=%v want=%v err=%v", got, want, err)
		}
	}
	now := time.Now()
	put(now.Add(time.Minute), now.Add(time.Minute), n.Revision)
	decide(true)
	put(now.Add(-time.Second), now.Add(time.Minute), n.Revision)
	decide(false)
	put(now.Add(time.Minute), now.Add(-time.Second), n.Revision)
	decide(false)
	put(now.Add(time.Minute), now.Add(time.Minute), n.Revision+1)
	decide(false)
	put(now.Add(time.Minute), now.Add(time.Minute), n.Revision)
	if _, err := a.SetNetworkStatus(context.Background(), n.ID, "disabled", "admin"); err != nil {
		t.Fatal(err)
	}
	decide(false)
	a.mu.RLock()
	_, ok := a.snapshots[n.ID]
	a.mu.RUnlock()
	if ok {
		t.Fatal("disabled source retained snapshot")
	}
}

func TestIntegrationSourceDisabledDuringVerification(t *testing.T) {
	a := integrationApp(t)
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	endpoint, ca := headscaleFixture(t, func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		select {
		case <-release:
			jsonResponse(w, 200, tailcfg.DERPAdmitClientResponse{Allow: true})
		case <-r.Context().Done():
		}
	})
	n := saveTestNetwork(t, a, model.Network{Name: "in-flight", Kind: "headscale", URL: endpoint}, map[string]string{"ca_pem": ca})
	result := make(chan bool, 1)
	go func() {
		allow, _, _ := a.decide(context.Background(), tailcfg.DERPAdmitClientRequest{NodePublic: key.NewNode().Public()})
		result <- allow
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("Headscale verification did not start")
	}
	if _, err := a.SetNetworkStatus(context.Background(), n.ID, "disabled", "admin"); err != nil {
		close(release)
		t.Fatal(err)
	}
	close(release)
	select {
	case allow := <-result:
		if allow {
			t.Fatal("stale in-flight approval survived disable/revision change")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("verification did not finish")
	}
}

func authenticatedRequest(t *testing.T, a *App, u model.User, method, path string, payload any, origin string) *httptest.ResponseRecorder {
	t.Helper()
	session := store.Token()
	if err := a.Store.SetSession(context.Background(), session, u, time.Hour); err != nil {
		t.Fatal(err)
	}
	var reader io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	r := httptest.NewRequest(method, path, reader)
	r.AddCookie(&http.Cookie{Name: "derpers_session", Value: session})
	if payload != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	return w
}

func TestIntegrationOwnershipAdministratorAndOrigin(t *testing.T) {
	a := integrationApp(t)
	owner := model.User{ID: "owner-a"}
	other := model.User{ID: "owner-b"}
	admin := model.User{ID: "admin", Admin: true}
	n := saveTestNetwork(t, a, model.Network{Name: "private-a", Kind: "headscale", OwnerID: owner.ID, URL: "https://hs.example.test/verify"}, map[string]string{"bearer_token": "super-secret-value"})
	saveTestNetwork(t, a, model.Network{Name: "private-b", Kind: "headscale", OwnerID: other.ID, URL: "https://hs.example.test/verify"}, nil)
	for _, tc := range []struct {
		name         string
		user         model.User
		method, path string
		payload      any
		origin       string
		status       int
	}{
		{"another owner cannot read", other, "GET", "/api/v1/networks/" + n.ID, nil, "", 403},
		{"another owner cannot delete", other, "DELETE", "/api/v1/networks/" + n.ID, nil, "", 403},
		{"owner cannot approve", owner, "POST", "/api/v1/networks/" + n.ID + "/approve", nil, "", 403},
		{"owner cannot read DNS", owner, "GET", "/api/v1/dns-accounts", nil, "", 403},
		{"owner cannot change settings", owner, "PUT", "/api/v1/settings", map[string]string{"approval_mode": "automatic"}, "", 403},
		{"owner cannot create node", owner, "POST", "/api/v1/nodes", map[string]string{"name": "forbidden"}, "", 403},
		{"owner cannot read audit", owner, "GET", "/api/v1/audit", nil, "", 403},
		{"cross-origin admin mutation rejected", admin, "PUT", "/api/v1/settings", map[string]string{"approval_mode": "automatic"}, "https://evil.example.test", 403},
		{"same-origin admin mutation allowed", admin, "PUT", "/api/v1/settings", map[string]string{"approval_mode": "manual"}, a.Config.PublicURL, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := authenticatedRequest(t, a, tc.user, tc.method, tc.path, tc.payload, tc.origin)
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d response=%s", w.Code, tc.status, w.Body.String())
			}
		})
	}
	for _, u := range []model.User{owner, other, admin} {
		w := authenticatedRequest(t, a, u, "GET", "/api/v1/networks", nil, "")
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
		var networks []model.Network
		if err := json.Unmarshal(w.Body.Bytes(), &networks); err != nil {
			t.Fatal(err)
		}
		want := 1
		if u.Admin {
			want = 2
		}
		if len(networks) != want {
			t.Fatalf("user=%s got %d networks want %d", u.ID, len(networks), want)
		}
		if strings.Contains(w.Body.String(), "super-secret-value") || strings.Contains(w.Body.String(), "bearer_token") {
			t.Fatal("secret leaked through network read")
		}
	}
	anonymous := httptest.NewRecorder()
	a.Handler().ServeHTTP(anonymous, httptest.NewRequest("GET", "/api/v1/me", nil))
	if anonymous.Code != 401 {
		t.Fatal("anonymous API request authenticated")
	}
}

func TestIntegrationEncryptionAndAtomicOneUseEnrollment(t *testing.T) {
	a := integrationApp(t)
	ctx := context.Background()
	n := saveTestNetwork(t, a, model.Network{Name: "encrypted", Kind: "headscale"}, map[string]string{"bearer_token": "private-credential-never-plaintext"})
	rec, err := a.Store.Get(ctx, "network", n.ID)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rec.Secret, []byte("private-credential")) {
		t.Fatal("credential stored in plaintext")
	}
	secrets, err := a.Store.Secrets(rec)
	if err != nil || secrets["bearer_token"] != "private-credential-never-plaintext" {
		t.Fatalf("credential roundtrip: %v", err)
	}
	if _, err = a.Store.Decrypt("network", store.ID(), rec.Secret); err == nil {
		t.Fatal("ciphertext was reusable for a different resource")
	}
	tampered := append([]byte(nil), rec.Secret...)
	tampered[len(tampered)-1] ^= 1
	if _, err = a.Store.Decrypt("network", n.ID, tampered); err == nil {
		t.Fatal("tampered credential decrypted")
	}
	token, err := a.Store.NewEnrollment(ctx, "node-one-use")
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err = a.Store.Pool.QueryRow(ctx, "SELECT count(*) FROM enrollments WHERE hash=$1", token).Scan(&count); err != nil || count != 0 {
		t.Fatal("enrollment token stored in plaintext")
	}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := a.Store.ConsumeEnrollment(ctx, token)
			if err == nil {
				if id != "node-one-use" {
					t.Errorf("wrong enrollment node %q", id)
				}
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("one-use token accepted %d times", accepted.Load())
	}
	expired, err := a.Store.NewEnrollment(ctx, "node-expired")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Store.Pool.Exec(ctx, "UPDATE enrollments SET expires=now()-interval '1 second' WHERE hash=$1", store.Hash(expired)); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Store.ConsumeEnrollment(ctx, expired); err == nil {
		t.Fatal("expired token accepted")
	}
}

func identityCA(t *testing.T, a *App) *ecdsa.PrivateKey {
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(41), Subject: pkix.Name{CommonName: "DERPers integration CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &signer.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	a.CA, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	a.Signer = signer
	a.CAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return signer
}
func signedTLSCertificate(t *testing.T, a *App, key *ecdsa.PrivateKey, template *x509.Certificate) tls.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, a.CA, &key.PublicKey, a.Signer)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	if err != nil {
		t.Fatal(err)
	}
	return pair
}
func csrMaterial(t *testing.T) (string, string) {
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "attacker-chosen-name"}, DNSNames: []string{"attacker.example.test"}}, signer)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
}

func TestIntegrationRealMTLSEnrollmentRenewalAndRevocation(t *testing.T) {
	a := integrationApp(t)
	identityCA(t, a)
	ctx := context.Background()
	now := time.Now()
	relayCert, relayKey, _ := testCertificate(t, "node.example.test", now.Add(-time.Hour), now.Add(24*time.Hour))
	node, err := a.AddNode(ctx, model.Node{Name: "integration-node", Hostname: "node.example.test", RegionID: 900, HTTPSPort: 443, STUNPort: 3478}, map[string]string{"certificate_pem": relayCert, "certificate_key_pem": relayKey})
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverCert := signedTLSCertificate(t, a, serverKey, &x509.Certificate{SerialNumber: big.NewInt(42), IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(a.CAPEM)
	server := httptest.NewUnstartedServer(a.Handler())
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	makeClient := func(certs ...tls.Certificate) *http.Client {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: certs, MinVersion: tls.VersionTLS12}}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr, Timeout: 3 * time.Second}
	}
	anonymous := makeClient()
	res, err := anonymous.Get(server.URL + "/node/v1/config")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatal("anonymous node API access permitted")
	}
	token, err := a.Store.NewEnrollment(ctx, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	csr, private := csrMaterial(t)
	post := func(client *http.Client, path string, payload any) (int, []byte) {
		t.Helper()
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		res, err := client.Post(server.URL+path, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, body
	}
	status, _ := post(anonymous, "/api/v1/node-enroll", model.EnrollmentRequest{Token: token, CSR: "invalid"})
	if status != 400 {
		t.Fatal("invalid CSR accepted")
	}
	status, b := post(anonymous, "/api/v1/node-enroll", model.EnrollmentRequest{Token: token, CSR: csr})
	if status != 200 {
		t.Fatalf("enrollment=%d %s", status, b)
	}
	var enrolled model.EnrollmentResponse
	if err = json.Unmarshal(b, &enrolled); err != nil {
		t.Fatal(err)
	}
	if enrolled.NodeID != node.ID {
		t.Fatal("incorrect enrolled identity")
	}
	block, _ := pem.Decode([]byte(enrolled.ClientCertificate))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 0 || leaf.Subject.CommonName != "" || len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://derpers/node/"+node.ID {
		t.Fatalf("CSR-supplied identity escaped node binding: %+v", leaf)
	}
	status, _ = post(anonymous, "/api/v1/node-enroll", model.EnrollmentRequest{Token: token, CSR: csr})
	if status != 403 {
		t.Fatal("enrollment token reused")
	}
	pair, err := tls.X509KeyPair([]byte(enrolled.ClientCertificate), []byte(private))
	if err != nil {
		t.Fatal(err)
	}
	client := makeClient(pair)
	res, err = client.Get(server.URL + "/node/v1/config")
	if err != nil {
		t.Fatal(err)
	}
	var cfg model.NodeConfig
	err = json.NewDecoder(res.Body).Decode(&cfg)
	res.Body.Close()
	if err != nil || res.StatusCode != 200 || cfg.NodeID != node.ID {
		t.Fatalf("mTLS node config failed %v status %d", err, res.StatusCode)
	}
	renewedCSR, _ := csrMaterial(t)
	status, b = post(client, "/node/v1/renew", map[string]string{"csr": renewedCSR})
	if status != 200 {
		t.Fatalf("renewal=%d %s", status, b)
	}
	var renewed model.EnrollmentResponse
	if err = json.Unmarshal(b, &renewed); err != nil || renewed.NodeID != node.ID || renewed.ClientCertificate == enrolled.ClientCertificate {
		t.Fatal("renewal did not issue a fresh certificate bound to node")
	}
	expiredKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://derpers/node/" + node.ID)
	expiredCert := signedTLSCertificate(t, a, expiredKey, &x509.Certificate{SerialNumber: big.NewInt(999), URIs: []*url.URL{uri}, NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	res, err = makeClient(expiredCert).Get(server.URL + "/node/v1/config")
	if err == nil {
		res.Body.Close()
		t.Fatal("expired certificate passed the real TLS handshake")
	}
	if _, err = a.Store.Pool.Exec(ctx, "UPDATE node_serials SET expires=now()-interval '1 second' WHERE serial=$1", leaf.SerialNumber.String()); err != nil {
		t.Fatal(err)
	}
	res, err = client.Get(server.URL + "/node/v1/config")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatalf("revoked serial was allowed: %d", res.StatusCode)
	}
}
