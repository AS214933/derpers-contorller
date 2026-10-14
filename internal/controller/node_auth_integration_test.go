package controller

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AS214933/derpers-contorller/internal/model"
	"github.com/AS214933/derpers-contorller/internal/nodeauth"
	"github.com/go-jose/go-jose/v4"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// Requests cross a real public HTTPS terminator and a plain HTTP origin. The
// controller never receives a TLS connection or a forwarded client certificate.
type nodeProofFixture struct {
	app       *App
	node      model.Node
	pair      tls.Certificate
	signer    *nodeauth.Signer
	edge      *httptest.Server
	client    *http.Client
	plainHops atomic.Uint64
}

func newNodeProofFixture(t *testing.T) *nodeProofFixture {
	t.Helper()
	a := integrationApp(t)
	a.Config.NodeAuthMode = "proof"
	identityCA(t, a)
	now := time.Now()
	cert, private, _ := testCertificate(t, "proof-node.example.test", now.Add(-time.Hour), now.Add(24*time.Hour))
	node, err := a.AddNode(context.Background(), model.Node{Name: "proof-node", Hostname: "proof-node.example.test", RegionID: 900}, map[string]string{"certificate_pem": cert, "certificate_key_pem": private})
	if err != nil {
		t.Fatal(err)
	}
	f := &nodeProofFixture{app: a, node: node}
	handler := a.Handler()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			t.Error("proxy fixture unexpectedly supplied origin TLS")
		}
		f.plainHops.Add(1)
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(origin.Close)
	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	f.edge = httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(originURL))
	t.Cleanup(f.edge.Close)
	f.client = f.edge.Client()
	f.client.Timeout = 5 * time.Second
	f.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	a.Config.ControllerURL = f.edge.URL
	a.Config.PublicURL = f.edge.URL
	token, err := a.Store.NewEnrollment(context.Background(), node.ID)
	if err != nil {
		t.Fatal(err)
	}
	csr, identityPrivate := csrMaterial(t)
	raw, err := json.Marshal(model.EnrollmentRequest{Token: token, CSR: csr})
	if err != nil {
		t.Fatal(err)
	}
	r := f.request(t, http.MethodPost, "/api/v1/node-enroll", raw, false)
	status, response := f.do(t, r)
	if status != 200 {
		t.Fatalf("registration over HTTP origin=%d %s", status, response)
	}
	var enrolled model.EnrollmentResponse
	if err := json.Unmarshal(response, &enrolled); err != nil || enrolled.NodeID != node.ID {
		t.Fatalf("registration identity=%q err=%v", enrolled.NodeID, err)
	}
	f.pair, err = tls.X509KeyPair([]byte(enrolled.ClientCertificate), []byte(identityPrivate))
	if err != nil {
		t.Fatal(err)
	}
	f.pair.Leaf, err = x509.ParseCertificate(f.pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	f.signer, err = nodeauth.NewSigner(f.pair)
	if err != nil {
		t.Fatal(err)
	}
	// Enrollment remains one-use even through the ordinary HTTP reverse proxy.
	if status, _ := f.do(t, f.request(t, http.MethodPost, "/api/v1/node-enroll", raw, false)); status != 403 {
		t.Fatalf("registration token replay=%d", status)
	}
	return f
}

func (f *nodeProofFixture) request(t *testing.T, method, target string, raw []byte, sign bool) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, f.edge.URL+target, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if raw != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if sign {
		if err := f.signer.Sign(r, raw, f.app.Config.ControllerURL); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func (f *nodeProofFixture) do(t *testing.T, r *http.Request) (int, []byte) {
	t.Helper()
	res, err := f.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("node/auth response may be cached: method=%s target=%s status=%d cache=%q", r.Method, r.URL.RequestURI(), res.StatusCode, res.Header.Get("Cache-Control"))
	}
	return res.StatusCode, raw
}

func TestIntegrationNodeProofThroughTLSHTTPProxy(t *testing.T) {
	f := newNodeProofFixture(t)
	r := f.request(t, http.MethodGet, "/node/v1/config?filter=a&filter=b&encoded=%2F", nil, true)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(f.app.CAPEM)
	proof, err := nodeauth.VerifyRequest(r, nil, roots, f.app.Config.ControllerURL, time.Now())
	if err != nil || proof.NodeID != f.node.ID {
		t.Fatalf("request proof failed standalone verification: %v", err)
	}
	status, raw := f.do(t, r)
	var configuration model.NodeConfig
	if status != 200 || json.Unmarshal(raw, &configuration) != nil || configuration.NodeID != f.node.ID || configuration.CertificateKeyPEM == "" {
		t.Fatalf("authenticated config=%d %s", status, raw)
	}
	pub := key.NewNode().Public()
	network := saveTestNetwork(t, f.app, model.Network{Name: "proof-authorized", Kind: "tailscale", Tailnet: "example.test"}, nil)
	f.app.mu.Lock()
	f.app.snapshots[network.ID] = snapshot{Revision: network.Revision, Expires: time.Now().Add(time.Minute), Keys: map[string]time.Time{pub.String(): time.Now().Add(time.Minute)}}
	f.app.mu.Unlock()
	admit, err := json.Marshal(tailcfg.DERPAdmitClientRequest{NodePublic: pub})
	if err != nil {
		t.Fatal(err)
	}
	// Whitespace is part of the signed raw body and must reach JSON decoding unchanged.
	admit = append(append([]byte(" \n"), admit...), '\n')
	status, raw = f.do(t, f.request(t, http.MethodPost, "/admission/v1/verify", admit, true))
	var result tailcfg.DERPAdmitClientResponse
	if status != 200 || json.Unmarshal(raw, &result) != nil || !result.Allow {
		t.Fatalf("authenticated admission=%d %s", status, raw)
	}
	unknown, _ := json.Marshal(tailcfg.DERPAdmitClientRequest{NodePublic: key.NewNode().Public()})
	status, raw = f.do(t, f.request(t, http.MethodPost, "/admission/v1/verify", unknown, true))
	if status != 200 || json.Unmarshal(raw, &result) != nil || result.Allow {
		t.Fatalf("unknown client admission=%d %s", status, raw)
	}
	csr, renewalPrivate := csrMaterial(t)
	renew, _ := json.Marshal(map[string]string{"csr": csr})
	status, raw = f.do(t, f.request(t, http.MethodPost, "/node/v1/renew", renew, true))
	var renewed model.EnrollmentResponse
	if status != 200 || json.Unmarshal(raw, &renewed) != nil || renewed.NodeID != f.node.ID {
		t.Fatalf("authenticated renewal=%d %s", status, raw)
	}
	renewedPair, err := tls.X509KeyPair([]byte(renewed.ClientCertificate), []byte(renewalPrivate))
	if err != nil || bytes.Equal(renewedPair.Certificate[0], f.pair.Certificate[0]) {
		t.Fatalf("renewal failed to issue a fresh matching identity: %v", err)
	}
	renewedSigner, err := nodeauth.NewSigner(renewedPair)
	if err != nil {
		t.Fatal(err)
	}
	r = f.request(t, http.MethodGet, "/node/v1/config", nil, false)
	if err := renewedSigner.Sign(r, nil, f.app.Config.ControllerURL); err != nil {
		t.Fatal(err)
	}
	if status, _ := f.do(t, r); status != 200 {
		t.Fatalf("renewed identity could not authenticate: status=%d", status)
	}
	if f.plainHops.Load() < 6 {
		t.Fatal("requests did not traverse the plain HTTP origin")
	}
	// The proxy's actual localhost origin peer must not implicitly authorize a scrape.
	if status, _ := f.do(t, f.request(t, http.MethodGet, "/metrics", nil, false)); status != 403 {
		t.Fatalf("proxy loopback origin bypassed metrics authentication: status=%d", status)
	}
}

func TestIntegrationNodeProofTamperingAndForgedProxyIdentity(t *testing.T) {
	f := newNodeProofFixture(t)
	body := []byte(`{"NodePublic":"` + key.NewNode().Public().String() + `"}`)
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"method binding", func(r *http.Request) { r.Method = http.MethodPost }},
		{"path binding", func(r *http.Request) { r.URL.Path = "/node/v1/tasks" }},
		{"escaped path binding", func(r *http.Request) { r.URL.RawPath = "/node/v1/%63onfig" }},
		{"query binding", func(r *http.Request) { r.URL.RawQuery = "q=changed" }},
		{"duplicate query order binding", func(r *http.Request) { r.URL.RawQuery = "q=two&q=one" }},
		{"missing authorization", func(r *http.Request) { r.Header.Del("Authorization") }},
		{"empty authorization", func(r *http.Request) { r.Header["Authorization"] = []string{""} }},
		{"duplicate authorization", func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) }},
		{"wrong authorization scheme", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+strings.TrimPrefix(r.Header.Get("Authorization"), nodeauth.Scheme+" "))
		}},
		{"unsupported content encoding", func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := f.request(t, http.MethodGet, "/node/v1/config?q=one&q=two", nil, true)
			tc.mutate(r)
			// None of these headers are certificate proof, even when they claim success.
			r.Header.Set("X-Forwarded-Client-Cert", string(f.app.CAPEM))
			r.Header.Set("X-SSL-Client-Verify", "SUCCESS")
			r.Header.Set("X-SSL-Client-S-DN", "spiffe://derpers/node/"+f.node.ID)
			r.Header.Set("X-Forwarded-Proto", "https")
			if status, _ := f.do(t, r); status != 403 {
				t.Fatalf("tampered request accepted: status=%d", status)
			}
		})
	}
	r := f.request(t, http.MethodPost, "/admission/v1/verify", body, true)
	changed := append(append([]byte(nil), body...), ' ')
	r.Body = io.NopCloser(bytes.NewReader(changed))
	r.ContentLength = int64(len(changed))
	if status, _ := f.do(t, r); status != 403 {
		t.Fatalf("mutated raw body accepted: status=%d", status)
	}
	r = f.request(t, http.MethodGet, "/node/v1/config", nil, false)
	if err := f.signer.Sign(r, nil, "https://other-controller.example.test"); err != nil {
		t.Fatal(err)
	}
	r.Host = "other-controller.example.test"
	r.Header.Set("Forwarded", "host=other-controller.example.test;proto=https")
	r.Header.Set("X-Forwarded-Host", "other-controller.example.test")
	if status, _ := f.do(t, r); status != 403 {
		t.Fatalf("Host or forwarded header changed configured audience: status=%d", status)
	}
	// Correctly signed invalid JSON reaches the ordinary business decoder and is
	// denied instead of being rewritten or accidentally authorized by the bridge.
	invalid := []byte("{} {}")
	if status, _ := f.do(t, f.request(t, http.MethodPost, "/admission/v1/verify", invalid, true)); status != 400 {
		t.Fatalf("signed malformed admission JSON status=%d", status)
	}
	oversize := append(append([]byte(nil), body...), bytes.Repeat([]byte(" "), 4097)...)
	if status, _ := f.do(t, f.request(t, http.MethodPost, "/admission/v1/verify", oversize, true)); status != 403 {
		t.Fatalf("oversize signed admission bypassed authentication body bounds: status=%d", status)
	}
}

func TestIntegrationNodeProofReplayConcurrentAndAcrossHandlers(t *testing.T) {
	f := newNodeProofFixture(t)
	original := f.request(t, http.MethodGet, "/node/v1/config", nil, true)
	const parallel = 16
	statuses := make(chan int, parallel)
	errors := make(chan error, parallel)
	var wg sync.WaitGroup
	for range parallel {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := original.Clone(context.Background())
			res, err := f.client.Do(r)
			if err != nil {
				errors <- err
				return
			}
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
			statuses <- res.StatusCode
		}()
	}
	wg.Wait()
	close(statuses)
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	accepted, denied := 0, 0
	for status := range statuses {
		switch status {
		case 200:
			accepted++
		case 403:
			denied++
		default:
			t.Errorf("unexpected concurrent replay status=%d", status)
		}
	}
	if accepted != 1 || denied != parallel-1 {
		t.Fatalf("atomic replay guard accepted=%d denied=%d", accepted, denied)
	}
	// A separate App shares only PostgreSQL and the CA, proving replay state is
	// not scoped to a handler, process-local cache, or TLS connection.
	other := &App{Config: f.app.Config, Store: f.app.Store, CA: f.app.CA, CAPEM: f.app.CAPEM}
	clone := original.Clone(context.Background())
	clone.RequestURI = clone.URL.RequestURI()
	clone.TLS = nil
	w := httptest.NewRecorder()
	other.Handler().ServeHTTP(w, clone)
	if w.Code != 403 {
		t.Fatalf("replay accepted by another controller instance: %d", w.Code)
	}
	// A newly signed retry receives its own jti and remains usable.
	if status, _ := f.do(t, f.request(t, http.MethodGet, "/node/v1/config", nil, true)); status != 200 {
		t.Fatalf("freshly signed retry rejected: status=%d", status)
	}
}

func TestIntegrationNodeProofDisabledRevokedAndDatabaseFailure(t *testing.T) {
	f := newNodeProofFixture(t)
	ctx := context.Background()
	if err := f.app.Store.Patch(ctx, "node", f.node.ID, f.node.Revision, map[string]any{"enabled": false}); err != nil {
		t.Fatal(err)
	}
	if status, _ := f.do(t, f.request(t, http.MethodGet, "/node/v1/config", nil, true)); status != 403 {
		t.Fatalf("disabled node authenticated: status=%d", status)
	}
	if err := f.app.Store.Patch(ctx, "node", f.node.ID, f.node.Revision, map[string]any{"enabled": true}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.Store.Pool.Exec(ctx, "UPDATE node_serials SET expires=now()-interval '1 second' WHERE serial=$1", f.pair.Leaf.SerialNumber.String()); err != nil {
		t.Fatal(err)
	}
	if status, _ := f.do(t, f.request(t, http.MethodGet, "/node/v1/config", nil, true)); status != 403 {
		t.Fatalf("revoked certificate authenticated: status=%d", status)
	}
	if _, err := f.app.Store.Pool.Exec(ctx, "UPDATE node_serials SET expires=$2 WHERE serial=$1", f.pair.Leaf.SerialNumber.String(), f.pair.Leaf.NotAfter); err != nil {
		t.Fatal(err)
	}
	if status, _ := f.do(t, f.request(t, http.MethodGet, "/node/v1/config", nil, true)); status != 200 {
		t.Fatalf("restored active fixture failed: status=%d", status)
	}
	// The database serial is deliberately still active. Expiry must be checked
	// on the actual signed certificate, independently of its database row.
	private := f.pair.PrivateKey.(*ecdsa.PrivateKey)
	template := *f.pair.Leaf
	template.NotBefore = time.Now().Add(-2 * time.Hour)
	template.NotAfter = time.Now().Add(-time.Hour)
	expired, err := x509.CreateCertificate(rand.Reader, &template, f.app.CA, &private.PublicKey, f.app.Signer)
	if err != nil {
		t.Fatal(err)
	}
	r := f.request(t, http.MethodGet, "/node/v1/config", nil, true)
	parts := strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), nodeauth.Scheme+" "), ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	expiredSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: private}, (&jose.SignerOptions{}).WithType(jose.ContentType(nodeauth.ProofType)).WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(expired)}))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := expiredSigner.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", nodeauth.Scheme+" "+compact)
	if status, _ := f.do(t, r); status != 403 {
		t.Fatalf("expired certificate with active DB serial authenticated: status=%d", status)
	}
	f.app.Store.Pool.Close()
	if status, _ := f.do(t, f.request(t, http.MethodGet, "/node/v1/config", nil, true)); status != 403 {
		t.Fatalf("database failure authenticated node: status=%d", status)
	}
}

func TestIntegrationNodeProofDefaultAndExplicitHybrid(t *testing.T) {
	f := newNodeProofFixture(t)
	for _, mode := range []string{"", "proof", "hybrid"} {
		t.Run("mode="+mode, func(t *testing.T) {
			f.app.Config.NodeAuthMode = mode
			r := httptest.NewRequest(http.MethodGet, f.app.Config.ControllerURL+"/node/v1/config", nil)
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{f.pair.Leaf}, VerifiedChains: [][]*x509.Certificate{{f.pair.Leaf, f.app.CA}}}
			w := httptest.NewRecorder()
			f.app.Handler().ServeHTTP(w, r)
			want := 403
			if mode == "hybrid" {
				want = 200
			}
			if w.Code != want {
				t.Fatalf("native verified mTLS status=%d want=%d", w.Code, want)
			}
			for _, invalid := range [][]string{{""}, {"DerpersProof invalid"}, {"", ""}} {
				clone := r.Clone(context.Background())
				clone.Header["Authorization"] = invalid
				w := httptest.NewRecorder()
				f.app.Handler().ServeHTTP(w, clone)
				if w.Code != 403 {
					t.Fatalf("invalid present Authorization fell back to mTLS: status=%d", w.Code)
				}
			}
		})
	}
	f.app.Config.NodeAuthMode = "hybrid"
	if status, _ := f.do(t, f.request(t, http.MethodGet, "/node/v1/config", nil, false)); status != 403 {
		t.Fatalf("hybrid trusted ordinary HTTP without proof: status=%d", status)
	}
}
