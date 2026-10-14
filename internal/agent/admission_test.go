package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AS214933/derpers-contorller/internal/model"
	"github.com/AS214933/derpers-contorller/internal/nodeauth"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func signingIdentityWithRoots(t *testing.T) (identity, *x509.CertPool) {
	t.Helper()
	ca := newTestCA(t, "node request signing CA")
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	pair, err := tls.X509KeyPair(ca.sign(t, private.Public(), false), privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.pem)
	return identity{NodeID: "node-1", Certificate: pair, PrivatePEM: privatePEM}, roots
}

func signingIdentityForTest(t *testing.T) identity {
	t.Helper()
	id, _ := signingIdentityWithRoots(t)
	return id
}

func admissionBody(t *testing.T) []byte {
	t.Helper()
	b, err := json.MarshalIndent(tailcfg.DERPAdmitClientRequest{NodePublic: key.NewNode().Public()}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

func TestAdmissionRelaySignsExactProtocolBytesAcrossTLSProxy(t *testing.T) {
	id, roots := signingIdentityWithRoots(t)
	body := admissionBody(t)
	var edge *httptest.Server
	var mu sync.Mutex
	proofIDs := map[string]bool{}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			t.Error("fixture did not exercise TLS termination before the controller")
		}
		data, _ := io.ReadAll(r.Body)
		if !bytes.Equal(data, body) || r.URL.Path != "/admission/v1/verify" || r.Method != http.MethodPost {
			t.Errorf("relay changed the protocol request: %s %s %q", r.Method, r.URL.Path, data)
		}
		if r.Header.Get("X-Client-Cert") != "" || r.Header.Get("X-Forwarded-Client-Cert") != "" || r.Header.Get("Authorization") == "Bearer spoofed" {
			t.Error("untrusted caller identity reached the controller")
		}
		proof, err := nodeauth.VerifyRequest(r, data, roots, edge.URL, time.Now())
		if err != nil {
			t.Errorf("proof did not survive TLS termination: %v", err)
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		if proof.NodeID != id.NodeID || proofIDs[proof.ID] {
			t.Error("wrong signing identity or reused request proof")
		}
		proofIDs[proof.ID] = true
		mu.Unlock()
		_, _ = io.WriteString(w, `{"Allow":true}`)
	}))
	defer origin.Close()
	originURL, _ := url.Parse(origin.URL)
	edge = httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(originURL))
	defer edge.Close()
	dir := t.TempDir()
	caFile := filepath.Join(dir, "edge-ca.crt")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: edge.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	a := &Agent{cfg: Config{ControllerURL: edge.URL, ControllerCAFile: caFile}, identity: id}
	if err := a.authenticatedClient(); err != nil {
		t.Fatal(err)
	}
	defer a.client.CloseIdleConnections()
	for range 2 {
		r := httptest.NewRequest(http.MethodPost, "http://agent:9081/verify", bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer spoofed")
		r.Header.Set("X-Client-Cert", "spoofed")
		r.Header.Set("X-Forwarded-Client-Cert", "spoofed")
		w := httptest.NewRecorder()
		a.admissionRelay(w, r)
		if w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"Allow":true}` {
			t.Fatalf("signed admission failed through the proxy: %d %s", w.Code, w.Body.String())
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(proofIDs) != 2 {
		t.Fatal("admission requests did not each receive a fresh signature proof")
	}
}

func TestConcurrentAdmissionUsesRenewedIdentitySnapshot(t *testing.T) {
	id, roots := signingIdentityWithRoots(t)
	renewedCA := newTestCA(t, "renewed node request CA")
	roots.AppendCertsFromPEM(renewedCA.pem)
	renewedPEM := renewedCA.sign(t, id.Certificate.Leaf.PublicKey, false)
	block, _ := pem.Decode(renewedPEM)
	renewedCertificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	var server *httptest.Server
	var oldRequests, newRequests atomic.Int32
	var holdAdmissions atomic.Bool
	inflight, release := make(chan struct{}), make(chan struct{})
	var startedOnce, releaseOnce sync.Once
	releaseRequests := func() { releaseOnce.Do(func() { close(release) }) }
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		proof, err := nodeauth.VerifyRequest(r, body, roots, server.URL, time.Now())
		if err != nil {
			t.Errorf("concurrent request used a partial or invalid identity: %v", err)
			w.WriteHeader(401)
			return
		}
		if proof.Certificate.SerialNumber.Cmp(id.Certificate.Leaf.SerialNumber) == 0 {
			oldRequests.Add(1)
		} else if proof.Certificate.SerialNumber.Cmp(renewedCertificate.SerialNumber) == 0 {
			newRequests.Add(1)
		} else {
			t.Error("unexpected signing certificate")
		}
		if r.URL.Path == "/node/v1/renew" {
			json.NewEncoder(w).Encode(model.EnrollmentResponse{NodeID: id.NodeID, ClientCertificate: string(renewedPEM), CACertificate: string(renewedCA.pem)})
			return
		}
		if holdAdmissions.Load() && proof.Certificate.SerialNumber.Cmp(id.Certificate.Leaf.SerialNumber) == 0 {
			startedOnce.Do(func() { close(inflight) })
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		_, _ = io.WriteString(w, `{"Allow":true}`)
	}))
	defer server.Close()
	defer releaseRequests()
	dir := t.TempDir()
	caFile := filepath.Join(dir, "server-ca.crt")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	a := &Agent{cfg: Config{ControllerURL: server.URL, ControllerCAFile: caFile, StateDir: dir, ManageContainers: true}, identity: id, applied: &model.NodeConfig{NodeID: id.NodeID}}
	if err := a.authenticatedClient(); err != nil {
		t.Fatal(err)
	}
	defer func() { a.nodeClient.Load().CloseIdleConnections() }()
	body := admissionBody(t)
	verify := func() {
		w := httptest.NewRecorder()
		a.admissionRelay(w, httptest.NewRequest("POST", "/verify", bytes.NewReader(body)))
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"Allow":true`) {
			t.Errorf("verification failed during renewal: %d %s", w.Code, w.Body.String())
		}
	}
	verify()
	holdAdmissions.Store(true)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 8 {
				verify()
			}
		}()
	}
	close(start)
	select {
	case <-inflight:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent verification did not reach the controller before renewal")
	}
	if err := a.renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	holdAdmissions.Store(false)
	releaseRequests()
	wg.Wait()
	verify()
	if oldRequests.Load() == 0 || newRequests.Load() == 0 {
		t.Fatalf("renewal did not replace the signed-client snapshot: old=%d new=%d", oldRequests.Load(), newRequests.Load())
	}
}

type admissionRoundTripper func(*http.Request) (*http.Response, error)

func (f admissionRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAdmissionRelayRejectsInvalidRequestsWithoutContactingController(t *testing.T) {
	body := admissionBody(t)
	for _, tc := range []struct {
		name, method, target string
		body                 []byte
		status               int
	}{
		{"unknown route", "POST", "/admission/v1/verify", body, 404},
		{"arbitrary URL query", "POST", "/verify?target=http://elsewhere", body, 404},
		{"GET", "GET", "/verify", body, 405},
		{"invalid JSON", "POST", "/verify", []byte(`{"NodePublic":`), 400},
		{"zero key", "POST", "/verify", []byte(`{}`), 400},
		{"oversized body", "POST", "/verify", append(append([]byte{}, body...), bytes.Repeat([]byte(" "), admissionLimit-len(body)+1)...), 413},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			a := &Agent{cfg: Config{ControllerURL: "https://controller.example.test"}}
			a.nodeClient.Store(&http.Client{Transport: admissionRoundTripper(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return nil, errors.New("must not be called")
			})})
			w := httptest.NewRecorder()
			a.admissionRelay(w, httptest.NewRequest(tc.method, tc.target, bytes.NewReader(tc.body)))
			if w.Code != tc.status || !strings.Contains(w.Body.String(), `"Allow":false`) || calls.Load() != 0 {
				t.Fatalf("invalid request was forwarded or allowed: status=%d body=%s calls=%d", w.Code, w.Body.String(), calls.Load())
			}
		})
	}
}

func TestAdmissionRelayDownstreamFailuresNeverAllow(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		err    error
		want   int
	}{
		{"explicit rejection", 200, `{"Allow":false}`, nil, 200},
		{"missing result", 200, `{}`, nil, 503},
		{"null result", 200, `{"Allow":null}`, nil, 503},
		{"string result", 200, `{"Allow":"true"}`, nil, 503},
		{"trailing JSON", 200, `{"Allow":true}{}`, nil, 503},
		{"oversized result", 200, `{"Allow":true}` + strings.Repeat(" ", admissionLimit), nil, 503},
		{"unauthorized", 401, `{"Allow":true}`, nil, 503},
		{"unavailable", 503, `{"Allow":true}`, nil, 503},
		{"redirect", 307, `{"Allow":true}`, nil, 503},
		{"transport failure", 0, "", errors.New("connection refused"), 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &Agent{cfg: Config{ControllerURL: "https://controller.example.test"}}
			a.nodeClient.Store(&http.Client{CheckRedirect: rejectRedirect, Transport: admissionRoundTripper(func(r *http.Request) (*http.Response, error) {
				if tc.err != nil {
					return nil, tc.err
				}
				return &http.Response{StatusCode: tc.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body)), Request: r}, nil
			})})
			w := httptest.NewRecorder()
			a.admissionRelay(w, httptest.NewRequest("POST", "/verify", bytes.NewReader(admissionBody(t))))
			if w.Code != tc.want || !strings.Contains(w.Body.String(), `"Allow":false`) {
				t.Fatalf("downstream failure allowed admission: %d %s", w.Code, w.Body.String())
			}
		})
	}
	var a Agent
	w := httptest.NewRecorder()
	a.admissionRelay(w, httptest.NewRequest("POST", "/verify", bytes.NewReader(admissionBody(t))))
	if w.Code != 503 || !strings.Contains(w.Body.String(), `"Allow":false`) {
		t.Fatal("unenrolled Agent did not fail closed")
	}
}

func TestAdmissionRelayHonorsBodyBoundaryAndCancellation(t *testing.T) {
	body := admissionBody(t)
	body = append(body, bytes.Repeat([]byte(" "), admissionLimit-len(body))...)
	a := &Agent{cfg: Config{ControllerURL: "https://controller.example.test"}}
	a.nodeClient.Store(&http.Client{Transport: admissionRoundTripper(func(r *http.Request) (*http.Response, error) {
		data, _ := io.ReadAll(r.Body)
		if len(data) != admissionLimit {
			t.Errorf("exactly 4KiB was changed or rejected: %d", len(data))
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"Allow":true}`)), Request: r}, nil
	})})
	w := httptest.NewRecorder()
	a.admissionRelay(w, httptest.NewRequest("POST", "/verify", bytes.NewReader(body)))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"Allow":true`) {
		t.Fatal("exactly 4KiB was rejected")
	}
	a.nodeClient.Store(&http.Client{Transport: admissionRoundTripper(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	w = httptest.NewRecorder()
	a.admissionRelay(w, httptest.NewRequest("POST", "/verify", bytes.NewReader(body)).WithContext(ctx))
	if w.Code != 503 || time.Since(started) > time.Second {
		t.Fatal("canceled verification was allowed or did not terminate promptly")
	}
}

func TestAdmissionRelayServerFailureCancelsAgentAndGracefulShutdownDoesNot(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "graceful shutdown", true: "listener failure"}[fail], func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var canceled atomic.Bool
			a := &Agent{}
			server, failures := a.startAdmissionRelay(listener, func() { canceled.Store(true) })
			defer server.Close()
			response, err := http.Get("http://" + listener.Addr().String() + "/verify")
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 405 {
				t.Fatal("private relay did not start serving")
			}
			if fail {
				listener.Close()
				select {
				case err := <-failures:
					if err == nil || !strings.Contains(err.Error(), "private admission relay failed") {
						t.Fatal("relay server failure was lost")
					}
				case <-time.After(time.Second):
					t.Fatal("relay server failure did not propagate")
				}
				deadline := time.Now().Add(time.Second)
				for !canceled.Load() && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if !canceled.Load() {
					t.Fatal("relay failure did not stop the Agent")
				}
			} else {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := server.Shutdown(ctx); err != nil {
					t.Fatal(err)
				}
				if canceled.Load() {
					t.Fatal("normal shutdown was reported as a fatal server failure")
				}
			}
		})
	}
}
