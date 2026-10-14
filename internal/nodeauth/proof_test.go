package nodeauth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Signer, *x509.CertPool, time.Time) {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	uri, _ := url.Parse("spiffe://derpers/node/node-1")
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return signer, roots, now
}

func request(t *testing.T, signer *Signer, now time.Time) *http.Request {
	t.Helper()
	r, err := http.NewRequest("POST", "https://control.example.test/node/v1/report?b=2&a=1", strings.NewReader(`{"revision":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if err = signer.signAt(r, []byte(`{"revision":1}`), "https://control.example.test/", now); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestProofBindsRequestWhileSurvivingTLSAndHostTermination(t *testing.T) {
	s, roots, now := fixture(t)
	r := request(t, s, now)
	r.URL.Scheme, r.URL.Host, r.Host = "http", "controller:8080", "arbitrary-proxy-host"
	r.Header.Set("X-Forwarded-Host", "attacker.example")
	proof, err := VerifyRequest(r, []byte(`{"revision":1}`), roots, "https://CONTROL.example.test", now)
	if err != nil || proof.NodeID != "node-1" || !proof.ExpiresAt.Equal(now.Add(Lifetime+ClockSkew)) {
		t.Fatalf("HTTP origin rejected authentic request: %+v %v", proof, err)
	}
	for _, kind := range []string{"body", "method", "path", "query", "audience", "untrusted-ca", "missing", "duplicate", "combined", "encoding", "multiple-encoding", "expired-cert"} {
		t.Run(kind, func(t *testing.T) {
			r := request(t, s, now)
			body := []byte(`{"revision":1}`)
			audience := "https://control.example.test"
			pool := roots
			at := now
			switch kind {
			case "body":
				body = []byte(`{ "revision":1}`)
			case "method":
				r.Method = "GET"
			case "path":
				r.URL.Path = "/node/v1/config"
			case "query":
				r.URL.RawQuery = "a=1&b=2"
			case "audience":
				audience = "https://another.example.test"
			case "untrusted-ca":
				pool = x509.NewCertPool()
			case "missing":
				r.Header.Del("Authorization")
			case "duplicate":
				r.Header.Add("Authorization", r.Header.Get("Authorization"))
			case "combined":
				r.Header.Set("Authorization", r.Header.Get("Authorization")+", "+r.Header.Get("Authorization"))
			case "encoding":
				r.Header.Set("Content-Encoding", "gzip")
			case "multiple-encoding":
				r.Header.Add("Content-Encoding", "identity")
				r.Header.Add("Content-Encoding", "identity")
			case "expired-cert":
				at = now.Add(2 * time.Hour)
			}
			if _, err := VerifyRequest(r, body, pool, audience, at); err == nil {
				t.Fatal("modified/untrusted request accepted")
			}
		})
	}
}

func TestProofRejectsAmbiguousClaimsAlgorithmsAndTimeWindows(t *testing.T) {
	s, roots, now := fixture(t)
	for _, kind := range []string{"expired", "future", "long-life", "zero-life", "short-nonce", "subject", "float-time", "duplicate", "case-alias", "unknown", "header-case", "header-duplicate", "none", "hmac", "remote-key", "critical"} {
		t.Run(kind, func(t *testing.T) {
			r := request(t, s, now)
			original := strings.TrimPrefix(r.Header.Get("Authorization"), Scheme+" ")
			parts := strings.Split(original, ".")
			payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
			var c map[string]any
			_ = json.Unmarshal(payload, &c)
			switch kind {
			case "expired":
				c["iat"] = now.Add(-76 * time.Second).Unix()
				c["exp"] = now.Add(-16 * time.Second).Unix()
			case "future":
				c["iat"] = now.Add(16 * time.Second).Unix()
				c["exp"] = now.Add(76 * time.Second).Unix()
			case "long-life":
				c["exp"] = now.Add(61 * time.Second).Unix()
			case "zero-life":
				c["exp"] = now.Unix()
			case "short-nonce":
				c["jti"] = "a"
			case "subject":
				c["sub"] = "other-node"
			case "float-time":
				c["iat"] = float64(now.Unix()) + 0.5
			case "unknown":
				c["iss"] = "unexpected-token-type"
			}
			payload, _ = json.Marshal(c)
			if kind == "duplicate" {
				payload = append([]byte(`{"sub":"another",`), payload[1:]...)
			}
			if kind == "case-alias" {
				payload = bytes.Replace(payload, []byte(`"exp":`), []byte(`"EXP":`), 1)
			}
			signed, err := s.signer.Sign(payload)
			if err != nil {
				t.Fatal(err)
			}
			compact, err := signed.CompactSerialize()
			if err != nil {
				t.Fatal(err)
			}
			parts = strings.Split(compact, ".")
			hdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
			switch kind {
			case "header-case":
				hdr = bytes.Replace(hdr, []byte(`"alg":`), []byte(`"ALG":`), 1)
			case "header-duplicate":
				hdr = append([]byte(`{"alg":"ES256",`), hdr[1:]...)
			case "none":
				hdr = bytes.Replace(hdr, []byte(`"ES256"`), []byte(`"none"`), 1)
			case "hmac":
				hdr = bytes.Replace(hdr, []byte(`"ES256"`), []byte(`"HS256"`), 1)
			case "remote-key":
				hdr = append([]byte(`{"jku":"https://attacker.invalid/keys",`), hdr[1:]...)
			case "critical":
				hdr = append([]byte(`{"crit":["b64"],"b64":false,`), hdr[1:]...)
			}
			parts[0] = base64.RawURLEncoding.EncodeToString(hdr)
			r.Header.Set("Authorization", Scheme+" "+strings.Join(parts, "."))
			if _, err := VerifyRequest(r, []byte(`{"revision":1}`), roots, "https://control.example.test", now); err == nil {
				t.Fatal("invalid proof accepted")
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTransportSignsFreshRawRequestsAndBoundsBodies(t *testing.T) {
	s, roots, _ := fixture(t)
	seen := map[string]bool{}
	transport := &Transport{Signer: s, Audience: "https://control.example.test", Base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		proof, err := VerifyRequest(r, body, roots, "https://control.example.test", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if seen[proof.ID] {
			t.Fatal("caller retry reused a proof")
		}
		seen[proof.ID] = true
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
	})}
	for range 2 {
		r, _ := http.NewRequest("POST", "https://control.example.test/node/v1/report", strings.NewReader(`{"revision":1}`))
		res, err := transport.RoundTrip(r)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if r.Header.Get("Authorization") != "" {
			t.Fatal("transport mutated caller's headers")
		}
	}
	r, _ := http.NewRequest("POST", "https://control.example.test/node/v1/report", strings.NewReader(strings.Repeat("x", MaxBodySize+1)))
	if _, err := transport.RoundTrip(r); err == nil {
		t.Fatal("oversized request accepted")
	}
}
