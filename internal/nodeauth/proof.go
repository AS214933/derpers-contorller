// Package nodeauth authenticates node HTTP requests independently of the TLS
// connection, allowing a trusted reverse proxy to terminate public HTTPS.
package nodeauth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	Scheme               = "DerpersProof"
	ProofType            = "derpers-node-request+jwt"
	MaxBodySize          = 1 << 20
	MaxAuthorizationSize = 8 << 10
	Lifetime             = 60 * time.Second
	ClockSkew            = 15 * time.Second
)

var ErrInvalidProof = errors.New("invalid node request proof")
var nodeIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type claims struct {
	Audience string `json:"aud"`
	Subject  string `json:"sub"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
	ID       string `json:"jti"`
	Method   string `json:"htm"`
	Target   string `json:"htu"`
	BodyHash string `json:"body_sha256"`
}

// Proof contains only verified data. ExpiresAt includes the accepted clock skew
// so replay records remain present for the entire verification window.
type Proof struct {
	Certificate *x509.Certificate
	NodeID      string
	ID          string
	ExpiresAt   time.Time
}

// Signer holds an immutable identity snapshot and can sign concurrent requests.
type Signer struct {
	signer      jose.Signer
	certificate *x509.Certificate
	nodeID      string
}

func NodeID(c *x509.Certificate) (string, error) {
	if c == nil || len(c.URIs) != 1 {
		return "", ErrInvalidProof
	}
	u := c.URIs[0]
	if u.Scheme != "spiffe" || u.Host != "derpers" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || !strings.HasPrefix(u.Path, "/node/") {
		return "", ErrInvalidProof
	}
	id := strings.TrimPrefix(u.Path, "/node/")
	if !nodeIDPattern.MatchString(id) {
		return "", ErrInvalidProof
	}
	return id, nil
}

func Audience(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", ErrInvalidProof
	}
	return "https://" + strings.ToLower(u.Host), nil
}

func NewSigner(pair tls.Certificate) (*Signer, error) {
	if len(pair.Certificate) < 1 || len(pair.Certificate) > 4 {
		return nil, ErrInvalidProof
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, ErrInvalidProof
	}
	id, err := NodeID(leaf)
	if err != nil {
		return nil, err
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, ErrInvalidProof
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil || !bytes.Equal(public, leaf.RawSubjectPublicKeyInfo) {
		return nil, ErrInvalidProof
	}
	chain := make([]string, len(pair.Certificate))
	for i, der := range pair.Certificate {
		chain[i] = base64.StdEncoding.EncodeToString(der)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType(jose.ContentType(ProofType)).WithHeader("x5c", chain))
	if err != nil {
		return nil, err
	}
	return &Signer{signer: signer, certificate: leaf, nodeID: id}, nil
}

func bodyHash(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }

func (s *Signer) Sign(r *http.Request, body []byte, audience string) error {
	return s.signAt(r, body, audience, time.Now())
}

func (s *Signer) signAt(r *http.Request, body []byte, audience string, now time.Time) error {
	if s == nil || r == nil || r.URL == nil || len(body) > MaxBodySize || now.Before(s.certificate.NotBefore) || !now.Before(s.certificate.NotAfter) {
		return ErrInvalidProof
	}
	aud, err := Audience(audience)
	if err != nil {
		return err
	}
	if r.Method == "" || len(r.URL.RequestURI()) > 2048 || r.URL.Fragment != "" {
		return ErrInvalidProof
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	c := claims{Audience: aud, Subject: s.nodeID, IssuedAt: now.Unix(), Expires: now.Add(Lifetime).Unix(), ID: base64.RawURLEncoding.EncodeToString(nonce[:]), Method: r.Method, Target: r.URL.RequestURI(), BodyHash: bodyHash(body)}
	payload, err := json.Marshal(c)
	if err != nil {
		return err
	}
	signed, err := s.signer.Sign(payload)
	if err != nil {
		return err
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		return err
	}
	value := Scheme + " " + compact
	if len(value) > MaxAuthorizationSize {
		return ErrInvalidProof
	}
	r.Header.Set("Authorization", value)
	return nil
}

// strictObject rejects duplicate fields and unknown fields before decoding into
// a typed structure. Request proofs deliberately have a small closed schema.
func strictObject(data []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return ErrInvalidProof
	}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return ErrInvalidProof
		}
		// JSON/JWT member names are case-sensitive. encoding/json otherwise
		// accepts case aliases such as EXP and exp as the same struct field.
		switch name {
		case "alg", "typ", "x5c", "aud", "sub", "iat", "exp", "jti", "htm", "htu", "body_sha256":
		default:
			return ErrInvalidProof
		}
		seen[name] = true
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return ErrInvalidProof
		}
	}
	if t, err = d.Token(); err != nil || t != json.Delim('}') {
		return ErrInvalidProof
	}
	if _, err = d.Token(); err != io.EOF {
		return ErrInvalidProof
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil {
		return ErrInvalidProof
	}
	return nil
}

func VerifyRequest(r *http.Request, body []byte, roots *x509.CertPool, audience string, now time.Time) (*Proof, error) {
	if r == nil || r.URL == nil || roots == nil || len(body) > MaxBodySize || len(r.Header.Values("Authorization")) != 1 || len(r.Header.Values("Content-Encoding")) > 1 || (r.Header.Get("Content-Encoding") != "" && r.Header.Get("Content-Encoding") != "identity") {
		return nil, ErrInvalidProof
	}
	value := r.Header.Get("Authorization")
	if len(value) > MaxAuthorizationSize || !strings.HasPrefix(value, Scheme+" ") {
		return nil, ErrInvalidProof
	}
	compact := strings.TrimPrefix(value, Scheme+" ")
	parts := strings.Split(compact, ".")
	if len(parts) != 3 || strings.ContainsAny(compact, " \t\r\n") {
		return nil, ErrInvalidProof
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidProof
	}
	var header struct {
		Algorithm    string   `json:"alg"`
		Type         string   `json:"typ"`
		Certificates []string `json:"x5c"`
	}
	if strictObject(headerBytes, &header) != nil || header.Algorithm != string(jose.ES256) || header.Type != ProofType || len(header.Certificates) < 1 || len(header.Certificates) > 4 {
		return nil, ErrInvalidProof
	}
	intermediates := x509.NewCertPool()
	var leaf *x509.Certificate
	for i, encoded := range header.Certificates {
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, ErrInvalidProof
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, ErrInvalidProof
		}
		if i == 0 {
			leaf = cert
		} else {
			intermediates.AddCert(cert)
		}
	}
	public, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() || leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, ErrInvalidProof
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, ErrInvalidProof
	}
	id, err := NodeID(leaf)
	if err != nil {
		return nil, err
	}
	signed, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(signed.Signatures) != 1 || len(signed.Signatures[0].Signature) != 64 {
		return nil, ErrInvalidProof
	}
	payload, err := signed.Verify(public)
	if err != nil {
		return nil, ErrInvalidProof
	}
	var c claims
	if strictObject(payload, &c) != nil {
		return nil, ErrInvalidProof
	}
	aud, err := Audience(audience)
	if err != nil || c.Audience != aud || c.Subject != id || c.Method != r.Method || c.Target != r.URL.RequestURI() || c.BodyHash != bodyHash(body) {
		return nil, ErrInvalidProof
	}
	seconds, skew, lifetime := now.Unix(), int64(ClockSkew/time.Second), int64(Lifetime/time.Second)
	if c.IssuedAt <= 0 || c.IssuedAt > seconds+skew || c.IssuedAt < seconds-lifetime-skew || c.Expires <= c.IssuedAt || c.Expires > c.IssuedAt+lifetime || seconds > c.Expires+skew {
		return nil, ErrInvalidProof
	}
	nonce, err := base64.RawURLEncoding.DecodeString(c.ID)
	if err != nil || len(nonce) != 16 || base64.RawURLEncoding.EncodeToString(nonce) != c.ID {
		return nil, ErrInvalidProof
	}
	return &Proof{Certificate: leaf, NodeID: id, ID: c.ID, ExpiresAt: time.Unix(c.Expires+skew, 0)}, nil
}

// Transport signs each call using the final request target and raw body. A
// caller retry invokes RoundTrip again and receives a fresh one-use proof.
type Transport struct {
	Base     http.RoundTripper
	Signer   *Signer
	Audience string
}

func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	copy := r.Clone(r.Context())
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, MaxBodySize+1))
		_ = r.Body.Close()
		if err != nil {
			return nil, err
		}
		if len(body) > MaxBodySize {
			return nil, errors.New("node request exceeds its body limit")
		}
		copy.Body = io.NopCloser(bytes.NewReader(body))
		copy.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}
	if err := t.Signer.Sign(copy, body, t.Audience); err != nil {
		return nil, err
	}
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(copy)
}

func (t *Transport) CloseIdleConnections() {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	if closer, ok := base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
