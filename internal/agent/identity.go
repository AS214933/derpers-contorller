package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AS214933/derpers-contorller/internal/model"
	"github.com/AS214933/derpers-contorller/internal/nodeauth"
)

type identity struct {
	NodeID      string
	Certificate tls.Certificate
	PrivatePEM  []byte
}
type persistedIdentity struct {
	NodeID      string `json:"node_id"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
	CA          string `json:"ca"`
}

func (a *Agent) loadIdentity() (bool, error) {
	if data, err := os.ReadFile(filepath.Join(a.cfg.StateDir, "identity.json")); err == nil {
		var persisted persistedIdentity
		if err := json.Unmarshal(data, &persisted); err != nil {
			return false, err
		}
		if persisted.NodeID == "" || (a.cfg.NodeID != "" && persisted.NodeID != a.cfg.NodeID) {
			return false, errors.New("persisted identity does not match NODE_ID")
		}
		pair, err := tls.X509KeyPair([]byte(persisted.Certificate), []byte(persisted.PrivateKey))
		if err != nil {
			return false, err
		}
		pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return false, err
		}
		if err := a.writeIdentityFiles(persisted); err != nil {
			return false, err
		}
		a.identity = identity{NodeID: persisted.NodeID, Certificate: pair, PrivatePEM: []byte(persisted.PrivateKey)}
		return true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	node, err := os.ReadFile(filepath.Join(a.cfg.StateDir, "node-id"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	key, err := os.ReadFile(filepath.Join(a.cfg.StateDir, "client.key"))
	if err != nil {
		return false, err
	}
	cert, err := os.ReadFile(filepath.Join(a.cfg.StateDir, "client.crt"))
	if err != nil {
		return false, err
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return false, err
	}
	pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false, err
	}
	nodeID := strings.TrimSpace(string(node))
	if nodeID == "" || (a.cfg.NodeID != "" && nodeID != a.cfg.NodeID) {
		return false, errors.New("persisted node identity does not match NODE_ID")
	}
	a.identity = identity{NodeID: nodeID, Certificate: pair, PrivatePEM: key}
	return true, nil
}

func (a *Agent) enroll(ctx context.Context) error {
	if a.cfg.EnrollmentToken == "" {
		return errors.New("no persisted identity; ENROLLMENT_TOKEN is required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	csr, err := createCSR(key)
	if err != nil {
		return err
	}
	var response model.EnrollmentResponse
	if err := a.request(ctx, a.bootstrap, http.MethodPost, "/api/v1/node-enroll", model.EnrollmentRequest{Token: a.cfg.EnrollmentToken, CSR: csr}, &response); err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	if err := a.saveIdentity(response, keyPEM); err != nil {
		return err
	}
	a.cfg.EnrollmentToken = ""
	return a.authenticatedClient()
}

func createCSR(key any) (string, error) {
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "derpers-node"}}, key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), nil
}

func (a *Agent) saveIdentity(response model.EnrollmentResponse, key []byte) error {
	if response.NodeID == "" || (a.cfg.NodeID != "" && response.NodeID != a.cfg.NodeID) || (a.identity.NodeID != "" && response.NodeID != a.identity.NodeID) {
		return errors.New("controller returned an unexpected node identity")
	}
	pair, err := tls.X509KeyPair([]byte(response.ClientCertificate), key)
	if err != nil {
		return fmt.Errorf("invalid enrollment certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(response.CACertificate)) {
		return errors.New("enrollment did not return a valid node CA")
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("verify node certificate: %w", err)
	}
	// Validate all material first, then write; write node-id last as enrollment commit.
	persisted := persistedIdentity{NodeID: response.NodeID, Certificate: response.ClientCertificate, PrivateKey: string(key), CA: response.CACertificate}
	encoded, err := json.Marshal(persisted)
	if err != nil {
		return err
	}
	// A single atomic file commits the key/certificate pair. Sidecar files are
	// repaired from it on restart, including interrupted key rotation/enrollment.
	if err := atomicWrite(filepath.Join(a.cfg.StateDir, "identity.json"), encoded, 0600); err != nil {
		return err
	}
	if err := a.writeIdentityFiles(persisted); err != nil {
		return err
	}
	pair.Leaf = leaf
	a.identity = identity{NodeID: response.NodeID, Certificate: pair, PrivatePEM: key}
	return nil
}

func (a *Agent) writeIdentityFiles(p persistedIdentity) error {
	for _, file := range []struct {
		name string
		body []byte
	}{{"client.key", []byte(p.PrivateKey)}, {"client.crt", []byte(p.Certificate)}, {"ca.crt", []byte(p.CA)}, {"node-id", []byte(p.NodeID + "\n")}} {
		if err := atomicWrite(filepath.Join(a.cfg.StateDir, file.name), file.body, 0600); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) renew(ctx context.Context) error {
	leaf := a.identity.Certificate.Leaf
	if leaf == nil || time.Until(leaf.NotAfter) > leaf.NotAfter.Sub(leaf.NotBefore)/3 {
		return nil
	}
	key, err := x509.ParsePKCS8PrivateKey(mustPEM(a.identity.PrivatePEM))
	if err != nil {
		return err
	}
	csr, err := createCSR(key)
	if err != nil {
		return err
	}
	var response model.EnrollmentResponse
	if err := a.request(ctx, a.client, http.MethodPost, "/node/v1/renew", map[string]string{"csr": csr}, &response); err != nil {
		return err
	}
	if err := a.saveIdentity(response, a.identity.PrivatePEM); err != nil {
		return err
	}
	if err := a.authenticatedClient(); err != nil {
		return err
	}
	return nil
}

func mustPEM(value []byte) []byte {
	b, _ := pem.Decode(value)
	if b == nil {
		return nil
	}
	return b.Bytes
}

func (a *Agent) tlsRoots() (*x509.CertPool, []byte, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	var bundle []byte
	for _, file := range []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", a.cfg.ControllerCAFile} {
		if file == "" {
			continue
		}
		data, readErr := os.ReadFile(file)
		if readErr != nil {
			if file == a.cfg.ControllerCAFile {
				return nil, nil, readErr
			}
			continue
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, nil, fmt.Errorf("CA file %s contains no certificates", file)
		}
		bundle = append(bundle, data...)
		bundle = append(bundle, '\n')
	}
	if a.applied != nil && a.applied.CAPEM != "" {
		if !roots.AppendCertsFromPEM([]byte(a.applied.CAPEM)) {
			return nil, nil, errors.New("node config ca_pem contains no certificates")
		}
		bundle = append(bundle, a.applied.CAPEM...)
		bundle = append(bundle, '\n')
	}
	return roots, bundle, nil
}

func (a *Agent) authenticatedClient() error {
	roots, _, err := a.tlsRoots()
	if err != nil {
		return err
	}
	signer, err := nodeauth.NewSigner(a.identity.Certificate)
	if err != nil {
		return err
	}
	if a.client != nil {
		a.client.CloseIdleConnections()
	}
	base := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, ForceAttemptHTTP2: true, MaxIdleConns: 10, IdleConnTimeout: 60 * time.Second}
	a.client = &http.Client{Timeout: 20 * time.Second, CheckRedirect: rejectRedirect, Transport: &nodeauth.Transport{Base: base, Signer: signer, Audience: strings.TrimRight(a.cfg.ControllerURL, "/")}}
	a.nodeClient.Store(a.client)
	return nil
}

func rejectRedirect(_ *http.Request, _ []*http.Request) error {
	return errors.New("controller redirects are not allowed")
}

func (a *Agent) request(ctx context.Context, client *http.Client, method, endpoint string, body, result any) error {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(a.cfg.ControllerURL, "/")+endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("controller %s %s returned HTTP %d", method, endpoint, resp.StatusCode)
	}
	if result != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(result); err != nil {
			return fmt.Errorf("decode %s: %w", endpoint, err)
		}
	}
	return nil
}
