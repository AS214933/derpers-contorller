package controller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AS214933/derpers-contorller/internal/config"
)

func TestNodeIssuerRejectsMismatchedCertificateAndPrivateKey(t *testing.T) {
	issuer := &App{}
	signer := identityCA(t, issuer)
	marshalKey := func(key *ecdsa.PrivateKey) []byte {
		t.Helper()
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := os.WriteFile(certFile, issuer.CAPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, marshalKey(signer), 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Config{NodeCACertFile: certFile, NodeCAKeyFile: keyFile}
	loaded, err := New(c, nil)
	if err != nil || loaded.CA == nil || loaded.Signer == nil {
		t.Fatalf("matching issuer failed: %v", err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, marshalKey(other), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = New(c, nil); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("mismatched issuer was accepted: %v", err)
	}

	leaf, leafPrivate, _ := testCertificate(t, "relay.example.test", time.Now().Add(-time.Hour), time.Now().Add(time.Hour*24))
	if err := os.WriteFile(certFile, []byte(leaf), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte(leafPrivate), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = New(c, nil); err == nil || !strings.Contains(err.Error(), "must be a CA") {
		t.Fatalf("non-CA issuer was accepted: %v", err)
	}
}
