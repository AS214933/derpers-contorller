package controller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/AS214933/derpers-contorller/internal/config"
	"github.com/AS214933/derpers-contorller/internal/model"
)

func TestAllowedIPSSRFPolicy(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"8.8.8.8", true}, {"2606:4700:4700::1111", true}, {"127.0.0.1", false}, {"::1", false},
		{"10.0.0.1", false}, {"172.16.0.1", false}, {"192.168.1.1", false}, {"fc00::1", false},
		{"100.100.100.200", false}, {"169.254.169.254", false}, {"fe80::1", false},
		{"224.0.0.1", false}, {"ff02::1", false}, {"0.0.0.0", false}, {"::", false}, {"::ffff:127.0.0.1", false},
	}
	for _, tc := range cases {
		if got := allowedIP(netip.MustParseAddr(tc.addr), nil); got != tc.want {
			t.Errorf("allowedIP(%s)=%v", tc.addr, got)
		}
	}
	if allowedIP(netip.Addr{}, nil) {
		t.Fatal("invalid address accepted")
	}
	allowed := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("127.0.0.1/32")}
	if !allowedIP(netip.MustParseAddr("10.20.3.4"), allowed) || !allowedIP(netip.MustParseAddr("127.0.0.1"), allowed) {
		t.Fatal("administrator approved private range rejected")
	}
	if allowedIP(netip.MustParseAddr("10.21.3.4"), allowed) {
		t.Fatal("neighboring private range permitted")
	}
	if allowedIP(netip.MustParseAddr("169.254.169.254"), []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}) {
		t.Fatal("metadata/link-local address must not be allowlisted")
	}
}

func TestHTTPSURLValidation(t *testing.T) {
	for _, raw := range []string{"https://headscale.example.com/verify", "https://headscale.example.com:8443/verify", "https://[2001:db8::1]/verify"} {
		if err := validHTTPS(raw); err != nil {
			t.Errorf("rejected %s: %v", raw, err)
		}
	}
	for _, raw := range []string{"http://example.com", "ftp://example.com", "https://", "//example.com", "https://user:secret@example.com/verify", "https://example.com/verify#token", "https://example.com:invalid/verify"} {
		if err := validHTTPS(raw); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}

func TestBodyRequiresExactlyOneCompleteJSONValue(t *testing.T) {
	cases := []struct {
		raw   string
		valid bool
	}{
		{`{"name":"safe"}`, true}, {"{\"name\":\"safe\"}\n \t", true}, {"", false}, {`{"name":`, false},
		{`{"name":"safe"}{"name":"second"}`, false}, {`{"name":"safe"}garbage`, false}, {`{"name":"safe"}{`, false},
		{`{"name":"safe"}` + strings.Repeat(" ", 1<<20), false},
	}
	for _, tc := range cases {
		r := httptest.NewRequest("POST", "/api/v1/test", strings.NewReader(tc.raw))
		var value struct {
			Name string `json:"name"`
		}
		err := body(r, &value)
		if (err == nil) != tc.valid {
			t.Errorf("body valid=%v, want=%v (length=%d, err=%v)", err == nil, tc.valid, len(tc.raw), err)
		}
	}
}

func TestOIDCOriginAndGroups(t *testing.T) {
	a := &App{Config: config.Config{PublicURL: "https://controller.example.com:8443/base"}}
	for _, tc := range []struct {
		origin string
		want   bool
	}{{"", true}, {"https://controller.example.com:8443", true}, {"http://controller.example.com:8443", false}, {"https://controller.example.com", false}, {"https://evil.example.com", false}, {"null", false}, {"https://controller.example.com:8443.evil.test", false}} {
		r := httptest.NewRequest("POST", "https://controller.example.com:8443/api/v1/settings", nil)
		r.Header.Set("Origin", tc.origin)
		if got := a.originOK(r); got != tc.want {
			t.Errorf("origin=%q accepted=%v", tc.origin, got)
		}
	}
	claims := map[string]any{"realm": map[string]any{"groups": []any{"users", 3, "admins"}}, "wrong": "admins"}
	if got := groups(claims, "realm.groups"); strings.Join(got, ",") != "users,admins" {
		t.Fatalf("nested groups: %v", got)
	}
	for _, path := range []string{"missing", "realm.missing", "wrong", "wrong.groups", ""} {
		if len(groups(claims, path)) != 0 {
			t.Errorf("non-array/missing group claim %s granted groups", path)
		}
	}
	if textClaim(true) != "" || textClaim("name") != "name" {
		t.Fatal("unexpected string claim coercion")
	}
}

func testCertificate(t *testing.T, host string, notBefore, notAfter time.Time) (string, string, *x509.Certificate) {
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &signer.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), leaf
}

func TestNodeCertificateSANKeyAndValidity(t *testing.T) {
	now := time.Now()
	cert, private, _ := testCertificate(t, "hk.derp.example.com", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err := validCertificate("hk.derp.example.com", cert, private); err != nil {
		t.Fatal(err)
	}
	if err := validCertificate("sg.derp.example.com", cert, private); err == nil {
		t.Fatal("wrong SAN accepted")
	}
	_, otherPrivate, _ := testCertificate(t, "hk.derp.example.com", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err := validCertificate("hk.derp.example.com", cert, otherPrivate); err == nil {
		t.Fatal("mismatched private key accepted")
	}
	for _, tc := range []struct {
		name       string
		start, end time.Time
	}{{"expired", now.Add(-2 * time.Hour), now.Add(-time.Hour)}, {"future", now.Add(time.Hour), now.Add(24 * time.Hour)}, {"insufficient lifetime", now.Add(-time.Hour), now.Add(30 * time.Minute)}} {
		t.Run(tc.name, func(t *testing.T) {
			c, k, _ := testCertificate(t, "hk.derp.example.com", tc.start, tc.end)
			if err := validCertificate("hk.derp.example.com", c, k); err == nil {
				t.Fatal("invalid validity accepted")
			}
		})
	}
	if err := validCertificate("hk.derp.example.com", "invalid PEM", private); err == nil {
		t.Fatal("invalid PEM accepted")
	}
}

func TestRenewalAtLastThirdOfLifetime(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cert := &x509.Certificate{NotBefore: start, NotAfter: start.Add(90 * 24 * time.Hour)}
	for _, tc := range []struct {
		at   time.Time
		want bool
	}{{start.Add(59 * 24 * time.Hour), false}, {start.Add(60 * 24 * time.Hour), true}, {start.Add(89 * 24 * time.Hour), true}, {start.Add(91 * 24 * time.Hour), true}} {
		if got := needsRenewal(cert, tc.at); got != tc.want {
			t.Errorf("renew at %s=%v want %v", tc.at, got, tc.want)
		}
	}
}

func TestDNSDomainAndAddressRules(t *testing.T) {
	for _, s := range []string{"example.com", "hk-01.derp.example.com", "xn--fiqs8s.example.com"} {
		if !domain(s) {
			t.Errorf("valid domain rejected: %s", s)
		}
	}
	for _, s := range []string{"localhost", ".example.com", "example..com", "-bad.example.com", "bad-.example.com", "UPPER.example.com", "bad_name.example.com", strings.Repeat("a", 64) + ".example.com"} {
		if domain(s) {
			t.Errorf("invalid domain accepted: %s", s)
		}
	}
	if !within("hk.derp.example.com", "derp.example.com") || !within("derp.example.com", "derp.example.com") || within("evilderp.example.com", "derp.example.com") || within("derp.example.com.evil", "derp.example.com") {
		t.Fatal("DNS suffix boundary incorrect")
	}
	records, err := desiredDNS(model.Node{Hostname: "hk.derp.example.com", IPv4: "203.0.113.7", IPv6: "2001:db8::7"})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Type != "A" || records[1].Type != "AAAA" || records[1].Value != "2001:db8::7" {
		t.Fatalf("unexpected records: %+v", records)
	}
	for _, node := range []model.Node{{}, {IPv4: "not-ip"}, {IPv4: "2001:db8::7"}, {IPv6: "203.0.113.7"}, {IPv4: "0.0.0.0"}, {IPv6: "::"}, {IPv4: "224.0.0.1"}} {
		if _, err := desiredDNS(node); err == nil {
			t.Errorf("invalid managed DNS addresses accepted: %+v", node)
		}
	}
}
