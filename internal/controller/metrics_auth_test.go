package controller

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AS214933/derpers-contorller/internal/config"
)

func TestMetricsAuthenticationIgnoresProxyAndTransportClaims(t *testing.T) {
	for _, tc := range []struct {
		name, token, remote string
		authorization       []string
		forwarded           bool
		tls                 bool
		want                bool
	}{
		{name: "remote HTTP has no implicit trust", remote: "192.0.2.10:1234"},
		{name: "remote HTTPS has no implicit trust", remote: "192.0.2.10:1234", tls: true},
		{name: "forged loopback and certificate headers", remote: "192.0.2.10:1234", forwarded: true},
		{name: "unset token denies actual IPv4 loopback", remote: "127.0.0.1:1234"},
		{name: "unset token denies actual IPv6 loopback", remote: "[::1]:1234"},
		{name: "unset token denies mapped actual loopback", remote: "[::ffff:127.0.0.1]:1234"},
		{name: "loopback hostname is not a peer IP", remote: "localhost:1234"},
		{name: "loopback without port is not a TCP peer", remote: "127.0.0.1"},
		{name: "malformed loopback port", remote: "127.0.0.1:invalid"},
		{name: "configured token requires credential on loopback", token: "scrape-secret", remote: "127.0.0.1:1234"},
		{name: "valid exact bearer", token: "scrape-secret", remote: "192.0.2.10:1234", authorization: []string{"Bearer scrape-secret"}, want: true},
		{name: "wrong bearer", token: "scrape-secret", remote: "192.0.2.10:1234", authorization: []string{"Bearer scrape-secreu"}},
		{name: "empty bearer", token: "scrape-secret", remote: "192.0.2.10:1234", authorization: []string{"Bearer "}},
		{name: "unset token does not accept arbitrary bearer", remote: "192.0.2.10:1234", authorization: []string{"Bearer "}},
		{name: "lowercase scheme is not the exact credential", token: "scrape-secret", remote: "192.0.2.10:1234", authorization: []string{"bearer scrape-secret"}},
		{name: "extra whitespace rejected", token: "scrape-secret", remote: "192.0.2.10:1234", authorization: []string{"Bearer  scrape-secret"}},
		{name: "trailing whitespace rejected", token: "scrape-secret", remote: "192.0.2.10:1234", authorization: []string{"Bearer scrape-secret "}},
		{name: "duplicate header rejected", token: "scrape-secret", remote: "192.0.2.10:1234", authorization: []string{"Bearer scrape-secret", "Bearer scrape-secret"}},
		{name: "combined header rejected", token: "scrape-secret", remote: "192.0.2.10:1234", authorization: []string{"Bearer scrape-secret, Bearer scrape-secret"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &App{Config: config.Config{MetricsToken: tc.token}}
			r := httptest.NewRequest(http.MethodGet, "http://controller/metrics", nil)
			r.RemoteAddr = tc.remote
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			for _, value := range tc.authorization {
				r.Header.Add("Authorization", value)
			}
			if tc.forwarded {
				r.Header.Set("Forwarded", "for=127.0.0.1;proto=https")
				r.Header.Set("X-Forwarded-For", "127.0.0.1")
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("X-Forwarded-Client-Cert", "spiffe://derpers/node/trusted")
				r.Header.Set("X-SSL-Client-Verify", "SUCCESS")
			}
			if got := a.metricsAuthorized(r); got != tc.want {
				t.Fatalf("metrics authorization=%v, want %v", got, tc.want)
			}
			if !tc.want {
				w := httptest.NewRecorder()
				a.metrics(w, r)
				if w.Code != http.StatusForbidden || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("denial status=%d cache=%q", w.Code, w.Header().Get("Cache-Control"))
				}
			}
		})
	}
}
