package controller

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AS214933/derpers-contorller/internal/config"
	"github.com/AS214933/derpers-contorller/internal/model"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestDevicesSnapshotFiltersAndExpires(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	keys := make([]string, 7)
	for i := range keys {
		keys[i] = key.NewNode().Public().String()
	}
	devs := []device{
		{NodeKey: keys[0], Authorized: true, Expires: now.Add(time.Hour).Format(time.RFC3339)},
		{NodeKey: keys[1], Authorized: true, Expires: now.Add(2 * time.Minute).Format(time.RFC3339)},
		{NodeKey: keys[2], Authorized: true, Expires: now.Format(time.RFC3339)},
		{NodeKey: keys[3], Authorized: true, External: true, ExpiryDisabled: true},
		{NodeKey: keys[4], Authorized: false, ExpiryDisabled: true},
		{NodeKey: keys[5], Authorized: true, ExpiryDisabled: true, Expires: "malformed-but-disabled"},
		{NodeKey: keys[6], Authorized: true, Expires: now.Add(-time.Second).Format(time.RFC3339)},
	}
	s, err := devicesSnapshot(devs, 42, now)
	if err != nil {
		t.Fatal(err)
	}
	if s.Revision != 42 || !s.Expires.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("snapshot metadata: %+v", s)
	}
	if len(s.Keys) != 3 {
		t.Fatalf("got %d authorized keys, want 3", len(s.Keys))
	}
	for _, i := range []int{0, 5} {
		if !s.Keys[keys[i]].Equal(s.Expires) {
			t.Errorf("key %d exceeded or shortened snapshot lifetime", i)
		}
	}
	if !s.Keys[keys[1]].Equal(now.Add(2 * time.Minute)) {
		t.Fatal("device expiry was not respected")
	}
	for _, i := range []int{2, 3, 4, 6} {
		if _, ok := s.Keys[keys[i]]; ok {
			t.Errorf("ineligible device %d was authorized", i)
		}
	}
}

func TestDevicesSnapshotRotationReplacesOldKey(t *testing.T) {
	now := time.Now()
	oldKey := key.NewNode().Public().String()
	newKey := key.NewNode().Public().String()
	old, err := devicesSnapshot([]device{{NodeKey: oldKey, Authorized: true, ExpiryDisabled: true}}, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	next, err := devicesSnapshot([]device{{NodeKey: newKey, Authorized: true, ExpiryDisabled: true}}, 1, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(old.Keys) != 1 || len(next.Keys) != 1 {
		t.Fatal("unexpected snapshot size")
	}
	if _, ok := next.Keys[oldKey]; ok {
		t.Fatal("rotated key retained")
	}
	if _, ok := next.Keys[newKey]; !ok {
		t.Fatal("new key missing")
	}
	empty, err := devicesSnapshot(nil, 2, now)
	if err != nil || len(empty.Keys) != 0 {
		t.Fatal("empty successful list must revoke all prior keys")
	}
}

func TestDevicesSnapshotRejectsMalformedAuthorizedData(t *testing.T) {
	for _, dev := range []device{
		{NodeKey: "bad-key", Authorized: true, ExpiryDisabled: true},
		{NodeKey: "nodekey:0000000000000000000000000000000000000000000000000000000000000000", Authorized: true, ExpiryDisabled: true},
		{NodeKey: key.NewNode().Public().String(), Authorized: true, Expires: "not-a-date"},
	} {
		if _, err := devicesSnapshot([]device{dev}, 1, time.Now()); err == nil {
			t.Errorf("accepted malformed authorized device %+v", dev)
		}
	}
	// Untrusted external and unauthorized records cannot invalidate an otherwise complete list.
	if _, err := devicesSnapshot([]device{{NodeKey: "invalid", Authorized: false}, {NodeKey: "invalid", External: true, Authorized: true}}, 1, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeNodeKey(t *testing.T) {
	want := key.NewNode().Public().String()
	got, err := normalizeKey(want[len("nodekey:"):])
	if err != nil || got != want {
		t.Fatalf("normalize raw key: %q %v", got, err)
	}
	for _, value := range []string{"", "nodekey:", "mkey:bad", "nodekey:" + "ffffffff"} {
		if _, err = normalizeKey(value); err == nil {
			t.Errorf("accepted invalid key %q", value)
		}
	}
}

func TestHeadscaleVerificationProtocol(t *testing.T) {
	tests := []struct {
		name, body       string
		status           int
		allow, wantError bool
	}{
		{"allow", `{"Allow":true}`, 200, true, false},
		{"deny", `{"Allow":false}`, 200, false, false},
		{"missing is never allowed", `{}`, 200, false, true},
		{"HTTP failure", `{"Allow":true}`, 503, false, true},
		{"malformed", `not-json`, 200, false, true},
		{"wrong type", `{"Allow":"true"}`, 200, false, true},
		{"trailing garbage", `{"Allow":true}garbage`, 200, false, true},
		{"second response", `{"Allow":true}{"Allow":false}`, 200, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/verify" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer test-token" {
					t.Error("missing configured bearer token")
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
			a := &App{Config: config.Config{AllowedCIDRs: []string{"127.0.0.1/32", "::1/128"}}}
			allow, err := a.verifyHeadscale(context.Background(), model.Network{URL: server.URL + "/verify"}, map[string]string{"ca_pem": ca, "bearer_token": "test-token"}, tailcfg.DERPAdmitClientRequest{NodePublic: key.NewNode().Public()})
			if (err != nil) != tc.wantError {
				t.Fatalf("error=%v, wantError=%v", err, tc.wantError)
			}
			if allow != tc.allow {
				t.Fatalf("allow=%v, want %v", allow, tc.allow)
			}
		})
	}
}

func TestHeadscaleRejectsRedirectAndDefaultPrivateAddress(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://8.8.8.8/verify", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	req := tailcfg.DERPAdmitClientRequest{NodePublic: key.NewNode().Public()}
	for _, cidrs := range [][]string{nil, {"127.0.0.1/32"}} {
		a := &App{Config: config.Config{AllowedCIDRs: cidrs}}
		allow, err := a.verifyHeadscale(context.Background(), model.Network{URL: server.URL + "/verify"}, map[string]string{"ca_pem": ca}, req)
		if err == nil || allow {
			t.Fatalf("private/redirect unexpectedly allowed with CIDRs %v", cidrs)
		}
	}
}
