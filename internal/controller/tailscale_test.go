package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AS214933/derpers-contorller/internal/model"
	"github.com/AS214933/derpers-contorller/internal/store"
	"golang.org/x/oauth2"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// Only a test transport rewrites the fixed official API host. Production URLs
// remain hard-coded; credentials are exchanged by the real oauth2 library.
type officialAPIFixtureTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (t officialAPIFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != "api.tailscale.com" {
		return nil, errors.New("test attempted a non-official upstream request")
	}
	rewritten := r.Clone(r.Context())
	u := *r.URL
	u.Scheme = t.target.Scheme
	u.Host = t.target.Host
	rewritten.URL = &u
	rewritten.Host = ""
	return t.base.RoundTrip(rewritten)
}

type officialAPIFixture struct {
	server                  *httptest.Server
	mu                      sync.Mutex
	devices                 []device
	status                  int
	raw                     string
	started                 chan struct{}
	release                 chan struct{}
	tokenCalls, deviceCalls atomic.Int32
}

func officialAPI(t *testing.T) *officialAPIFixture {
	t.Helper()
	f := &officialAPIFixture{status: 200, devices: []device{}}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/oauth/token":
			f.tokenCalls.Add(1)
			if r.Method != "POST" {
				t.Error("OAuth token request must use POST")
			}
			if err := r.ParseForm(); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			id, secret, ok := r.BasicAuth()
			if !ok || id != "test-client" || secret != "test-secret" {
				t.Error("clientcredentials did not authenticate with configured OAuth client")
				w.WriteHeader(401)
				return
			}
			if r.Form.Get("scope") != "devices:core:read" || r.Form.Get("grant_type") != "client_credentials" {
				t.Errorf("unexpected OAuth grant/scopes: %v", r.Form)
				w.WriteHeader(400)
				return
			}
			jsonResponse(w, 200, map[string]any{"access_token": "test-official-access-token", "token_type": "Bearer", "expires_in": 3600})
		case "/api/v2/tailnet/team.example.com/devices":
			f.deviceCalls.Add(1)
			if r.Method != "GET" || r.URL.Query().Get("fields") != "all" || r.Header.Get("Authorization") != "Bearer test-official-access-token" {
				t.Errorf("invalid official devices request: %s %s", r.Method, r.URL)
				w.WriteHeader(401)
				return
			}
			f.mu.Lock()
			devs := append([]device{}, f.devices...)
			status, raw, started, release := f.status, f.raw, f.started, f.release
			f.started = nil
			f.mu.Unlock()
			if started != nil {
				close(started)
			}
			if release != nil {
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			if raw != "" {
				_, _ = w.Write([]byte(raw))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"devices": devs})
		default:
			t.Errorf("unexpected official API endpoint %s", r.URL)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}
func (f *officialAPIFixture) context() context.Context {
	target, _ := url.Parse(f.server.URL)
	client := &http.Client{Transport: officialAPIFixtureTransport{target: target, base: f.server.Client().Transport}, Timeout: 5 * time.Second}
	return context.WithValue(context.Background(), oauth2.HTTPClient, client)
}
func (f *officialAPIFixture) set(devices []device, status int, raw string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.devices = devices
	f.status = status
	f.raw = raw
}

var officialTestCredentials = map[string]string{"client_id": "test-client", "client_secret": "test-secret"}

func TestFetchDevicesOfficialOAuthHTTPContract(t *testing.T) {
	fixture := officialAPI(t)
	pub := key.NewNode().Public().String()
	fixture.set([]device{{NodeKey: pub, Authorized: true, ExpiryDisabled: true}}, 200, "")
	devs, err := fetchDevices(fixture.context(), "team.example.com", officialTestCredentials)
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 1 || devs[0].NodeKey != pub || !devs[0].Authorized {
		t.Fatalf("unexpected official API data: %+v", devs)
	}
	if fixture.tokenCalls.Load() != 1 || fixture.deviceCalls.Load() != 1 {
		t.Fatalf("did not execute real OAuth plus devices calls: %d/%d", fixture.tokenCalls.Load(), fixture.deviceCalls.Load())
	}
	for _, credentials := range []map[string]string{nil, {"client_id": "test-client"}, {"client_secret": "test-secret"}} {
		if _, err := fetchDevices(fixture.context(), "team.example.com", credentials); err == nil {
			t.Fatal("missing OAuth credentials accepted")
		}
	}
}

func TestFetchDevicesRejectsIncompleteOrMalformedResponse(t *testing.T) {
	fixture := officialAPI(t)
	cases := []struct {
		name, raw string
		status    int
		valid     bool
	}{
		{"empty complete list", `{"devices":[]}`, 200, true},
		{"missing devices", `{}`, 200, false},
		{"null devices", `{"devices":null}`, 200, false},
		{"truncated list", `{"devices":[`, 200, false},
		{"invalid type", `{"devices":{}}`, 200, false},
		{"HTTP error", `{"devices":[]}`, 503, false},
		{"trailing garbage", `{"devices":[]}garbage`, 200, false},
		{"multiple values", `{"devices":[]}{"devices":[]}`, 200, false},
		{"over limit", `{"devices":[]}` + strings.Repeat(" ", 16<<20), 200, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture.set(nil, tc.status, tc.raw)
			_, err := fetchDevices(fixture.context(), "team.example.com", officialTestCredentials)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v want=%v err=%v", err == nil, tc.valid, err)
			}
		})
	}
}

func TestIntegrationOfficialOAuthSyncRotationDeletionAndFailureTTL(t *testing.T) {
	a := integrationApp(t)
	fixture := officialAPI(t)
	ctx := fixture.context()
	oldKey, newKey := key.NewNode().Public(), key.NewNode().Public()
	n := saveTestNetwork(t, a, model.Network{Name: "official-sync", Kind: "tailscale", Tailnet: "team.example.com"}, officialTestCredentials)
	fixture.set([]device{{NodeKey: oldKey.String(), Authorized: true, ExpiryDisabled: true}}, 200, "")
	if err := a.SyncNetwork(ctx, n.ID); err != nil {
		t.Fatal(err)
	}
	a.mu.RLock()
	first := a.snapshots[n.ID]
	a.mu.RUnlock()
	if _, ok := first.Keys[oldKey.String()]; !ok {
		t.Fatal("first official snapshot omitted authorized device")
	}
	fixture.set(nil, 503, `{"error":"API unavailable"}`)
	if err := a.SyncNetwork(ctx, n.ID); err == nil {
		t.Fatal("sync failure not reported")
	}
	a.mu.RLock()
	retained := a.snapshots[n.ID]
	a.mu.RUnlock()
	if !retained.Expires.Equal(first.Expires) || len(retained.Keys) != 1 {
		t.Fatal("failed sync extended TTL or replaced previously complete snapshot")
	}
	a.mu.Lock()
	retained.Expires = time.Now().Add(-time.Second)
	a.snapshots[n.ID] = retained
	a.mu.Unlock()
	allow, _, err := a.decide(context.Background(), tailcfg.DERPAdmitClientRequest{NodePublic: oldKey})
	if err != nil || allow {
		t.Fatal("expired snapshot retained authorization after sync failure")
	}
	fixture.set([]device{{NodeKey: newKey.String(), Authorized: true, ExpiryDisabled: true}}, 200, "")
	if err := a.SyncNetwork(ctx, n.ID); err != nil {
		t.Fatal(err)
	}
	allow, _, err = a.decide(context.Background(), tailcfg.DERPAdmitClientRequest{NodePublic: newKey})
	if err != nil || !allow {
		t.Fatalf("rotated key denied: %v", err)
	}
	allow, _, err = a.decide(context.Background(), tailcfg.DERPAdmitClientRequest{NodePublic: oldKey})
	if err != nil || allow {
		t.Fatal("old device key survived complete snapshot replacement")
	}
	fixture.set([]device{}, 200, "")
	if err := a.SyncNetwork(ctx, n.ID); err != nil {
		t.Fatal(err)
	}
	allow, _, err = a.decide(context.Background(), tailcfg.DERPAdmitClientRequest{NodePublic: newKey})
	if err != nil || allow {
		t.Fatal("deleted device survived a complete empty device list")
	}
	rec, err := a.Store.Get(ctx, "network", n.ID)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := store.Decode[model.Network](rec)
	if err != nil || stored.DeviceCount != 0 || stored.Health != "healthy" || stored.LastSuccess == nil {
		t.Fatalf("snapshot health metadata not persisted: %+v %v", stored, err)
	}
}

func TestIntegrationOfficialSourceDisabledDuringSync(t *testing.T) {
	a := integrationApp(t)
	fixture := officialAPI(t)
	pub := key.NewNode().Public()
	fixture.set([]device{{NodeKey: pub.String(), Authorized: true, ExpiryDisabled: true}}, 200, "")
	n := saveTestNetwork(t, a, model.Network{Name: "official-inflight", Kind: "tailscale", Tailnet: "team.example.com"}, officialTestCredentials)
	started, release := make(chan struct{}), make(chan struct{})
	fixture.mu.Lock()
	fixture.started = started
	fixture.release = release
	fixture.mu.Unlock()
	result := make(chan error, 1)
	go func() { result <- a.SyncNetwork(fixture.context(), n.ID) }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("official API call did not start")
	}
	if _, err := a.SetNetworkStatus(context.Background(), n.ID, "disabled", "admin"); err != nil {
		close(release)
		t.Fatal(err)
	}
	close(release)
	select {
	case err := <-result:
		if !errors.Is(err, store.ErrConflict) {
			t.Fatalf("in-flight disabled sync error=%v want conflict", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("sync did not finish")
	}
	a.mu.RLock()
	_, exists := a.snapshots[n.ID]
	a.mu.RUnlock()
	if exists {
		t.Fatal("disabled source wrote its in-flight snapshot back")
	}
	rec, err := a.Store.Get(context.Background(), "network", n.ID)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := store.Decode[model.Network](rec)
	if err != nil || stored.Status != "disabled" || stored.Revision != n.Revision+1 || stored.DeviceCount != 0 {
		t.Fatalf("stale sync changed disabled source: %+v %v", stored, err)
	}
}
