package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/AS214933/derpers-contorller/internal/model"
	"github.com/AS214933/derpers-contorller/internal/store"
	"golang.org/x/oauth2/clientcredentials"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type device struct {
	NodeKey        string `json:"nodeKey"`
	Authorized     bool   `json:"authorized"`
	External       bool   `json:"isExternal"`
	ExpiryDisabled bool   `json:"keyExpiryDisabled"`
	Expires        string `json:"expires"`
}

func normalizeHeadscale(raw string) (string, error) {
	if e := validHTTPS(raw); e != nil {
		return "", e
	}
	u, _ := url.Parse(raw)
	if u.RawQuery != "" {
		return "", errors.New("Headscale URL must not include a query")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	if !strings.HasSuffix(u.Path, "/verify") {
		u.Path += "/verify"
	}
	return u.String(), nil
}

func normalizeKey(s string) (string, error) {
	if !strings.HasPrefix(s, "nodekey:") {
		s = "nodekey:" + s
	}
	var k key.NodePublic
	if e := k.UnmarshalText([]byte(s)); e != nil || k.IsZero() {
		return "", errors.New("invalid node public key")
	}
	return k.String(), nil
}
func devicesSnapshot(devs []device, revision int64, now time.Time) (snapshot, error) {
	s := snapshot{Revision: revision, Expires: now.Add(15 * time.Minute), Keys: map[string]time.Time{}}
	for _, d := range devs {
		if d.External || !d.Authorized {
			continue
		}
		k, e := normalizeKey(d.NodeKey)
		if e != nil {
			return s, errors.New("device response contains an invalid node key")
		}
		until := s.Expires
		if !d.ExpiryDisabled {
			t, e := time.Parse(time.RFC3339, d.Expires)
			if e != nil {
				return s, errors.New("device response contains an invalid expiry")
			}
			if !t.After(now) {
				continue
			}
			if t.Before(until) {
				until = t
			}
		}
		s.Keys[k] = until
	}
	return s, nil
}
func (a *App) syncAll(ctx context.Context) {
	rs, e := a.Store.List(ctx, "network", "")
	if e != nil {
		return
	}
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, rec := range rs {
		n, e := store.Decode[model.Network](rec)
		if e != nil || n.Status != "approved" || n.Kind != "tailscale" {
			continue
		}
		wg.Add(1)
		go func(n model.Network) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			_ = a.SyncNetwork(ctx, n.ID)
		}(n)
	}
	wg.Wait()
}
func (a *App) SyncNetwork(ctx context.Context, id string) error {
	return a.syncNetwork(ctx, id, true)
}
func (a *App) syncNetwork(ctx context.Context, id string, force bool) error {
	lock, _ := a.syncLocks.LoadOrStore(id, &sync.Mutex{})
	m := lock.(*sync.Mutex)
	m.Lock()
	defer m.Unlock()
	rec, e := a.Store.Get(ctx, "network", id)
	if e != nil {
		return e
	}
	n, e := store.Decode[model.Network](rec)
	if e != nil {
		return e
	}
	if n.Status != "approved" || n.Kind != "tailscale" {
		return errors.New("source is not an approved official tailnet")
	}
	if !force {
		a.mu.RLock()
		snap, ok := a.snapshots[id]
		a.mu.RUnlock()
		if ok && snap.Revision == n.Revision && time.Now().Before(snap.Expires) {
			return nil
		}
	}
	sec, e := a.Store.Secrets(rec)
	if e != nil {
		return e
	}
	devs, e := fetchDevices(ctx, n.Tailnet, sec)
	if e != nil {
		a.syncFailures.Add(1)
		_ = a.Store.Patch(ctx, "network", id, n.Revision, map[string]any{"health": "degraded", "last_error": e.Error()})
		a.event(ctx, "sync_failed", "system", "", id, e.Error())
		return e
	}
	snap, e := devicesSnapshot(devs, n.Revision, time.Now())
	if e != nil {
		a.syncFailures.Add(1)
		_ = a.Store.Patch(ctx, "network", id, n.Revision, map[string]any{"health": "degraded", "last_error": e.Error()})
		a.event(ctx, "sync_failed", "system", "", id, e.Error())
		return e
	}
	current, e := a.Store.Get(ctx, "network", id)
	if e != nil || current.Revision != n.Revision {
		return store.ErrConflict
	}
	latest, e := store.Decode[model.Network](current)
	if e != nil || latest.Status != "approved" {
		return store.ErrConflict
	}
	a.mu.Lock()
	a.snapshots[id] = snap
	a.mu.Unlock()
	now := time.Now().UTC()
	e = a.Store.Patch(ctx, "network", id, n.Revision, map[string]any{"health": "healthy", "last_error": "", "last_success": now, "device_count": len(snap.Keys)})
	if e != nil {
		a.invalidate(id)
		return e
	}
	a.event(ctx, "sync_success", "system", "", id, fmt.Sprintf("%d authorized node keys", len(snap.Keys)))
	return nil
}
func fetchDevices(ctx context.Context, tailnet string, sec map[string]string) ([]device, error) {
	if sec["client_id"] == "" || sec["client_secret"] == "" || tailnet == "" {
		return nil, errors.New("tailnet and OAuth client credentials are required")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cfg := clientcredentials.Config{ClientID: sec["client_id"], ClientSecret: sec["client_secret"], TokenURL: "https://api.tailscale.com/api/v2/oauth/token", Scopes: []string{"devices:core:read"}}
	client := cfg.Client(ctx)
	req, e := http.NewRequestWithContext(ctx, "GET", "https://api.tailscale.com/api/v2/tailnet/"+url.PathEscape(tailnet)+"/devices?fields=all", nil)
	if e != nil {
		return nil, e
	}
	res, e := client.Do(req)
	if e != nil {
		return nil, errors.New("Tailscale OAuth or API request failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("Tailscale devices API returned HTTP %d", res.StatusCode)
	}
	var result struct {
		Devices *[]device `json:"devices"`
	}
	payload, readErr := io.ReadAll(io.LimitReader(res.Body, (16<<20)+1))
	if readErr != nil || len(payload) > 16<<20 {
		return nil, errors.New("Tailscale devices response exceeds its limit")
	}
	if e = json.Unmarshal(payload, &result); e != nil || result.Devices == nil {
		return nil, errors.New("invalid or incomplete Tailscale device response")
	}
	return *result.Devices, nil
}
func (a *App) verifyHeadscale(ctx context.Context, n model.Network, sec map[string]string, req tailcfg.DERPAdmitClientRequest) (bool, error) {
	if e := validHTTPS(n.URL); e != nil {
		return false, e
	}
	b, _ := json.Marshal(req)
	r, e := http.NewRequestWithContext(ctx, "POST", n.URL, bytes.NewReader(b))
	if e != nil {
		return false, e
	}
	r.Header.Set("Content-Type", "application/json")
	if sec["bearer_token"] != "" {
		r.Header.Set("Authorization", "Bearer "+sec["bearer_token"])
	}
	client := a.privateClient(sec["ca_pem"], 2*time.Second)
	defer client.CloseIdleConnections()
	res, e := client.Do(r)
	if e != nil {
		return false, errors.New("Headscale verification request failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return false, fmt.Errorf("Headscale verification returned HTTP %d", res.StatusCode)
	}
	var result struct{ Allow *bool }
	payload, readErr := io.ReadAll(io.LimitReader(res.Body, 4097))
	if readErr != nil || len(payload) > 4096 {
		return false, errors.New("Headscale verification response exceeds its limit")
	}
	if e = json.Unmarshal(payload, &result); e != nil || result.Allow == nil {
		return false, errors.New("Headscale verification returned invalid JSON")
	}
	return *result.Allow, nil
}
func (a *App) TestNetwork(ctx context.Context, n model.Network, sec map[string]string) error {
	if n.Kind == "tailscale" {
		devs, e := fetchDevices(ctx, n.Tailnet, sec)
		if e != nil {
			return e
		}
		_, e = devicesSnapshot(devs, 1, time.Now())
		return e
	}
	if n.Kind != "headscale" {
		return errors.New("network kind must be tailscale or headscale")
	}
	pub := key.NewNode().Public()
	allow, e := a.verifyHeadscale(ctx, n, sec, tailcfg.DERPAdmitClientRequest{NodePublic: pub})
	if e != nil {
		return e
	}
	if allow {
		return errors.New("Headscale allowed a randomly generated unknown key")
	}
	return nil
}
func (a *App) sourceStillActive(ctx context.Context, n model.Network) bool {
	r, e := a.Store.Get(ctx, "network", n.ID)
	if e != nil || r.Revision != n.Revision {
		return false
	}
	v, e := store.Decode[model.Network](r)
	return e == nil && v.Status == "approved"
}
func (a *App) decide(ctx context.Context, req tailcfg.DERPAdmitClientRequest) (bool, string, error) {
	rows, e := a.Store.List(ctx, "network", "")
	if e != nil {
		return false, "", e
	}
	active := []model.Network{}
	secrets := map[string]map[string]string{}
	for _, r := range rows {
		n, e := store.Decode[model.Network](r)
		if e != nil {
			return false, "", e
		}
		if n.Status != "approved" {
			continue
		}
		if n.Kind == "tailscale" {
			a.mu.RLock()
			snap, ok := a.snapshots[n.ID]
			until := snap.Keys[req.NodePublic.String()]
			a.mu.RUnlock()
			if ok && snap.Revision == n.Revision && time.Now().Before(snap.Expires) && time.Now().Before(until) && a.sourceStillActive(ctx, n) {
				return true, n.ID, nil
			}
		} else if n.Kind == "headscale" {
			sec, e := a.Store.Secrets(r)
			if e != nil {
				return false, "", e
			}
			active = append(active, n)
			secrets[n.ID] = sec
		}
	}
	if len(active) == 0 {
		return false, "", nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type answer struct {
		n     model.Network
		allow bool
		err   error
	}
	ch := make(chan answer, len(active))
	sem := make(chan struct{}, 16)
	for _, n := range active {
		go func(n model.Network) {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				ch <- answer{n: n, err: ctx.Err()}
				return
			}
			yes, e := a.verifyHeadscale(ctx, n, secrets[n.ID], req)
			ch <- answer{n: n, allow: yes, err: e}
		}(n)
	}
	var hadError bool
	for range active {
		select {
		case <-ctx.Done():
			return false, "", ctx.Err()
		case r := <-ch:
			if r.err != nil {
				hadError = true
				_ = a.Store.Patch(ctx, "network", r.n.ID, r.n.Revision, map[string]any{"health": "degraded", "last_error": r.err.Error()})
				continue
			}
			_ = a.Store.Patch(ctx, "network", r.n.ID, r.n.Revision, map[string]any{"health": "healthy", "last_error": "", "last_success": time.Now().UTC()})
			if r.allow && a.sourceStillActive(ctx, r.n) {
				return true, r.n.ID, nil
			}
		}
	}
	if hadError {
		return false, "", errors.New("authorization sources unavailable")
	}
	return false, "", nil
}
func (a *App) admission(w http.ResponseWriter, r *http.Request) {
	node, e := a.NodeIdentity(r)
	if e != nil {
		failure(w, 403, "verified active node identity required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var req tailcfg.DERPAdmitClientRequest
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if e = body(r, &req); e != nil || req.NodePublic.IsZero() {
		jsonResponse(w, 400, tailcfg.DERPAdmitClientResponse{Allow: false})
		return
	}
	allow, source, e := a.decide(ctx, req)
	status := 200
	detail := "unknown node public key"
	if e != nil {
		a.failures.Add(1)
		status = 503
		detail = "authorization could not be verified"
	}
	if allow {
		detail = "authorized by trusted source"
	}
	auditCtx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if x := a.Store.Audit(auditCtx, model.Audit{Event: "admission", Actor: "node", NodeID: node.ID, NetworkID: source, NodePublic: req.NodePublic.String(), Allow: &allow, Detail: detail}); x != nil {
		allow = false
		if status != 503 {
			a.failures.Add(1)
		}
		status = 503
	}
	if allow {
		a.allowed.Add(1)
	} else {
		a.denied.Add(1)
	}
	jsonResponse(w, status, tailcfg.DERPAdmitClientResponse{Allow: allow})
}
