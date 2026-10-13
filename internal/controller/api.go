package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/AS214933/derpers-contorller/internal/model"
	"github.com/AS214933/derpers-contorller/internal/store"
	"gopkg.in/yaml.v3"
	"tailscale.com/tailcfg"
)

func (a *App) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { jsonResponse(w, 200, map[string]string{"status": "ok"}) })
	m.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, c := context.WithTimeout(r.Context(), 2*time.Second)
		defer c()
		if e := a.Store.Pool.Ping(ctx); e != nil {
			failure(w, 503, "database unavailable")
			return
		}
		jsonResponse(w, 200, map[string]string{"status": "ready"})
	})
	m.HandleFunc("GET /auth/login", a.login)
	m.HandleFunc("GET /auth/callback", a.callback)
	m.HandleFunc("POST /auth/logout", a.logout)
	m.HandleFunc("GET /api/v1/me", a.authHandler(a.me, false))
	m.HandleFunc("POST /api/v1/node-enroll", a.enroll)
	m.HandleFunc("POST /admission/v1/verify", a.admission)
	m.HandleFunc("/node/v1/", a.nodeAPI)
	m.HandleFunc("/api/v1/", a.authHandler(a.management, false))
	m.HandleFunc("GET /derpmap.json", func(w http.ResponseWriter, r *http.Request) {
		v, e := a.DERPMap(r.Context(), true)
		if e != nil {
			failure(w, 503, "map unavailable")
			return
		}
		jsonResponse(w, 200, v)
	})
	m.HandleFunc("GET /metrics", a.metrics)
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.NotFound(w, r)
			return
		}
		clean := filepath.Clean("/" + r.URL.Path)
		p := filepath.Join(a.Config.WebDir, clean)
		if st, e := os.Stat(p); e == nil && !st.IsDir() {
			http.ServeFile(w, r, p)
			return
		}
		http.ServeFile(w, r, filepath.Join(a.Config.WebDir, "index.html"))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		defer func() {
			if v := recover(); v != nil {
				slog.Error("HTTP handler panic", "path", r.URL.Path, "panic", fmt.Sprint(v))
				failure(w, 500, "internal server error")
			}
		}()
		m.ServeHTTP(w, r)
	})
}
func (a *App) management(w http.ResponseWriter, r *http.Request, u model.User) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/"), "/")
	switch parts[0] {
	case "networks":
		a.networkAPI(w, r, u, parts[1:])
	case "nodes":
		a.nodesAPI(w, r, u, parts[1:])
	case "dns-accounts":
		if !u.Admin {
			failure(w, 403, "administrator required")
			return
		}
		a.dnsAPI(w, r, u, parts[1:])
	case "settings":
		if !u.Admin {
			failure(w, 403, "administrator required")
			return
		}
		a.settingsAPI(w, r, u)
	case "audit":
		if !u.Admin {
			failure(w, 403, "administrator required")
			return
		}
		v, e := a.Store.Audits(r.Context())
		if e != nil {
			failure(w, 503, "audit unavailable")
			return
		}
		jsonResponse(w, 200, v)
	case "monitoring-config":
		if !u.Admin {
			failure(w, 403, "administrator required")
			return
		}
		jsonResponse(w, 200, map[string]string{"grafana_url": a.Config.GrafanaURL, "prometheus_url": a.Config.PrometheusURL})
	case "metrics":
		if !u.Admin {
			failure(w, 403, "administrator required")
			return
		}
		if r.Method != "GET" {
			failure(w, 405, "method not allowed")
			return
		}
		a.metrics(w, r)
	case "derpmap":
		a.exportMap(w, r)
	default:
		http.NotFound(w, r)
	}
}
func (a *App) Settings(ctx context.Context) map[string]string {
	r, e := a.Store.Get(ctx, "settings", "global")
	if e != nil {
		return map[string]string{"approval_mode": "manual"}
	}
	v, _ := store.Decode[map[string]string](r)
	if v["approval_mode"] == "" {
		v["approval_mode"] = "manual"
	}
	return v
}
func (a *App) settingsAPI(w http.ResponseWriter, r *http.Request, u model.User) {
	if r.Method == "GET" {
		jsonResponse(w, 200, a.Settings(r.Context()))
		return
	}
	if r.Method != "PUT" {
		failure(w, 405, "method not allowed")
		return
	}
	var v map[string]string
	if body(r, &v) != nil || (v["approval_mode"] != "manual" && v["approval_mode"] != "automatic") {
		failure(w, 400, "approval_mode must be manual or automatic")
		return
	}
	rev := int64(1)
	if old, e := a.Store.Get(r.Context(), "settings", "global"); e == nil {
		rev = old.Revision + 1
	}
	if e := a.Store.Save(r.Context(), "settings", "global", "", rev, v, nil); e != nil {
		apiError(w, e)
		return
	}
	a.event(r.Context(), "settings_changed", u.ID, "", "", "approval mode updated")
	jsonResponse(w, 200, v)
}
func apiError(w http.ResponseWriter, e error) {
	status := 400
	if errors.Is(e, store.ErrNotFound) {
		status = 404
	} else if errors.Is(e, store.ErrConflict) {
		status = 409
	}
	failure(w, status, e.Error())
}
func (a *App) networkAPI(w http.ResponseWriter, r *http.Request, u model.User, parts []string) {
	ctx := r.Context()
	if len(parts) == 0 && r.Method == "GET" {
		owner := u.ID
		if u.Admin {
			owner = ""
		}
		rows, e := a.Store.List(ctx, "network", owner)
		if e != nil {
			failure(w, 503, "storage unavailable")
			return
		}
		out := []model.Network{}
		for _, row := range rows {
			n, e := store.Decode[model.Network](row)
			if e != nil {
				failure(w, 500, "invalid stored source")
				return
			}
			out = append(out, n)
		}
		jsonResponse(w, 200, out)
		return
	}
	var old model.Network
	var rec store.Record
	var err error
	if len(parts) > 0 {
		rec, err = a.Store.Get(ctx, "network", parts[0])
		if err != nil {
			apiError(w, err)
			return
		}
		old, err = store.Decode[model.Network](rec)
		if err != nil {
			apiError(w, err)
			return
		}
		if old.OwnerID != u.ID && !u.Admin {
			failure(w, 403, "network belongs to another user")
			return
		}
	}
	if len(parts) == 1 && r.Method == "GET" {
		jsonResponse(w, 200, old)
		return
	}
	if len(parts) == 1 && r.Method == "DELETE" {
		if err = a.Store.Delete(ctx, "network", old.ID); err != nil {
			apiError(w, err)
			return
		}
		a.invalidate(old.ID)
		a.event(ctx, "network_deleted", u.ID, "", old.ID, "network removed")
		jsonResponse(w, 204, nil)
		return
	}
	if len(parts) == 0 && r.Method == "POST" || len(parts) == 1 && r.Method == "PUT" {
		var input struct {
			model.Network
			Credentials map[string]string `json:"credentials"`
		}
		if err = body(r, &input); err != nil {
			apiError(w, err)
			return
		}
		n := input.Network
		if n.Name == "" || (n.Kind != "headscale" && n.Kind != "tailscale") {
			failure(w, 400, "name and supported kind are required")
			return
		}
		sec := input.Credentials
		if sec == nil {
			sec = map[string]string{}
		}
		if old.ID != "" {
			prior, e := a.Store.Secrets(rec)
			if e != nil {
				failure(w, 500, "credential decryption failed")
				return
			}
			for k, v := range prior {
				if sec[k] == "" {
					sec[k] = v
				}
			}
		}
		if n.Kind == "headscale" {
			if n.URL, err = normalizeHeadscale(n.URL); err != nil {
				apiError(w, err)
				return
			}
		}
		if n.Kind == "tailscale" && (n.Tailnet == "" || sec["client_id"] == "" || sec["client_secret"] == "") {
			failure(w, 400, "tailnet and OAuth client credentials required")
			return
		}
		if err = a.TestNetwork(ctx, n, sec); err != nil {
			apiError(w, err)
			return
		}
		n.ID = old.ID
		n.OwnerID = old.OwnerID
		n.CreatedAt = old.CreatedAt
		n.Revision = old.Revision + 1
		if n.ID == "" {
			n.ID = store.ID()
			n.OwnerID = u.ID
			n.CreatedAt = time.Now().UTC()
		}
		n.Status = "pending"
		if a.Settings(ctx)["approval_mode"] == "automatic" {
			n.Status = "approved"
		}
		if old.ID != "" && old.Kind == n.Kind && old.Tailnet == n.Tailnet && old.URL == n.URL {
			prior, _ := a.Store.Secrets(rec)
			if prior["client_id"] == sec["client_id"] && prior["ca_pem"] == sec["ca_pem"] {
				n.Status = old.Status
			}
		}
		n.Health = "healthy"
		n.DeviceCount = old.DeviceCount
		n.LastSuccess = old.LastSuccess
		n.LastError = ""
		if err = a.Store.Save(ctx, "network", n.ID, n.OwnerID, n.Revision, n, sec); err != nil {
			apiError(w, err)
			return
		}
		a.invalidate(n.ID)
		a.event(ctx, "network_saved", u.ID, "", n.ID, "source tested and saved")
		jsonResponse(w, 200, n)
		return
	}
	if len(parts) == 2 && r.Method == "POST" {
		sec, e := a.Store.Secrets(rec)
		if e != nil {
			failure(w, 500, "credential decryption failed")
			return
		}
		switch parts[1] {
		case "test":
			e = a.TestNetwork(ctx, old, sec)
			patch := map[string]any{"health": "healthy", "last_error": ""}
			if e != nil {
				patch["health"] = "degraded"
				patch["last_error"] = e.Error()
			} else if old.Kind == "headscale" {
				patch["last_success"] = time.Now().UTC()
			}
			if x := a.Store.Patch(ctx, "network", old.ID, old.Revision, patch); x != nil {
				apiError(w, x)
				return
			}
			a.event(ctx, "source_test", u.ID, "", old.ID, patch["health"].(string))
			if e != nil {
				apiError(w, e)
				return
			}
			jsonResponse(w, 200, map[string]string{"status": "ok"})
			return
		case "sync":
			if e = a.SyncNetwork(ctx, old.ID); e != nil {
				apiError(w, e)
				return
			}
			jsonResponse(w, 200, map[string]string{"status": "ok"})
			return
		case "approve", "reject", "disable":
			if !u.Admin {
				failure(w, 403, "administrator required")
				return
			}
			status := map[string]string{"approve": "approved", "reject": "rejected", "disable": "disabled"}[parts[1]]
			n, e := a.SetNetworkStatus(ctx, old.ID, status, u.ID)
			if e != nil {
				apiError(w, e)
				return
			}
			jsonResponse(w, 200, n)
			return
		}
	}
	failure(w, 405, "unsupported network operation")
}
func (a *App) AddNetwork(ctx context.Context, n model.Network, sec map[string]string, approve bool) (model.Network, error) {
	if n.Kind != "headscale" && n.Kind != "tailscale" {
		return n, errors.New("kind must be headscale or tailscale")
	}
	if n.Kind == "headscale" {
		var e error
		n.URL, e = normalizeHeadscale(n.URL)
		if e != nil {
			return n, e
		}
	}
	if e := a.TestNetwork(ctx, n, sec); e != nil {
		return n, e
	}
	n.ID = store.ID()
	n.OwnerID = "operator"
	n.Revision = 1
	n.CreatedAt = time.Now().UTC()
	n.Status = "pending"
	if approve {
		n.Status = "approved"
	}
	n.Health = "healthy"
	e := a.Store.Save(ctx, "network", n.ID, n.OwnerID, 1, n, sec)
	if e == nil {
		a.event(ctx, "network_created", "operator", "", n.ID, "source validated")
	}
	return n, e
}
func (a *App) SetNetworkStatus(ctx context.Context, id, status, actor string) (model.Network, error) {
	r, e := a.Store.Get(ctx, "network", id)
	if e != nil {
		return model.Network{}, e
	}
	n, e := store.Decode[model.Network](r)
	if e != nil {
		return n, e
	}
	if status != "approved" && status != "disabled" && status != "rejected" {
		return n, errors.New("invalid status")
	}
	if status == "approved" {
		sec, e := a.Store.Secrets(r)
		if e != nil {
			return n, e
		}
		if e = a.TestNetwork(ctx, n, sec); e != nil {
			return n, e
		}
	}
	n.Status = status
	if status == "approved" {
		n.Health = "healthy"
		n.LastError = ""
		if n.Kind == "headscale" {
			now := time.Now().UTC()
			n.LastSuccess = &now
		}
	}
	n.Revision++
	if e = a.Store.Save(ctx, "network", id, n.OwnerID, n.Revision, n, nil); e != nil {
		return n, e
	}
	a.invalidate(id)
	a.event(ctx, "network_status", actor, "", id, status)
	return n, nil
}
func (a *App) DERPMap(ctx context.Context, only bool) (tailcfg.DERPMap, error) {
	out := tailcfg.DERPMap{OmitDefaultRegions: only, Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{}}
	rows, e := a.Store.List(ctx, "node", "")
	if e != nil {
		return out, e
	}
	for _, r := range rows {
		n, e := store.Decode[model.Node](r)
		if e != nil {
			return out, e
		}
		if !n.Enabled || !n.Published {
			continue
		}
		stun := -1
		if n.STUNEnabled {
			stun = n.STUNPort
		}
		out.Regions[tailcfg.DERPRegionID(n.RegionID)] = &tailcfg.DERPRegion{RegionID: tailcfg.DERPRegionID(n.RegionID), RegionCode: n.RegionCode, RegionName: n.RegionName, Nodes: []*tailcfg.DERPNode{{Name: n.Name, RegionID: tailcfg.DERPRegionID(n.RegionID), HostName: n.Hostname, IPv4: n.IPv4, IPv6: n.IPv6, DERPPort: n.HTTPSPort, STUNPort: stun, CanPort80: n.HTTPEnabled}}}
	}
	return out, nil
}
func (a *App) exportMap(w http.ResponseWriter, r *http.Request) {
	v, e := a.DERPMap(r.Context(), r.URL.Query().Get("only_custom") == "true")
	if e != nil {
		failure(w, 503, "map unavailable")
		return
	}
	if r.URL.Query().Get("format") == "yaml" {
		b, e := yaml.Marshal(v)
		if e != nil {
			apiError(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(b)
		return
	}
	jsonResponse(w, 200, v)
}

var hostnameRE = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)

func validNode(n model.Node) error {
	if n.Name == "" || !domain(strings.ToLower(n.Hostname)) {
		return errors.New("name and valid fully qualified hostname required")
	}
	if n.HTTPSPort < 1 || n.HTTPSPort > 65535 || n.STUNPort < 1 || n.STUNPort > 65535 || n.HTTPSPort == 80 && n.HTTPEnabled {
		return errors.New("invalid or conflicting port")
	}
	if n.RegionID < 900 || n.RegionID > 999 {
		return errors.New("region_id must be 900..999")
	}
	if n.IPv4 != "" || n.IPv6 != "" {
		if _, e := desiredDNS(n); e != nil {
			return e
		}
	}
	return nil
}
func drainBody(r *http.Request) { _, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 4096)) }

var _ = fmt.Sprintf
