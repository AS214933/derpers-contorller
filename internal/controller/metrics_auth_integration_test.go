package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AS214933/derpers-contorller/internal/model"
	"github.com/AS214933/derpers-contorller/internal/store"
)

func TestIntegrationMetricsScrapeTokenAndAdminIsolation(t *testing.T) {
	a := integrationApp(t)
	a.Config.MetricsToken = "non-production-scrape-secret"
	ctx := context.Background()
	admin, user := store.Token(), store.Token()
	for token, account := range map[string]model.User{
		admin: {ID: "metrics-admin", Admin: true},
		user:  {ID: "metrics-user"},
	} {
		if err := a.Store.SetSession(ctx, token, account, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, path, cookie, bearer string
		want                       int
	}{
		{"anonymous scrape denied", "/metrics", "", "", 403},
		{"scrape credential accepted", "/metrics", "", "Bearer non-production-scrape-secret", 200},
		{"ordinary user scrape denied", "/metrics", user, "", 403},
		{"administrator scrape accepted", "/metrics", admin, "", 200},
		{"forged administrator session denied", "/metrics", "forged-session", "", 403},
		{"API does not accept scrape token", "/api/v1/metrics", "", "Bearer non-production-scrape-secret", 401},
		{"API ordinary user denied despite token", "/api/v1/metrics", user, "Bearer non-production-scrape-secret", 403},
		{"API administrator accepted", "/api/v1/metrics", admin, "", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://controller"+tc.path, nil)
			r.RemoteAddr = "192.0.2.10:1234"
			r.Header.Set("X-Forwarded-Proto", "https")
			if tc.cookie != "" {
				r.AddCookie(&http.Cookie{Name: "derpers_session", Value: tc.cookie})
			}
			if tc.bearer != "" {
				r.Header.Set("Authorization", tc.bearer)
			}
			w := httptest.NewRecorder()
			a.Handler().ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.want, w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("metrics response may be cached: %q", w.Header().Get("Cache-Control"))
			}
			if tc.want == 200 && !strings.Contains(w.Body.String(), "derpers_admissions_allowed_total ") {
				t.Fatal("authenticated scrape did not return actual controller metrics")
			}
		})
	}
	if err := a.Store.DeleteSession(ctx, admin); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "http://controller/metrics", nil)
	r.RemoteAddr = "192.0.2.10:1234"
	r.AddCookie(&http.Cookie{Name: "derpers_session", Value: admin})
	if a.metricsAuthorized(r) {
		t.Fatal("revoked administrator session retained metrics access")
	}
}
