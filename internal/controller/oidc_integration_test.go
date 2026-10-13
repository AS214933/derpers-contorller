package controller

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/AS214933/derpers-contorller/internal/model"
	"github.com/AS214933/derpers-contorller/internal/store"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

// This is an actual discovery/JWKS/token issuer, using RSA-signed ID tokens. The
// production verifier, code exchange, nonce, PKCE and PostgreSQL sessions all run.
type oidcTestIssuer struct {
	server           *httptest.Server
	nonce, challenge string
	claims           map[string]any
}

func newOIDCTestIssuer(t *testing.T) *oidcTestIssuer {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: private}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "integration-key"))
	if err != nil {
		t.Fatal(err)
	}
	fixture := &oidcTestIssuer{claims: map[string]any{}}
	fixture.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			jsonResponse(w, 200, map[string]any{"issuer": fixture.server.URL, "authorization_endpoint": fixture.server.URL + "/authorize", "token_endpoint": fixture.server.URL + "/token", "jwks_uri": fixture.server.URL + "/keys", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic"}, "code_challenge_methods_supported": []string{"S256"}})
		case "/keys":
			jsonResponse(w, 200, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &private.PublicKey, KeyID: "integration-key", Algorithm: string(jose.RS256), Use: "sig"}}})
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			id, secret, ok := r.BasicAuth()
			if !ok || id != "test-client" || secret != "test-secret" {
				w.WriteHeader(401)
				return
			}
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "test-code" || base64.RawURLEncoding.EncodeToString(sum[:]) != fixture.challenge {
				t.Error("OIDC code exchange did not provide the bound PKCE verifier")
				w.WriteHeader(400)
				return
			}
			claims := map[string]any{"iss": fixture.server.URL, "sub": "shared-subject", "aud": "test-client", "exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix(), "nonce": fixture.nonce, "email": "same-email@example.test", "name": "测试用户"}
			for k, v := range fixture.claims {
				claims[k] = v
			}
			raw, err := json.Marshal(claims)
			if err != nil {
				t.Error(err)
				return
			}
			signed, err := signer.Sign(raw)
			if err != nil {
				t.Error(err)
				return
			}
			token, err := signed.CompactSerialize()
			if err != nil {
				t.Error(err)
				return
			}
			jsonResponse(w, 200, map[string]any{"access_token": "non-production-test-access-token", "token_type": "Bearer", "expires_in": 300, "id_token": token})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}
func performOIDCLogin(t *testing.T, a *App, fixture *oidcTestIssuer) (*httptest.ResponseRecorder, *http.Cookie, *http.Request) {
	t.Helper()
	a.Config.OIDCIssuer = fixture.server.URL
	a.Config.OIDCClientID = "test-client"
	a.Config.OIDCClientSecret = "test-secret"
	a.Config.OIDCGroupsClaim = "realm.groups"
	a.Config.OIDCAdminGroups = []string{"derp-admins"}
	a.Config.OIDCScopes = []string{"openid", "profile", "email", "groups"}
	ctx := oidc.ClientContext(context.Background(), fixture.server.Client())
	if err := a.InitAuth(ctx); err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRecorder()
	a.Handler().ServeHTTP(login, httptest.NewRequest("GET", "/auth/login", nil))
	if login.Code != 302 {
		t.Fatalf("login redirect: %d %s", login.Code, login.Body.String())
	}
	redirect, err := url.Parse(login.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.nonce = redirect.Query().Get("nonce")
	fixture.challenge = redirect.Query().Get("code_challenge")
	if fixture.nonce == "" || fixture.challenge == "" || redirect.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("login omitted nonce or PKCE")
	}
	var stateCookie *http.Cookie
	for _, c := range login.Result().Cookies() {
		if c.Name == "derpers_oauth" {
			stateCookie = c
		}
	}
	if stateCookie == nil || !stateCookie.HttpOnly || !stateCookie.Secure || stateCookie.SameSite != http.SameSiteLaxMode || stateCookie.Path != "/auth" {
		t.Fatalf("unsafe OAuth state cookie: %+v", stateCookie)
	}
	callback := httptest.NewRequest("GET", "/auth/callback?state="+url.QueryEscape(redirect.Query().Get("state"))+"&code=test-code", nil).WithContext(ctx)
	callback.AddCookie(stateCookie)
	result := httptest.NewRecorder()
	a.Handler().ServeHTTP(result, callback)
	return result, stateCookie, callback
}
func oidcSessionUser(t *testing.T, a *App, response *httptest.ResponseRecorder) model.User {
	t.Helper()
	if response.Code != 302 || response.Header().Get("Location") != "/" {
		t.Fatalf("callback did not establish session: %d %s", response.Code, response.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range response.Result().Cookies() {
		if c.Name == "derpers_session" {
			cookie = c
		}
	}
	if cookie == nil || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unsafe session cookie: %+v", cookie)
	}
	var user model.User
	if err := a.Store.Session(context.Background(), cookie.Value, &user, false); err != nil {
		t.Fatal(err)
	}
	return user
}

func TestIntegrationOIDCVerifiedIssuerSubjectAndAdminGroups(t *testing.T) {
	a := integrationApp(t)
	firstIssuer := newOIDCTestIssuer(t)
	firstIssuer.claims["realm"] = map[string]any{"groups": []string{"users", "derp-admins"}}
	response, _, callback := performOIDCLogin(t, a, firstIssuer)
	first := oidcSessionUser(t, a, response)
	if first.ID != store.Hash(firstIssuer.server.URL+"\x00shared-subject") || first.Subject != "shared-subject" || !first.Admin {
		t.Fatalf("verified identity/administrator group incorrect: %+v", first)
	}
	replay := httptest.NewRecorder()
	a.Handler().ServeHTTP(replay, callback.Clone(callback.Context()))
	if replay.Code != 400 {
		t.Fatal("consumed OAuth state replayed")
	}
	secondIssuer := newOIDCTestIssuer(t)
	secondIssuer.claims["realm"] = map[string]any{"groups": []string{"users"}}
	response, _, _ = performOIDCLogin(t, a, secondIssuer)
	second := oidcSessionUser(t, a, response)
	if first.ID == second.ID || second.Subject != first.Subject || second.Email != first.Email || second.Admin {
		t.Fatalf("identity must use issuer+sub rather than email or sub alone: first=%+v second=%+v", first, second)
	}
	delete(firstIssuer.claims, "realm")
	response, _, _ = performOIDCLogin(t, a, firstIssuer)
	ordinary := oidcSessionUser(t, a, response)
	if ordinary.ID != first.ID || ordinary.Admin {
		t.Fatal("missing groups inherited administrator privilege")
	}
}

func TestIntegrationOIDCRejectsInvalidIDTokens(t *testing.T) {
	a := integrationApp(t)
	fixture := newOIDCTestIssuer(t)
	for _, tc := range []struct {
		name   string
		claims map[string]any
	}{
		{"wrong nonce", map[string]any{"nonce": "different-login"}},
		{"wrong audience", map[string]any{"aud": "another-client"}},
		{"wrong issuer", map[string]any{"iss": "https://untrusted-issuer.example.test"}},
		{"expired token", map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture.claims = tc.claims
			response, _, _ := performOIDCLogin(t, a, fixture)
			if response.Code != 401 {
				t.Fatalf("invalid ID token established session: %d %s", response.Code, response.Body.String())
			}
			for _, c := range response.Result().Cookies() {
				if c.Name == "derpers_session" && c.MaxAge > 0 {
					t.Fatal("invalid identity created session cookie")
				}
			}
		})
	}
}
