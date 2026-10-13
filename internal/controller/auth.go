package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AS214933/derpers-contorller/internal/model"
	"github.com/AS214933/derpers-contorller/internal/store"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type authentication struct {
	app      *App
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
}
type authState struct{ State, Nonce, Verifier string }

func newAuthentication(ctx context.Context, a *App) (*authentication, error) {
	if e := validHTTPS(a.Config.PublicURL); e != nil {
		return nil, errors.New("PUBLIC_URL must be HTTPS when OIDC is enabled")
	}
	p, e := oidc.NewProvider(ctx, a.Config.OIDCIssuer)
	if e != nil {
		return nil, e
	}
	return &authentication{app: a, oauth: oauth2.Config{ClientID: a.Config.OIDCClientID, ClientSecret: a.Config.OIDCClientSecret, RedirectURL: strings.TrimRight(a.Config.PublicURL, "/") + "/auth/callback", Endpoint: p.Endpoint(), Scopes: a.Config.OIDCScopes}, verifier: p.Verifier(&oidc.Config{ClientID: a.Config.OIDCClientID})}, nil
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if a.auth == nil {
		failure(w, 503, "OIDC is not configured")
		return
	}
	st := authState{State: store.Token(), Nonce: store.Token(), Verifier: oauth2.GenerateVerifier()}
	cookie := store.Token()
	if e := a.Store.SetSession(r.Context(), cookie, st, 10*time.Minute); e != nil {
		failure(w, 503, "session storage unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "derpers_oauth", Value: cookie, Path: "/auth", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, a.auth.oauth.AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier)), http.StatusFound)
}
func (a *App) callback(w http.ResponseWriter, r *http.Request) {
	if a.auth == nil {
		failure(w, 503, "OIDC is not configured")
		return
	}
	c, e := r.Cookie("derpers_oauth")
	if e != nil {
		failure(w, 400, "login state is missing")
		return
	}
	var st authState
	if e = a.Store.Session(r.Context(), c.Value, &st, true); e != nil || st.State != r.URL.Query().Get("state") || r.URL.Query().Get("error") != "" {
		failure(w, 400, "login state is invalid or expired")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	tok, e := a.auth.oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(st.Verifier))
	if e != nil {
		failure(w, 401, "OIDC code exchange failed")
		return
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok {
		failure(w, 401, "OIDC response has no ID token")
		return
	}
	id, e := a.auth.verifier.Verify(ctx, raw)
	if e != nil || id.Nonce != st.Nonce {
		failure(w, 401, "OIDC token validation failed")
		return
	}
	claims := map[string]any{}
	if e = id.Claims(&claims); e != nil {
		failure(w, 401, "invalid identity claims")
		return
	}
	u := model.User{ID: store.Hash(id.Issuer + "\x00" + id.Subject), Subject: id.Subject, Email: textClaim(claims["email"]), Name: textClaim(claims["name"]), Groups: groups(claims, a.Config.OIDCGroupsClaim)}
	for _, g := range u.Groups {
		for _, admin := range a.Config.OIDCAdminGroups {
			if g == admin {
				u.Admin = true
			}
		}
	}
	session := store.Token()
	if e = a.Store.SetSession(ctx, session, u, time.Hour); e != nil {
		failure(w, 503, "session storage unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "derpers_session", Value: session, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 3600})
	http.SetCookie(w, &http.Cookie{Name: "derpers_oauth", Value: "", Path: "/auth", Secure: true, HttpOnly: true, MaxAge: -1})
	a.event(ctx, "login", u.ID, "", "", "OIDC session established")
	http.Redirect(w, r, "/", http.StatusFound)
}
func textClaim(v any) string { s, _ := v.(string); return s }
func groups(claims map[string]any, path string) []string {
	var v any = claims
	for _, part := range strings.Split(path, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return []string{}
		}
		v = m[part]
	}
	out := []string{}
	switch a := v.(type) {
	case []any:
		for _, g := range a {
			if s, ok := g.(string); ok {
				out = append(out, s)
			}
		}
	case []string:
		out = a
	}
	return out
}
func (a *App) currentUser(r *http.Request) (model.User, error) {
	var u model.User
	c, e := r.Cookie("derpers_session")
	if e != nil {
		return u, e
	}
	e = a.Store.Session(r.Context(), c.Value, &u, false)
	return u, e
}
func (a *App) originOK(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, e := url.Parse(a.Config.PublicURL)
	return e == nil && origin == u.Scheme+"://"+u.Host
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if !a.originOK(r) {
		failure(w, 403, "origin rejected")
		return
	}
	if c, e := r.Cookie("derpers_session"); e == nil {
		_ = a.Store.DeleteSession(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "derpers_session", Value: "", Path: "/", Secure: true, HttpOnly: true, MaxAge: -1})
	jsonResponse(w, 204, nil)
}
func (a *App) authHandler(next func(http.ResponseWriter, *http.Request, model.User), admin bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, e := a.currentUser(r)
		if e != nil {
			failure(w, 401, "login required")
			return
		}
		if admin && !u.Admin {
			failure(w, 403, "administrator group required")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			if !a.originOK(r) {
				failure(w, 403, "origin rejected")
				return
			}
			if r.Body != nil && r.ContentLength != 0 && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				failure(w, 415, "application/json required")
				return
			}
		}
		next(w, r, u)
	}
}
func (a *App) me(w http.ResponseWriter, r *http.Request, u model.User) { jsonResponse(w, 200, u) }

var _ = json.Valid
