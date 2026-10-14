package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"tailscale.com/tailcfg"
)

const admissionLimit = 4096

// This listener belongs only to the node's private Docker network. Caddy keeps
// derper's existing verification URL stable while the Agent signs each request.
func (a *Agent) startAdmissionRelay(listener net.Listener, cancel context.CancelFunc) (*http.Server, <-chan error) {
	server := &http.Server{Handler: http.HandlerFunc(a.admissionRelay), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	failures := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			failures <- fmt.Errorf("private admission relay failed: %w", err)
			cancel()
		}
	}()
	return server, failures
}

func (a *Agent) admissionRelay(w http.ResponseWriter, r *http.Request) {
	respond := func(status int, allow bool) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(tailcfg.DERPAdmitClientResponse{Allow: allow})
	}
	if r.URL.Path != "/verify" || r.URL.RawQuery != "" {
		respond(http.StatusNotFound, false)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		respond(http.StatusMethodNotAllowed, false)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, admissionLimit))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			respond(http.StatusRequestEntityTooLarge, false)
		} else {
			respond(http.StatusBadRequest, false)
		}
		return
	}
	var request tailcfg.DERPAdmitClientRequest
	if json.Unmarshal(data, &request) != nil || request.NodePublic.IsZero() {
		respond(http.StatusBadRequest, false)
		return
	}
	client := a.nodeClient.Load()
	if client == nil {
		respond(http.StatusServiceUnavailable, false)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	upstream, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(a.cfg.ControllerURL, "/")+"/admission/v1/verify", bytes.NewReader(data))
	if err != nil {
		respond(http.StatusServiceUnavailable, false)
		return
	}
	// Preserve the protocol body exactly, but generate authentication locally.
	// No caller-supplied identity, authorization or forwarding headers survive.
	upstream.Header.Set("Content-Type", "application/json")
	response, err := client.Do(upstream)
	if err != nil {
		respond(http.StatusServiceUnavailable, false)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		respond(http.StatusServiceUnavailable, false)
		return
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, admissionLimit+1))
	var result struct{ Allow *bool }
	if err != nil || len(payload) > admissionLimit || json.Unmarshal(payload, &result) != nil || result.Allow == nil {
		respond(http.StatusServiceUnavailable, false)
		return
	}
	respond(http.StatusOK, *result.Allow)
}
