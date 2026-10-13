package controller

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestACMETransportKeepsBodyAliveAndCancelsTask(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		select {
		case <-time.After(20 * time.Millisecond):
			_, _ = w.Write([]byte("complete"))
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &http.Client{Transport: contextualTransport{ctx, http.DefaultTransport}}
	res, e := client.Get(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(res.Body)
	res.Body.Close()
	if e != nil || string(b) != "complete" {
		t.Fatalf("transport cancelled the response body early: %q %v", b, e)
	}
	res, e = client.Get(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	cancel()
	_, e = io.ReadAll(res.Body)
	res.Body.Close()
	if e == nil {
		t.Fatal("task cancellation did not stop ACME body read")
	}
}
