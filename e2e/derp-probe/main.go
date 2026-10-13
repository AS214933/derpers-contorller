//go:build e2eprobe

// Real protocol probe built within the pinned upstream Tailscale module.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/types/key"
)

func main() {
	url := flag.String("url", "", "DERP URL")
	caFile := flag.String("ca", "", "CA PEM")
	flag.Parse()
	if *url == "" || *caFile == "" {
		fmt.Fprintln(os.Stderr, "url and ca required")
		os.Exit(2)
	}
	roots := x509.NewCertPool()
	ca, err := os.ReadFile(*caFile)
	if err != nil || !roots.AppendCertsFromPEM(ca) {
		fmt.Fprintln(os.Stderr, "invalid CA", err)
		os.Exit(2)
	}
	private := key.NewNode()
	json.NewEncoder(os.Stdout).Encode(map[string]any{"node_public": private.Public().String(), "phase": "start"})
	monitor := netmon.NewStatic()
	client, err := derphttp.NewClient(private, *url, func(string, ...any) {}, monitor)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer client.Close()
	client.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": "transport_error", "error": err.Error()})
		os.Exit(2)
	}
	// Connect alone does not wait for admission. ServerInfo is sent only after verification.
	type result struct {
		message derp.ReceivedMessage
		err     error
	}
	done := make(chan result, 1)
	go func() { m, e := client.Recv(); done <- result{m, e} }()
	select {
	case got := <-done:
		if _, ok := got.message.(derp.ServerInfoMessage); ok {
			json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": "admitted"})
			os.Exit(1)
		}
		if got.err != nil {
			json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": "closed", "error": got.err.Error()})
			return
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": "unexpected", "type": fmt.Sprintf("%T", got.message)})
		os.Exit(2)
	case <-ctx.Done():
		json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": "timeout"})
		os.Exit(2)
	}
}
