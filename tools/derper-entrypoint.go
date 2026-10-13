//go:build linux

// The wrapper preserves JSON argument boundaries and exposes authenticated local metrics.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	args := os.Args[1:]
	metrics := len(args) == 1 && args[0] == "metrics"
	if metrics || len(args) == 0 {
		file := os.Getenv("DERPER_ARGS_FILE")
		if file == "" {
			file = "/node/derper-args.json"
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &args); err != nil {
			return fmt.Errorf("invalid derper arguments: %w", err)
		}
		if len(args) == 0 {
			return fmt.Errorf("derper arguments are empty")
		}
	}
	if !metrics {
		return syscall.Exec("/usr/local/bin/derper", append([]string{"derper"}, args...), os.Environ())
	}
	flags := map[string]string{}
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			key := strings.TrimLeft(args[i], "-")
			if k, v, ok := strings.Cut(key, "="); ok {
				flags[k] = v
			} else if i+1 < len(args) {
				flags[key] = args[i+1]
				i++
			}
		}
	}
	_, port, err := net.SplitHostPort(flags["a"])
	if err != nil {
		return err
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if ca, err := os.ReadFile(filepath.Join(flags["certdir"], "ca.crt")); err == nil {
		if !roots.AppendCertsFromPEM(ca) {
			return fmt.Errorf("invalid node CA")
		}
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: flags["hostname"], RootCAs: roots}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
	response, err := client.Get("https://" + net.JoinHostPort(flags["hostname"], port) + "/debug/varz")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("metrics HTTP %d", response.StatusCode)
	}
	_, err = io.Copy(os.Stdout, io.LimitReader(response.Body, 4<<20))
	return err
}
