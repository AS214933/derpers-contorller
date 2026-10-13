package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/AS214933/derpers-contorller/internal/config"
	"github.com/AS214933/derpers-contorller/internal/controller"
	"github.com/AS214933/derpers-contorller/internal/model"
	"github.com/AS214933/derpers-contorller/internal/store"
	"gopkg.in/yaml.v3"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		slog.Error("controller command failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, errOut io.Writer) error {
	global := flag.NewFlagSet("controller", flag.ContinueOnError)
	global.SetOutput(errOut)
	path := global.String("config", "", "YAML startup configuration file; environment overrides YAML")
	global.Usage = func() {
		fmt.Fprintln(errOut, "Usage: controller [--config FILE] serve|migrate|network|node|derpmap|audit")
		global.PrintDefaults()
	}
	if err := global.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	args = global.Args()
	if len(args) == 0 {
		args = []string{"serve"}
	}
	if !knownCommand(args[0]) {
		return fmt.Errorf("unknown command %q", args[0])
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	db, err := store.Open(startup, cfg.DatabaseURL, cfg.MasterKey)
	if err != nil {
		cancel()
		return fmt.Errorf("open PostgreSQL: %w", err)
	}
	defer db.Close()
	if err := db.Migrate(startup); err != nil {
		cancel()
		return fmt.Errorf("database migration: %w", err)
	}
	cancel()
	if args[0] == "migrate" {
		if len(args) != 1 {
			return errors.New("migrate takes no arguments")
		}
		return printJSON(out, map[string]string{"status": "migrated"})
	}
	app, err := controller.New(cfg, db)
	if err != nil {
		return err
	}
	if args[0] == "serve" {
		if len(args) != 1 {
			return errors.New("serve takes no positional arguments")
		}
		return serve(ctx, app)
	}
	commandCtx, stop := context.WithTimeout(ctx, 60*time.Second)
	defer stop()
	switch args[0] {
	case "network":
		return networkCommand(commandCtx, app, args[1:], out, errOut)
	case "node":
		return nodeCommand(commandCtx, app, args[1:], out, errOut)
	case "derpmap":
		flags := newFlags("derpmap", errOut)
		format := flags.String("format", "json", "json or yaml")
		only := flags.Bool("only-custom", true, "omit public default DERP regions")
		if err := parseFlags(flags, args[1:]); err != nil {
			return err
		}
		if *format != "json" && *format != "yaml" {
			return errors.New("format must be json or yaml")
		}
		value, err := app.DERPMap(commandCtx, *only)
		if err != nil {
			return err
		}
		if *format == "json" {
			return printJSON(out, value)
		}
		body, err := yaml.Marshal(value)
		if err != nil {
			return err
		}
		_, err = out.Write(body)
		return err
	case "audit":
		if len(args) != 2 || args[1] != "list" {
			return errors.New("usage: controller audit list")
		}
		value, err := db.Audits(commandCtx)
		if err != nil {
			return err
		}
		return printJSON(out, value)
	}
	return errors.New("unsupported command")
}

func knownCommand(command string) bool {
	switch command {
	case "serve", "migrate", "network", "node", "derpmap", "audit":
		return true
	}
	return false
}
func printJSON(out io.Writer, value any) error { return json.NewEncoder(out).Encode(value) }
func newFlags(name string, out io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(out)
	return flags
}
func parseFlags(flags *flag.FlagSet, args []string) error {
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	return nil
}
func required(values ...string) error {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return errors.New("required command arguments are missing; see --help")
		}
	}
	return nil
}
func readOptional(file string) (string, error) {
	if file == "" {
		return "", nil
	}
	body, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func networkCommand(ctx context.Context, app *controller.App, args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: controller network add|list|set-status")
	}
	flags := newFlags("network "+args[0], errOut)
	switch args[0] {
	case "add":
		name := flags.String("name", "", "network name")
		kind := flags.String("kind", "", "headscale or tailscale")
		networkURL := flags.String("url", "", "Headscale HTTPS origin or /verify URL")
		tailnet := flags.String("tailnet", "", "official Tailnet identifier")
		caFile := flags.String("ca-file", "", "additional Headscale server CA PEM file")
		clientID := flags.String("client-id", "", "Tailscale OAuth client ID")
		secretFile := flags.String("client-secret-file", "", "file containing Tailscale OAuth client secret")
		bearerFile := flags.String("bearer-token-file", "", "file containing optional Headscale reverse proxy bearer token")
		approve := flags.Bool("approve", false, "approve after source connection and credentials have been validated")
		if err := parseFlags(flags, args[1:]); err != nil {
			return err
		}
		if err := required(*name, *kind); err != nil {
			return err
		}
		ca, err := readOptional(*caFile)
		if err != nil {
			return err
		}
		secret, err := readOptional(*secretFile)
		if err != nil {
			return err
		}
		bearer, err := readOptional(*bearerFile)
		if err != nil {
			return err
		}
		credentials := map[string]string{}
		if ca != "" {
			credentials["ca_pem"] = ca
		}
		if *clientID != "" {
			credentials["client_id"] = *clientID
		}
		if secret != "" {
			credentials["client_secret"] = strings.TrimSpace(secret)
		}
		if bearer != "" {
			credentials["bearer_token"] = strings.TrimSpace(bearer)
		}
		value, err := app.AddNetwork(ctx, model.Network{Name: *name, Kind: *kind, URL: *networkURL, Tailnet: *tailnet}, credentials, *approve)
		if err != nil {
			return err
		}
		return printJSON(out, value)
	case "set-status":
		id := flags.String("id", "", "network ID")
		status := flags.String("status", "", "approved, disabled or rejected")
		if err := parseFlags(flags, args[1:]); err != nil {
			return err
		}
		if err := required(*id, *status); err != nil {
			return err
		}
		value, err := app.SetNetworkStatus(ctx, *id, *status, "operator")
		if err != nil {
			return err
		}
		return printJSON(out, value)
	case "list":
		if err := parseFlags(flags, args[1:]); err != nil {
			return err
		}
		rows, err := app.Store.List(ctx, "network", "")
		if err != nil {
			return err
		}
		values := []model.Network{}
		for _, row := range rows {
			value, err := store.Decode[model.Network](row)
			if err != nil {
				return err
			}
			values = append(values, value)
		}
		return printJSON(out, values)
	default:
		return errors.New("usage: controller network add|list|set-status")
	}
}

func nodeCommand(ctx context.Context, app *controller.App, args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: controller node add|list|token|publish")
	}
	flags := newFlags("node "+args[0], errOut)
	switch args[0] {
	case "add":
		name := flags.String("name", "", "node name")
		hostname := flags.String("hostname", "", "DERP TLS hostname")
		ipv4 := flags.String("ipv4", "", "optional public IPv4")
		ipv6 := flags.String("ipv6", "", "optional public IPv6")
		port := flags.Int("https-port", 443, "DERP HTTPS port")
		stunPort := flags.Int("stun-port", 3478, "STUN UDP port")
		stun := flags.Bool("stun", true, "enable STUN")
		httpProbe := flags.Bool("http", true, "enable HTTP port 80 probe")
		regionID := flags.Int("region-id", 0, "stable region ID 900..999; zero allocates one")
		regionCode := flags.String("region-code", "", "region code")
		regionName := flags.String("region-name", "", "region display name")
		dnsID := flags.String("dns-account-id", "", "DNS account ID for managed DNS and ACME")
		certFile := flags.String("cert-file", "", "existing server certificate PEM file")
		keyFile := flags.String("key-file", "", "existing server private key PEM file")
		caFile := flags.String("ca-file", "", "additional server trust CA PEM file")
		derperKeyFile := flags.String("derper-key-file", "", "existing DERP config/key to preserve when migrating")
		derperImage := flags.String("derper-image", "", "override desired DERP image")
		caddyImage := flags.String("caddy-image", "", "override desired Caddy image")
		if err := parseFlags(flags, args[1:]); err != nil {
			return err
		}
		if err := required(*name, *hostname); err != nil {
			return err
		}
		if (*certFile == "") != (*keyFile == "") {
			return errors.New("cert-file and key-file must be provided together")
		}
		secrets := map[string]string{}
		for field, file := range map[string]string{"certificate_pem": *certFile, "certificate_key_pem": *keyFile, "ca_pem": *caFile, "derper_key": *derperKeyFile} {
			body, err := readOptional(file)
			if err != nil {
				return err
			}
			if body != "" {
				secrets[field] = body
			}
		}
		value, err := app.AddNode(ctx, model.Node{Name: *name, Hostname: *hostname, IPv4: *ipv4, IPv6: *ipv6, HTTPSPort: *port, STUNPort: *stunPort, STUNEnabled: *stun, HTTPEnabled: *httpProbe, RegionID: *regionID, RegionCode: *regionCode, RegionName: *regionName, DNSAccountID: *dnsID, DerperImage: *derperImage, CaddyImage: *caddyImage}, secrets)
		if err != nil {
			return err
		}
		return printJSON(out, value)
	case "token", "publish":
		id := flags.String("id", "", "node ID")
		if err := parseFlags(flags, args[1:]); err != nil {
			return err
		}
		if err := required(*id); err != nil {
			return err
		}
		if args[0] == "publish" {
			value, err := app.PublishNode(ctx, *id)
			if err != nil {
				return err
			}
			return printJSON(out, value)
		}
		record, err := app.Store.Get(ctx, "node", *id)
		if err != nil {
			return err
		}
		node, err := store.Decode[model.Node](record)
		if err != nil {
			return err
		}
		if !node.Enabled {
			return errors.New("cannot enroll a disabled node")
		}
		token, err := app.Store.NewEnrollment(ctx, *id)
		if err != nil {
			return err
		}
		if err := app.Store.Audit(ctx, model.Audit{Event: "node_token", Actor: "operator", NodeID: *id, Detail: "one-time token issued via local CLI"}); err != nil {
			return err
		}
		return printJSON(out, map[string]string{"token": token, "node_id": *id})
	case "list":
		if err := parseFlags(flags, args[1:]); err != nil {
			return err
		}
		rows, err := app.Store.List(ctx, "node", "")
		if err != nil {
			return err
		}
		values := []model.Node{}
		for _, row := range rows {
			value, err := store.Decode[model.Node](row)
			if err != nil {
				return err
			}
			values = append(values, value)
		}
		return printJSON(out, values)
	default:
		return errors.New("usage: controller node add|list|token|publish")
	}
}

func serve(ctx context.Context, app *controller.App) error {
	if app.Config.TLSAddr == "" {
		return errors.New("TLS_ADDR is required for authenticated node and admission APIs")
	}
	if err := app.InitAuth(ctx); err != nil {
		return fmt.Errorf("initialize OIDC: %w", err)
	}
	tlsConfig, err := app.TLSConfig()
	if err != nil {
		return fmt.Errorf("initialize controller TLS: %w", err)
	}
	tlsListener, err := net.Listen("tcp", app.Config.TLSAddr)
	if err != nil {
		return err
	}
	defer tlsListener.Close()
	handler := app.Handler()
	newServer := func(addr string) *http.Server {
		return &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	}
	tlsServer := newServer(app.Config.TLSAddr)
	tlsServer.TLSConfig = tlsConfig
	servers := []*http.Server{tlsServer}
	listeners := []net.Listener{tlsListener}
	if app.Config.HTTPAddr != "" {
		listener, err := net.Listen("tcp", app.Config.HTTPAddr)
		if err != nil {
			return err
		}
		defer listener.Close()
		servers = append(servers, newServer(app.Config.HTTPAddr))
		listeners = append(listeners, listener)
	}
	backgroundCtx, stop := context.WithCancel(ctx)
	defer stop()
	app.Background(backgroundCtx)
	serverErrors := make(chan error, len(servers))
	for i, server := range servers {
		listener := listeners[i]
		isTLS := i == 0
		go func() {
			var err error
			if isTLS {
				err = server.ServeTLS(listener, "", "")
			} else {
				err = server.Serve(listener)
			}
			serverErrors <- err
		}()
	}
	slog.Info("controller serving", "http_addr", app.Config.HTTPAddr, "tls_addr", app.Config.TLSAddr)
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-serverErrors:
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
	}
	stop()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, server := range servers {
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			serveErr = errors.Join(serveErr, err)
		}
	}
	return serveErr
}
