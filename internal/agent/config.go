// Package agent reconciles a single DERP node with the controller. All Docker
// operations are checked against the node's ownership labels.
package agent

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ControllerURL, EnrollmentToken, ControllerCAFile string
	StateDir, ConfigDir, HostStateDir, HostConfigDir string
	DockerHost, DockerNetwork, NodeID                string
	DerperContainer, CaddyContainer                  string
	DerperImage, CaddyImage                          string
	AllowedImagePrefixes                             []string
	ManageContainers, PublishPorts                   bool
	PollInterval, HeartbeatInterval, HealthTimeout   time.Duration
}

func ConfigFromEnvironment() (Config, error) {
	c := Config{
		ControllerURL: os.Getenv("CONTROLLER_URL"), EnrollmentToken: os.Getenv("ENROLLMENT_TOKEN"),
		ControllerCAFile: os.Getenv("CONTROLLER_CA_FILE"), NodeID: os.Getenv("NODE_ID"),
		StateDir: env("STATE_DIR", "/var/lib/derpers-agent"), ConfigDir: env("CONFIG_DIR", "/node"),
		HostStateDir: os.Getenv("HOST_STATE_DIR"), HostConfigDir: os.Getenv("HOST_CONFIG_DIR"),
		DockerHost: env("DOCKER_HOST", "unix:///var/run/docker.sock"), DockerNetwork: os.Getenv("DOCKER_NETWORK"),
		DerperContainer: os.Getenv("DERPER_CONTAINER"), CaddyContainer: os.Getenv("CADDY_CONTAINER"),
		DerperImage: os.Getenv("DERPER_IMAGE"), CaddyImage: os.Getenv("CADDY_IMAGE"),
		AllowedImagePrefixes: strings.FieldsFunc(os.Getenv("ALLOWED_IMAGE_PREFIXES"), func(r rune) bool { return r == ',' }),
	}
	var err error
	for name, dst := range map[string]*bool{"MANAGE_CONTAINERS": &c.ManageContainers, "PUBLISH_NODE_PORTS": &c.PublishPorts} {
		*dst, err = strconv.ParseBool(env(name, "true"))
		if err != nil {
			return c, fmt.Errorf("%s must be true or false", name)
		}
	}
	for name, item := range map[string]struct {
		dst      *time.Duration
		fallback string
	}{
		"POLL_INTERVAL": {&c.PollInterval, "15s"}, "HEARTBEAT_INTERVAL": {&c.HeartbeatInterval, "15s"}, "HEALTH_TIMEOUT": {&c.HealthTimeout, "30s"},
	} {
		*item.dst, err = time.ParseDuration(env(name, item.fallback))
		if err != nil || *item.dst < time.Second {
			return c, fmt.Errorf("%s must be a duration of at least 1s", name)
		}
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	u, err := url.Parse(c.ControllerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("CONTROLLER_URL must be an HTTPS origin without userinfo, query or path")
	}
	if c.StateDir == "" || c.ConfigDir == "" {
		return errors.New("STATE_DIR and CONFIG_DIR are required")
	}
	if c.PollInterval <= 0 || c.HeartbeatInterval <= 0 || c.HealthTimeout <= 0 {
		return errors.New("poll, heartbeat and health durations must be positive")
	}
	if c.ManageContainers && (c.DockerNetwork == "" || !path.IsAbs(c.HostConfigDir) || !path.IsAbs(c.HostStateDir)) {
		return errors.New("manage mode requires DOCKER_NETWORK and absolute HOST_CONFIG_DIR/HOST_STATE_DIR bind paths")
	}
	for _, p := range []string{c.HostConfigDir, c.HostStateDir} {
		if strings.ContainsAny(p, "\r\n:") {
			return errors.New("host bind paths must be absolute Linux paths without colon or newline")
		}
	}
	return nil
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func atomicWrite(filename string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(filename), ".agent-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), filename); err != nil {
		return err
	}
	// Persist the rename on Linux. Some platforms do not support directory Sync.
	if dir, err := os.Open(filepath.Dir(filename)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}
