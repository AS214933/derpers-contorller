package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var errDockerNotFound = errors.New("docker object not found")

type Docker struct {
	client  *http.Client
	baseURL string
}

type containerConfig struct {
	Image        string              `json:"Image"`
	Cmd          []string            `json:"Cmd,omitempty"`
	Entrypoint   []string            `json:"Entrypoint,omitempty"`
	Env          []string            `json:"Env,omitempty"`
	Labels       map[string]string   `json:"Labels"`
	ExposedPorts map[string]struct{} `json:"ExposedPorts,omitempty"`
	User         string              `json:"User,omitempty"`
	WorkingDir   string              `json:"WorkingDir,omitempty"`
	Volumes      map[string]struct{} `json:"Volumes,omitempty"`
	StopSignal   string              `json:"StopSignal,omitempty"`
}

type endpoint struct {
	Aliases []string `json:"Aliases"`
}

type containerSpec struct {
	containerConfig
	HostConfig       map[string]any `json:"HostConfig"`
	NetworkingConfig struct {
		EndpointsConfig map[string]endpoint `json:"EndpointsConfig"`
	} `json:"NetworkingConfig"`
}

type containerInfo struct {
	ID              string          `json:"Id"`
	Name            string          `json:"Name"`
	Config          containerConfig `json:"Config"`
	HostConfig      map[string]any  `json:"HostConfig"`
	NetworkSettings struct {
		Networks map[string]endpoint `json:"Networks"`
	} `json:"NetworkSettings"`
	State struct {
		Running  bool   `json:"Running"`
		Status   string `json:"Status"`
		ExitCode int    `json:"ExitCode"`
		Health   *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
}

func NewDocker(host string) (*Docker, error) {
	u, err := url.Parse(host)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{MaxIdleConns: 10, IdleConnTimeout: 60 * time.Second}
	base := "http://docker/v1.47"
	switch u.Scheme {
	case "unix":
		if u.Path == "" {
			return nil, errors.New("empty Docker socket path")
		}
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", u.Path)
		}
	case "tcp", "http":
		// Plain TCP Engine APIs are only supported on loopback; a Unix socket is
		// required for a containerized production node.
		hostname := u.Hostname()
		if hostname != "localhost" && (net.ParseIP(hostname) == nil || !net.ParseIP(hostname).IsLoopback()) {
			return nil, errors.New("unencrypted Docker TCP endpoints must be loopback")
		}
		base = "http://" + u.Host + "/v1.47"
	default:
		return nil, errors.New("DOCKER_HOST must be unix:// or loopback tcp://")
	}
	return &Docker{client: &http.Client{Transport: transport, Timeout: 3 * time.Minute}, baseURL: base}, nil
}

func (d *Docker) call(ctx context.Context, method, route string, body any) (*http.Response, error) {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, d.baseURL+route, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, errDockerNotFound
	}
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotModified {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("Docker %s %s: HTTP %d %s", method, route, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return resp, nil
}

func (d *Docker) action(ctx context.Context, method, route string, body any) error {
	resp, err := d.call(ctx, method, route, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return err
}

func (d *Docker) Inspect(ctx context.Context, name, nodeID string) (containerInfo, error) {
	var out containerInfo
	resp, err := d.call(ctx, http.MethodGet, "/containers/"+url.PathEscape(name)+"/json", nil)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&out); err != nil {
		return out, err
	}
	if out.Config.Labels["derpers.node_id"] != nodeID || (out.Config.Labels["derpers.component"] != "derper" && out.Config.Labels["derpers.component"] != "caddy") {
		return out, errors.New("refusing to manage a container without this node's ownership labels")
	}
	return out, nil
}

func (d *Docker) ensureImage(ctx context.Context, image string) error {
	resp, err := d.call(ctx, http.MethodGet, "/images/"+url.PathEscape(image)+"/json", nil)
	if err == nil {
		resp.Body.Close()
		return nil
	}
	if !errors.Is(err, errDockerNotFound) {
		return err
	}
	resp, err = d.call(ctx, http.MethodPost, "/images/create?fromImage="+url.QueryEscape(image), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 16<<20))
	for {
		var progress struct {
			Error string `json:"error"`
		}
		err := decoder.Decode(&progress)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if progress.Error != "" {
			return fmt.Errorf("pull image: %s", progress.Error)
		}
	}
}

func (d *Docker) create(ctx context.Context, name string, spec containerSpec) error {
	return d.action(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(name), spec)
}

func (d *Docker) start(ctx context.Context, name string) error {
	return d.action(ctx, http.MethodPost, "/containers/"+url.PathEscape(name)+"/start", nil)
}

func (d *Docker) Restart(ctx context.Context, name, nodeID string) error {
	if _, err := d.Inspect(ctx, name, nodeID); err != nil {
		return err
	}
	return d.action(ctx, http.MethodPost, "/containers/"+url.PathEscape(name)+"/restart?t=10", nil)
}

func (d *Docker) Ensure(ctx context.Context, name, nodeID string, spec containerSpec, health func(context.Context) error) error {
	current, err := d.Inspect(ctx, name, nodeID)
	if errors.Is(err, errDockerNotFound) {
		if err := d.ensureImage(ctx, spec.Image); err != nil {
			return err
		}
		if err := d.create(ctx, name, spec); err != nil {
			return err
		}
		if err := d.start(ctx, name); err != nil {
			return err
		}
		return health(ctx)
	}
	if err != nil {
		return err
	}
	if current.Config.Image == spec.Image && current.Config.Labels["derpers.spec_hash"] == spec.Labels["derpers.spec_hash"] {
		if !current.State.Running {
			if err := d.start(ctx, name); err != nil {
				return err
			}
		}
		return health(ctx)
	}
	return d.replace(ctx, name, nodeID, "reconcile", spec, health)
}

// replace keeps the stopped original container until the replacement has passed
// health checks. The predictable backup name also permits crash recovery.
func (d *Docker) replace(ctx context.Context, name, nodeID, taskID string, spec containerSpec, health func(context.Context) error) (err error) {
	if err := d.ensureImage(ctx, spec.Image); err != nil {
		return err
	}
	if _, err := d.Inspect(ctx, name, nodeID); err != nil {
		return err
	}
	backup := backupName(name, taskID)
	if _, err := d.Inspect(ctx, backup, nodeID); err == nil {
		return errors.New("an earlier container replacement needs recovery")
	} else if !errors.Is(err, errDockerNotFound) {
		return err
	}
	if err := d.action(ctx, http.MethodPost, "/containers/"+url.PathEscape(name)+"/stop?t=10", nil); err != nil {
		return err
	}
	if err := d.action(ctx, http.MethodPost, "/containers/"+url.PathEscape(name)+"/rename?name="+url.QueryEscape(backup), nil); err != nil {
		_ = d.start(ctx, name)
		return err
	}
	defer func() {
		if err == nil {
			return
		}
		recoveryCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		if restoreErr := d.RecoverReplacement(recoveryCtx, name, nodeID, taskID); restoreErr != nil {
			err = fmt.Errorf("%w; rollback failed: %v", err, restoreErr)
		}
	}()
	if err = d.create(ctx, name, spec); err != nil {
		return err
	}
	if err = d.start(ctx, name); err != nil {
		return err
	}
	if err = health(ctx); err != nil {
		return err
	}
	if err = d.action(ctx, http.MethodDelete, "/containers/"+url.PathEscape(backup)+"?force=true", nil); err != nil {
		return err
	}
	return nil
}

func backupName(name, taskID string) string {
	// Task IDs are never interpreted as shell commands or arbitrary paths.
	var suffix strings.Builder
	for _, r := range taskID {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			suffix.WriteRune(r)
		}
	}
	s := suffix.String()
	if len(s) > 32 {
		s = s[:32]
	}
	if s == "" {
		s = "task"
	}
	return name + "-rollback-" + s
}

func (d *Docker) RecoverReplacement(ctx context.Context, name, nodeID, taskID string) error {
	backup := backupName(name, taskID)
	if _, err := d.Inspect(ctx, backup, nodeID); errors.Is(err, errDockerNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	if _, err := d.Inspect(ctx, name, nodeID); err == nil {
		if err := d.action(ctx, http.MethodDelete, "/containers/"+url.PathEscape(name)+"?force=true", nil); err != nil {
			return err
		}
	} else if !errors.Is(err, errDockerNotFound) {
		return err
	}
	if err := d.action(ctx, http.MethodPost, "/containers/"+url.PathEscape(backup)+"/rename?name="+url.QueryEscape(name), nil); err != nil {
		return err
	}
	return d.start(ctx, name)
}

func (d *Docker) Upgrade(ctx context.Context, name, nodeID, taskID, image string, health func(context.Context) error) error {
	current, err := d.Inspect(ctx, name, nodeID)
	if err != nil {
		return err
	}
	if current.Config.Image == image && current.State.Running {
		return health(ctx)
	}
	spec := containerSpec{containerConfig: current.Config, HostConfig: current.HostConfig}
	spec.Image = image
	spec.NetworkingConfig.EndpointsConfig = current.NetworkSettings.Networks
	return d.replace(ctx, name, nodeID, taskID, spec, health)
}

func (d *Docker) Logs(ctx context.Context, name, nodeID string, tail int) (string, error) {
	if _, err := d.Inspect(ctx, name, nodeID); err != nil {
		return "", err
	}
	if tail < 1 {
		tail = 200
	}
	if tail > 2000 {
		tail = 2000
	}
	resp, err := d.call(ctx, http.MethodGet, "/containers/"+url.PathEscape(name)+"/logs?stdout=true&stderr=true&timestamps=true&tail="+strconv.Itoa(tail), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	return readDockerStream(io.LimitReader(resp.Body, 2<<20))
}

func readDockerStream(reader io.Reader) (string, error) {
	buffered := bufio.NewReader(reader)
	first, err := buffered.Peek(8)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	// Docker multiplexes stdout/stderr unless TTY is enabled. Also support plain
	// log streams, as some logging drivers return unframed text.
	if len(first) < 8 || first[0] > 2 || first[1] != 0 || first[2] != 0 || first[3] != 0 {
		data, err := io.ReadAll(buffered)
		return string(data), err
	}
	var out bytes.Buffer
	for {
		var header [8]byte
		_, err := io.ReadFull(buffered, header[:])
		if errors.Is(err, io.EOF) {
			return out.String(), nil
		}
		if err != nil {
			return out.String(), err
		}
		n := binary.BigEndian.Uint32(header[4:])
		if n > 2<<20 || out.Len()+int(n) > 2<<20 {
			return out.String(), errors.New("Docker output exceeds 2 MiB limit")
		}
		if _, err := io.CopyN(&out, buffered, int64(n)); err != nil {
			return out.String(), err
		}
	}
}

func (d *Docker) Exec(ctx context.Context, name, nodeID string, command []string) (string, error) {
	if _, err := d.Inspect(ctx, name, nodeID); err != nil {
		return "", err
	}
	resp, err := d.call(ctx, http.MethodPost, "/containers/"+url.PathEscape(name)+"/exec", map[string]any{"AttachStdout": true, "AttachStderr": true, "Cmd": command})
	if err != nil {
		return "", err
	}
	var exec struct {
		ID string `json:"Id"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&exec)
	resp.Body.Close()
	if err != nil {
		return "", err
	}
	resp, err = d.call(ctx, http.MethodPost, "/exec/"+url.PathEscape(exec.ID)+"/start", map[string]any{"Detach": false, "Tty": false})
	if err != nil {
		return "", err
	}
	out, err := readDockerStream(io.LimitReader(resp.Body, 2<<20))
	resp.Body.Close()
	if err != nil {
		return "", err
	}
	resp, err = d.call(ctx, http.MethodGet, "/exec/"+url.PathEscape(exec.ID)+"/json", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var result struct {
		ExitCode int  `json:"ExitCode"`
		Running  bool `json:"Running"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if result.Running || result.ExitCode != 0 {
		return out, fmt.Errorf("container command exited with status %d", result.ExitCode)
	}
	return out, nil
}

func (d *Docker) Stats(ctx context.Context, name, nodeID string) (map[string]float64, error) {
	if _, err := d.Inspect(ctx, name, nodeID); err != nil {
		return nil, err
	}
	resp, err := d.call(ctx, http.MethodGet, "/containers/"+url.PathEscape(name)+"/stats?stream=false&one-shot=true", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var stats struct {
		Memory struct{ Usage, Limit float64 } `json:"memory_stats"`
		CPU    struct {
			CPUUsage struct {
				Total float64 `json:"total_usage"`
			} `json:"cpu_usage"`
		} `json:"cpu_stats"`
		Networks map[string]struct {
			RX float64 `json:"rx_bytes"`
			TX float64 `json:"tx_bytes"`
		} `json:"networks"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&stats); err != nil {
		return nil, err
	}
	metrics := map[string]float64{"memory_bytes": stats.Memory.Usage, "memory_limit_bytes": stats.Memory.Limit, "cpu_seconds_total": stats.CPU.CPUUsage.Total / 1e9}
	for _, network := range stats.Networks {
		metrics["received_bytes_total"] += network.RX
		metrics["sent_bytes_total"] += network.TX
	}
	return metrics, nil
}
