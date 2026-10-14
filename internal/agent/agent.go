package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/AS214933/derpers-contorller/internal/model"
)

type taskRecord struct {
	Task     model.Task       `json:"task"`
	Result   model.TaskResult `json:"result"`
	Reported bool             `json:"reported,omitempty"`
}
type diskState struct {
	Applied *model.NodeConfig     `json:"applied,omitempty"`
	Tasks   map[string]taskRecord `json:"tasks"`
}

type Agent struct {
	cfg               Config
	logger            *slog.Logger
	docker            *Docker
	bootstrap, client *http.Client
	identity          identity
	applied           *model.NodeConfig
	disk              diskState
	status            string
	nodeClient        atomic.Pointer[http.Client]
	heartbeatState    atomic.Pointer[model.Report]
}

func New(cfg Config, logger *slog.Logger) (*Agent, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	a := &Agent{cfg: cfg, logger: logger, disk: diskState{Tasks: map[string]taskRecord{}}, status: "starting"}
	for _, dir := range []string{cfg.StateDir, cfg.ConfigDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
	}
	data, err := os.ReadFile(filepath.Join(cfg.StateDir, "state.json"))
	if err == nil {
		if err := json.Unmarshal(data, &a.disk); err != nil {
			return nil, fmt.Errorf("invalid persisted agent state: %w", err)
		}
		a.applied = a.disk.Applied
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if a.disk.Tasks == nil {
		a.disk.Tasks = map[string]taskRecord{}
	}
	roots, _, err := a.tlsRoots()
	if err != nil {
		return nil, err
	}
	a.bootstrap = &http.Client{Timeout: 20 * time.Second, CheckRedirect: rejectRedirect, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, ForceAttemptHTTP2: true}}
	a.docker, err = NewDocker(cfg.DockerHost)
	if err != nil {
		return nil, err
	}
	loaded, err := a.loadIdentity()
	if err != nil {
		return nil, err
	}
	if loaded {
		if err := a.authenticatedClient(); err != nil {
			return nil, err
		}
	}
	initial := model.Report{Status: "starting", Metrics: map[string]float64{}}
	if a.applied != nil {
		initial.Revision = a.applied.Revision
	}
	a.cacheHeartbeat(initial)
	return a, nil
}

func (a *Agent) saveDisk() error {
	data, err := json.MarshalIndent(a.disk, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(a.cfg.StateDir, "state.json"), data, 0600)
}

func (a *Agent) Run(ctx context.Context) (runErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer a.bootstrap.CloseIdleConnections()
	for a.identity.NodeID == "" {
		if err := a.enroll(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if _, committed := os.Stat(filepath.Join(a.cfg.StateDir, "identity.json")); committed == nil {
				return fmt.Errorf("identity was committed but sidecar recovery is required: %w", err)
			}
			a.logger.Error("node enrollment failed", "error", a.safe(err.Error()))
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(5 * time.Second):
			}
		} else {
			a.logger.Info("node enrolled", "node_id", a.identity.NodeID)
		}
	}
	if time.Now().After(a.identity.Certificate.Leaf.NotAfter) {
		if a.cfg.EnrollmentToken == "" {
			return errors.New("node identity certificate expired; obtain a fresh enrollment token and re-enroll this node")
		}
		if err := a.enroll(ctx); err != nil {
			return fmt.Errorf("re-enroll expired node identity: %w", err)
		}
	}
	if a.cfg.ManageContainers {
		listener, err := net.Listen("tcp", ":9081")
		if err != nil {
			return fmt.Errorf("listen for private admission requests: %w", err)
		}
		relay, failures := a.startAdmissionRelay(listener, cancel)
		defer func() {
			shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if err := relay.Shutdown(shutdown); err != nil {
				_ = relay.Close()
				runErr = errors.Join(runErr, fmt.Errorf("stop private admission relay: %w", err))
			}
			select {
			case err := <-failures:
				runErr = errors.Join(runErr, err)
			default:
			}
		}()
	}
	if err := a.recover(ctx); err != nil {
		return err
	}
	poll := time.NewTicker(a.cfg.PollInterval)
	defer poll.Stop()
	heartbeatCtx, stopHeartbeat := context.WithCancel(ctx)
	heartbeatDone := make(chan struct{})
	go func() { defer close(heartbeatDone); a.keepalive(heartbeatCtx) }()
	defer func() { stopHeartbeat(); <-heartbeatDone }()
	a.synchronize(ctx)
	for {
		select {
		case <-ctx.Done():
			if a.client != nil {
				a.client.CloseIdleConnections()
			}
			return nil
		case <-poll.C:
			a.synchronize(ctx)
		}
	}
}

func (a *Agent) cacheHeartbeat(report model.Report) {
	copyReport := model.Report{Revision: report.Revision, Status: report.Status, Metrics: map[string]float64{}}
	for key, value := range report.Metrics {
		copyReport.Metrics[key] = value
	}
	a.heartbeatState.Store(&copyReport)
}

func (a *Agent) keepalive(ctx context.Context) {
	ticker := time.NewTicker(a.cfg.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			client, snapshot := a.nodeClient.Load(), a.heartbeatState.Load()
			if client == nil || snapshot == nil {
				continue
			}
			requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := a.request(requestCtx, client, http.MethodPost, "/node/v1/report", snapshot, nil)
			cancel()
			if err != nil && ctx.Err() == nil {
				a.logger.Warn("node heartbeat", "error", err)
			}
		}
	}
}

func (a *Agent) recover(ctx context.Context) (recoverErr error) {
	pendingPath := filepath.Join(a.cfg.StateDir, "configuration.pending.json")
	pendingData, pendingErr := os.ReadFile(pendingPath)
	defer func() {
		if recoverErr != nil && pendingErr == nil {
			if err := atomicWrite(pendingPath, pendingData, 0600); err != nil {
				recoverErr = errors.Join(recoverErr, fmt.Errorf("retain recovery journal: %w", err))
			}
		}
	}()
	if err := a.recoverConfiguration(); err != nil {
		return err
	}
	if a.applied != nil {
		if err := a.validateNodeConfig(*a.applied); err != nil {
			if a.applied.NodeID != a.identity.NodeID {
				return fmt.Errorf("persisted node config: %w", err)
			}
			a.logger.Warn("stored node configuration requires refresh", "error", a.safe(err.Error()))
		} else {
			files, err := a.configurationFiles(*a.applied)
			if err != nil {
				return err
			}
			if _, err := applyFiles(files); err != nil {
				return err
			}
		}
		if a.cfg.ManageContainers {
			for _, component := range []string{"caddy", "derper"} {
				if err := a.docker.RecoverReplacement(ctx, a.componentName(component), a.identity.NodeID, "reconcile"); err != nil {
					return err
				}
			}
		}
	}
	for id, record := range a.disk.Tasks {
		if record.Result.Status != "running" {
			continue
		}
		var payload taskPayload
		if json.Unmarshal(record.Task.Payload, &payload) == nil && record.Task.Type == "upgrade" && a.cfg.ManageContainers && (payload.Component == "caddy" || payload.Component == "derper") {
			if err := a.docker.RecoverReplacement(ctx, a.componentName(payload.Component), a.identity.NodeID, id); err != nil {
				return err
			}
		}
		record.Result.Status = "failed"
		record.Result.Message = "agent restarted during task; recovery attempted; operation not repeated"
		a.disk.Tasks[id] = record
	}
	return a.saveDisk()
}

func (a *Agent) synchronize(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	if err := a.renew(ctx); err != nil {
		a.logger.Error("renew node identity", "error", a.safe(err.Error()))
	}
	// Read the pending task snapshot first. A desired-image update and its
	// upgrade task form one controller transaction; do not let background
	// reconciliation bypass that task's rollback/outcome tracking.
	var tasks []model.Task
	tasksErr := a.request(ctx, a.client, http.MethodGet, "/node/v1/tasks", nil, &tasks)
	var config model.NodeConfig
	err := tasksErr
	if err == nil {
		err = a.request(ctx, a.client, http.MethodGet, "/node/v1/config", nil, &config)
	}
	if err == nil {
		if a.applied != nil && config.Revision < a.applied.Revision {
			err = errors.New("controller returned an older configuration revision")
		} else {
			err = a.applyConfigurationWithTasks(ctx, config, tasks)
		}
	}
	if err != nil {
		var rollbackErr *rollbackFailure
		if errors.As(err, &rollbackErr) {
			a.status = "rollback_failed"
		} else {
			a.status = "degraded"
		}
		a.logger.Error("reconcile node configuration", "error", a.safe(err.Error()))
	} else {
		a.status = "ready"
	}
	if tasksErr == nil {
		for _, task := range tasks {
			if ctx.Err() != nil {
				break
			}
			if task.Type != "upgrade" {
				a.executeTask(ctx, task)
			}
		}
	}
	a.report(ctx)
}

func (a *Agent) report(ctx context.Context) {
	if a.client == nil || ctx.Err() != nil {
		return
	}
	report := model.Report{Status: a.status, Metrics: map[string]float64{}}
	if a.applied != nil {
		report.Revision = a.applied.Revision
		for _, component := range []string{"caddy", "derper"} {
			statsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			info, err := a.docker.Inspect(statsCtx, a.componentName(component), a.identity.NodeID)
			report.Metrics[component+"_process_up"] = 0
			var stats map[string]float64
			if err == nil && info.State.Running {
				report.Metrics[component+"_process_up"] = 1
				stats, err = a.docker.Stats(statsCtx, a.componentName(component), a.identity.NodeID)
			}
			cancel()
			if err == nil {
				for key, value := range stats {
					report.Metrics[component+"_"+key] = value
				}
			}
		}
		report.Metrics["derper_up"] = 0
		probeCtx, stopProbe := context.WithTimeout(ctx, 3*time.Second)
		if a.probeRelay(probeCtx, *a.applied) == nil {
			report.Metrics["derper_up"] = 1
		}
		stopProbe()
		report.Metrics["derper_probe_timestamp_seconds"] = float64(time.Now().Unix())
		report.Metrics["derper_metrics_up"] = 0
		metricsCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		text, err := a.docker.Exec(metricsCtx, a.derperName(), a.identity.NodeID, []string{"/usr/local/bin/derper-entrypoint", "metrics"})
		cancel()
		if err == nil {
			report.Metrics["derper_metrics_up"] = 1
			parsed := parseMetrics(text)
			keys := make([]string, 0, len(parsed))
			for key := range parsed {
				if strings.HasPrefix(key, "derp_") {
					keys = append(keys, key)
				}
			}
			sort.Strings(keys)
			for _, key := range keys {
				if len(report.Metrics) >= 64 {
					break
				}
				report.Metrics["derper_"+key] = parsed[key]
			}
		}
	}
	ids := make([]string, 0, len(a.disk.Tasks))
	for id := range a.disk.Tasks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	resultBytes := 0
	for _, id := range ids {
		record := a.disk.Tasks[id]
		if record.Result.Status != "running" && !record.Reported {
			encoded, _ := json.Marshal(record.Result)
			if len(report.Results) >= 100 || resultBytes+len(encoded) > 512<<10 {
				break
			}
			report.Results = append(report.Results, record.Result)
			resultBytes += len(encoded)
		}
	}
	a.cacheHeartbeat(report)
	if err := a.request(ctx, a.client, http.MethodPost, "/node/v1/report", report, nil); err != nil {
		a.logger.Warn("report node status", "error", a.safe(err.Error()))
	} else if len(report.Results) > 0 {
		for _, result := range report.Results {
			record := a.disk.Tasks[result.TaskID]
			record.Reported = true
			record.Result.Logs = ""
			a.disk.Tasks[result.TaskID] = record
		}
		if err := a.saveDisk(); err != nil {
			a.logger.Error("persist report acknowledgement", "error", err)
		}
	}
}

func (a *Agent) safe(text string) string {
	for _, secret := range []string{a.cfg.EnrollmentToken, string(a.identity.PrivatePEM)} {
		if secret != "" {
			text = strings.ReplaceAll(text, secret, "[REDACTED]")
		}
	}
	if a.applied != nil && a.applied.CertificateKeyPEM != "" {
		text = strings.ReplaceAll(text, a.applied.CertificateKeyPEM, "[REDACTED]")
	}
	text = secretPattern.ReplaceAllString(text, "$1[REDACTED]")
	text = privateKeyPattern.ReplaceAllString(text, "[REDACTED PRIVATE KEY]")
	if len(text) > 256<<10 {
		text = text[:256<<10] + "\n[output truncated]"
	}
	return text
}
