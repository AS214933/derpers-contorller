package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/AS214933/derpers-contorller/internal/model"
)

type taskPayload struct {
	Component      string `json:"component"`
	Image          string `json:"image"`
	Tail           int    `json:"tail"`
	TargetRevision int64  `json:"target_revision"`
	PreviousImage  string `json:"previous_image"`
}

func (a *Agent) applyConfigurationWithTasks(ctx context.Context, config model.NodeConfig, tasks []model.Task) error {
	prepared := []string{}
	var blocked error
	for _, task := range tasks {
		if task.Type != "upgrade" || task.NodeID != a.identity.NodeID || task.ID == "" || (task.Status != "pending" && task.Status != "running") {
			continue
		}
		var payload taskPayload
		decodeErr := json.Unmarshal(task.Payload, &payload)
		desired := ""
		if payload.Component == "derper" {
			desired = config.DerperImage
		} else if payload.Component == "caddy" {
			desired = config.CaddyImage
		}
		if record, exists := a.disk.Tasks[task.ID]; exists {
			if record.Reported {
				record.Reported = false
				a.disk.Tasks[task.ID] = record
			}
			if record.Result.Status == "failed" && desired == payload.Image {
				blocked = errors.New("failed upgrade awaits controller rollback")
			}
			continue
		}
		record := taskRecord{Task: task, Result: model.TaskResult{TaskID: task.ID, Status: "running"}}
		var invalid error
		switch {
		case decodeErr != nil || desired == "":
			invalid = errors.New("invalid upgrade task payload")
		case payload.TargetRevision > config.Revision:
			invalid = errors.New("upgrade task is newer than configuration snapshot")
		case desired != payload.Image:
			invalid = errors.New("upgrade superseded by a newer desired image")
		case !a.cfg.ManageContainers:
			invalid = errors.New("container management is disabled")
		case a.applied == nil:
			invalid = errors.New("node must apply an initial configuration before upgrade")
		case !a.allowedUpgrade(payload.Image, payload.Component):
			invalid = errors.New("upgrade requires an allowed repository and sha256 digest")
		}
		if invalid != nil {
			record.Result.Status = "failed"
			record.Result.Message = invalid.Error()
			if desired == payload.Image {
				blocked = invalid
			}
		} else {
			prepared = append(prepared, task.ID)
		}
		a.disk.Tasks[task.ID] = record
	}
	if err := a.saveDisk(); err != nil {
		return fmt.Errorf("persist upgrade transaction: %w", err)
	}
	if blocked != nil {
		for _, id := range prepared {
			record := a.disk.Tasks[id]
			record.Result.Status = "failed"
			record.Result.Message = "configuration transaction blocked by another invalid upgrade"
			a.disk.Tasks[id] = record
		}
		_ = a.saveDisk()
		return blocked
	}
	err := a.applyConfig(ctx, config)
	for _, id := range prepared {
		record := a.disk.Tasks[id]
		if err != nil {
			record.Result.Status = "failed"
			record.Result.Message = a.safe("upgrade failed and previous configuration restored: " + err.Error())
		} else {
			record.Result.Status = "succeeded"
			record.Result.Message = "desired image and configuration applied and health checked"
		}
		a.disk.Tasks[id] = record
	}
	if saveErr := a.saveDisk(); saveErr != nil {
		return errors.Join(err, saveErr)
	}
	return err
}

var secretPattern = regexp.MustCompile(`(?i)((?:bearer|client_secret|authorization|password|access_token|refresh_token|tskey-[a-z]+)\s*[=:" ]+)[^\s",}]+`)
var privateKeyPattern = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)

func (a *Agent) executeTask(ctx context.Context, task model.Task) {
	if task.ID == "" || task.NodeID != a.identity.NodeID {
		a.logger.Warn("ignored task with invalid identity")
		return
	}
	if task.Status != "" && task.Status != "pending" && task.Status != "running" {
		return
	}
	if record, done := a.disk.Tasks[task.ID]; done {
		// The controller can redeliver an old pending snapshot after an accepted
		// report. Replay its outcome, never the command.
		if record.Reported {
			record.Reported = false
			a.disk.Tasks[task.ID] = record
		}
		return
	}
	record := taskRecord{Task: task, Result: model.TaskResult{TaskID: task.ID, Status: "running"}}
	a.disk.Tasks[task.ID] = record
	if err := a.saveDisk(); err != nil {
		delete(a.disk.Tasks, task.ID)
		a.logger.Error("persist task before execution", "error", err)
		return
	}
	err := a.performTask(ctx, task, &record.Result)
	if err != nil {
		record.Result.Status = "failed"
		record.Result.Message = a.safe(err.Error())
	} else {
		record.Result.Status = "succeeded"
		if record.Result.Message == "" {
			record.Result.Message = "completed"
		}
	}
	a.disk.Tasks[task.ID] = record
	if err := a.saveDisk(); err != nil {
		a.logger.Error("persist task result", "task_id", task.ID, "error", err)
	}
	a.logger.Info("node task finished", "task_id", task.ID, "type", task.Type, "status", record.Result.Status)
}

func (a *Agent) performTask(ctx context.Context, task model.Task, result *model.TaskResult) error {
	var payload taskPayload
	if err := json.Unmarshal(task.Payload, &payload); err != nil {
		return errors.New("invalid task payload")
	}
	if payload.Component != "derper" && payload.Component != "caddy" {
		return errors.New("task component must be derper or caddy")
	}
	if a.applied == nil {
		return errors.New("no configuration has been successfully applied")
	}
	name := a.componentName(payload.Component)
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	switch task.Type {
	case "logs":
		logs, err := a.docker.Logs(ctx, name, a.identity.NodeID, payload.Tail)
		if err != nil {
			return err
		}
		result.Logs = a.safe(logs)
		if len(result.Logs) > 64<<10 {
			result.Logs = result.Logs[:64<<10] + "\n[output truncated]"
		}
		return nil
	case "restart":
		if !a.cfg.ManageContainers {
			return errors.New("container management is disabled")
		}
		if err := a.docker.Restart(ctx, name, a.identity.NodeID); err != nil {
			return err
		}
		return a.healthCheck(payload.Component, *a.applied)(ctx)
	case "upgrade":
		if !a.cfg.ManageContainers {
			return errors.New("container management is disabled")
		}
		if !a.allowedUpgrade(payload.Image, payload.Component) {
			return errors.New("upgrade requires an allowed repository and an explicit sha256 digest")
		}
		if err := a.docker.Upgrade(ctx, name, a.identity.NodeID, task.ID, payload.Image, a.healthCheck(payload.Component, *a.applied)); err != nil {
			return fmt.Errorf("upgrade failed; previous container retained/restored: %w", err)
		}
		return nil
	default:
		return errors.New("unsupported task type")
	}
}

func imageRepository(image string) string {
	image = strings.SplitN(image, "@", 2)[0]
	if colon := strings.LastIndex(image, ":"); colon > strings.LastIndex(image, "/") {
		image = image[:colon]
	}
	return image
}

func (a *Agent) allowedUpgrade(image, component string) bool {
	if !imagePattern.MatchString(image) || !digestPattern.MatchString(image) {
		return false
	}
	repo := imageRepository(image)
	allowed := append([]string{}, a.cfg.AllowedImagePrefixes...)
	allowed = append(allowed, "ghcr.io/as214933/derpers-contorller-derper", "docker.io/library/caddy", "caddy")
	if a.applied != nil {
		if component == "caddy" {
			allowed = append(allowed, imageRepository(a.applied.CaddyImage))
		} else {
			allowed = append(allowed, imageRepository(a.applied.DerperImage))
		}
	}
	for _, prefix := range allowed {
		prefix = strings.TrimSpace(prefix)
		if prefix != "" && (repo == prefix || strings.HasPrefix(repo, strings.TrimRight(prefix, "/")+"/")) {
			return true
		}
	}
	return false
}

func (a *Agent) knownRollbackImage(image, component string) bool {
	if a.applied == nil {
		return false
	}
	current := a.applied.DerperImage
	if component == "caddy" {
		current = a.applied.CaddyImage
	}
	for _, record := range a.disk.Tasks {
		if record.Task.Type != "upgrade" || record.Result.Status != "failed" {
			continue
		}
		var payload taskPayload
		if json.Unmarshal(record.Task.Payload, &payload) == nil && payload.Component == component && payload.Image == current && payload.PreviousImage == image && image != "" {
			return true
		}
	}
	return false
}

func parseMetrics(body string) map[string]float64 {
	metrics := map[string]float64{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		if bracket := strings.IndexByte(name, '{'); bracket >= 0 {
			name = name[:bracket]
		}
		if !regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`).MatchString(name) {
			continue
		}
		value, err := strconv.ParseFloat(fields[1], 64)
		if err == nil && !math.IsNaN(value) && !math.IsInf(value, 0) {
			metrics[name] += value
		}
	}
	return metrics
}
