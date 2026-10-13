package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AS214933/derpers-contorller/internal/model"
	"github.com/AS214933/derpers-contorller/internal/store"
)

func taskNode(t *testing.T, a *App) model.Node {
	t.Helper()
	cert, key, _ := testCertificate(t, "task-node.example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	n, err := a.AddNode(context.Background(), model.Node{Name: "task-node", Hostname: "task-node.example.test", RegionID: 900, HTTPSPort: 443, STUNPort: 3478}, map[string]string{"certificate_pem": cert, "certificate_key_pem": key})
	if err != nil {
		t.Fatal(err)
	}
	return n
}
func currentTaskNode(t *testing.T, a *App, id string) model.Node {
	t.Helper()
	record, err := a.Store.Get(context.Background(), "node", id)
	if err != nil {
		t.Fatal(err)
	}
	n, err := store.Decode[model.Node](record)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
func upgradeTask(n model.Node, image string) model.Task {
	payload, _ := json.Marshal(map[string]any{"component": "derper", "image": image, "previous_image": n.DerperImage, "target_revision": n.Revision + 1})
	return model.Task{ID: store.ID(), NodeID: n.ID, Type: "upgrade", Status: "pending", Payload: payload, CreatedAt: time.Now().UTC()}
}

func TestIntegrationUpgradeQueueIsAtomicAndCASProtected(t *testing.T) {
	a := integrationApp(t)
	ctx := context.Background()
	n := taskNode(t, a)
	task := upgradeTask(n, "ghcr.io/example/derper@sha256:"+strings.Repeat("a", 64))
	// A task ID conflict occurs after the transaction's desired-state UPDATE.
	// Neither the image nor its revision may escape when INSERT fails.
	if err := a.Store.Save(ctx, "task", task.ID, "", 1, model.Task{ID: task.ID, NodeID: n.ID, Type: "logs", Status: "succeeded"}, nil); err != nil {
		t.Fatal(err)
	}
	updated := n
	updated.Revision++
	updated.DerperImage = "ghcr.io/example/derper@sha256:" + strings.Repeat("a", 64)
	if err := a.Store.QueueNodeTask(ctx, updated, task); err == nil {
		t.Fatal("duplicate task ID was accepted")
	}
	got := currentTaskNode(t, a, n.ID)
	if got.Revision != n.Revision || got.DerperImage != n.DerperImage {
		t.Fatalf("partial upgrade transaction escaped: %+v", got)
	}
	first, second := upgradeTask(n, updated.DerperImage), upgradeTask(n, updated.DerperImage)
	start := make(chan struct{})
	outcomes := make(chan error, 2)
	var workers sync.WaitGroup
	for _, candidate := range []model.Task{first, second} {
		workers.Add(1)
		go func(task model.Task) {
			defer workers.Done()
			<-start
			outcomes <- a.Store.QueueNodeTask(ctx, updated, task)
		}(candidate)
	}
	close(start)
	workers.Wait()
	close(outcomes)
	successes, conflicts := 0, 0
	for err := range outcomes {
		if err == nil {
			successes++
		} else if errors.Is(err, store.ErrConflict) {
			conflicts++
		} else {
			t.Fatalf("unexpected queue error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent queue results success=%d conflict=%d", successes, conflicts)
	}
	got = currentTaskNode(t, a, n.ID)
	if got.Revision != 2 || got.DerperImage != updated.DerperImage {
		t.Fatalf("desired state not committed atomically: %+v", got)
	}
	var pending int
	if err := a.Store.Pool.QueryRow(ctx, "SELECT count(*) FROM resources WHERE kind='task' AND data->>'type'='upgrade' AND data->>'status'='pending'").Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 1 {
		t.Fatalf("queued %d pending upgrades", pending)
	}
}

func TestIntegrationHeartbeatIsMonotonicAndSurvivesConfigSave(t *testing.T) {
	a := integrationApp(t)
	ctx := context.Background()
	n := taskNode(t, a)
	// An administrator loaded this old snapshot before the Agent's report.
	stale := n
	if err := a.Store.ReportNode(ctx, n.ID, model.Report{Revision: 1, Status: "ready", Metrics: map[string]float64{"derper_bytes_sent": 222}}); err != nil {
		t.Fatal(err)
	}
	stale.Name = "renamed-by-admin"
	stale.Revision = 2
	if err := a.Store.Save(ctx, "node", n.ID, "", 2, stale, nil); err != nil {
		t.Fatal(err)
	}
	got := currentTaskNode(t, a, n.ID)
	if got.Name != stale.Name || got.LastSeen == nil || got.AppliedRevision != 1 || got.Status != "ready" || got.Metrics["derper_bytes_sent"] != 222 {
		t.Fatalf("stale configuration save erased heartbeat: %+v", got)
	}
	if err := a.Store.ReportNode(ctx, n.ID, model.Report{Revision: 2, Status: "ready"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.ReportNode(ctx, n.ID, model.Report{Revision: 1, Status: "degraded"}); err != nil {
		t.Fatal(err)
	}
	got = currentTaskNode(t, a, n.ID)
	if got.AppliedRevision != 2 || got.Status != "ready" {
		t.Fatalf("late heartbeat regressed state: %+v", got)
	}
	if err := a.Store.ReportNode(ctx, n.ID, model.Report{Revision: 3, Status: "ready"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("future revision was accepted: %v", err)
	}
	// Ordinary configuration CAS also permits exactly one concurrent writer.
	base := got
	start := make(chan struct{})
	outcomes := make(chan error, 2)
	var workers sync.WaitGroup
	for _, name := range []string{"writer-a", "writer-b"} {
		workers.Add(1)
		go func(name string) {
			defer workers.Done()
			candidate := base
			candidate.Name = name
			candidate.Revision++
			<-start
			outcomes <- a.Store.Save(ctx, "node", candidate.ID, "", candidate.Revision, candidate, nil)
		}(name)
	}
	close(start)
	workers.Wait()
	close(outcomes)
	successes, conflicts := 0, 0
	for err := range outcomes {
		if err == nil {
			successes++
		} else if errors.Is(err, store.ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("configuration CAS success=%d conflict=%d", successes, conflicts)
	}
}

func TestIntegrationUpgradeFailureRollbackIsIdempotent(t *testing.T) {
	a := integrationApp(t)
	ctx := context.Background()
	n := taskNode(t, a)
	image := "ghcr.io/example/derper@sha256:" + strings.Repeat("a", 64)
	task := upgradeTask(n, image)
	updated := n
	updated.Revision++
	updated.DerperImage = image
	if err := a.Store.QueueNodeTask(ctx, updated, task); err != nil {
		t.Fatal(err)
	}
	result := model.TaskResult{TaskID: task.ID, Status: "failed", Message: "new image failed health check; original restored"}
	for range 2 {
		if err := a.Store.CompleteNodeTask(ctx, task, result); err != nil {
			t.Fatal(err)
		}
	}
	got := currentTaskNode(t, a, n.ID)
	if got.Revision != 3 || got.DerperImage != n.DerperImage {
		t.Fatalf("rollback was missing or repeated: %+v", got)
	}
	record, err := a.Store.Get(ctx, "task", task.ID)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := store.Decode[model.Task](record)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != "failed" || completed.Message != result.Message {
		t.Fatalf("task completion not committed: %+v", completed)
	}
}

func TestIntegrationOldFailedUpgradeCannotReplaceNewDesiredImage(t *testing.T) {
	a := integrationApp(t)
	ctx := context.Background()
	n := taskNode(t, a)
	imageA := "ghcr.io/example/derper@sha256:" + strings.Repeat("a", 64)
	imageB := "ghcr.io/example/derper@sha256:" + strings.Repeat("b", 64)
	task := upgradeTask(n, imageA)
	updated := n
	updated.Revision++
	updated.DerperImage = imageA
	if err := a.Store.QueueNodeTask(ctx, updated, task); err != nil {
		t.Fatal(err)
	}
	newer := currentTaskNode(t, a, n.ID)
	newer.Revision++
	newer.DerperImage = imageB
	if err := a.Store.Save(ctx, "node", n.ID, "", newer.Revision, newer, nil); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.CompleteNodeTask(ctx, task, model.TaskResult{TaskID: task.ID, Status: "failed"}); err != nil {
		t.Fatal(err)
	}
	got := currentTaskNode(t, a, n.ID)
	if got.Revision != 3 || got.DerperImage != imageB {
		t.Fatalf("old failure overwrote newer desired image: %+v", got)
	}
}

func TestIntegrationDisabledNodeRejectsAgentTasks(t *testing.T) {
	a := integrationApp(t)
	ctx := context.Background()
	n := taskNode(t, a)
	disabled := n
	disabled.Enabled = false
	disabled.Revision++
	if err := a.Store.Save(ctx, "node", n.ID, "", disabled.Revision, disabled, nil); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"restart", "logs", "upgrade"} {
		t.Run(kind, func(t *testing.T) {
			payload, _ := json.Marshal(map[string]any{"component": "derper", "image": "ghcr.io/example/derper@sha256:" + strings.Repeat("a", 64)})
			task := model.Task{ID: store.ID(), NodeID: n.ID, Type: kind, Status: "pending", Payload: payload}
			response := authenticatedRequest(t, a, model.User{ID: "task-admin", Admin: true}, "POST", "/api/v1/nodes/"+n.ID+"/tasks", task, a.Config.PublicURL)
			if response.Code != http.StatusConflict {
				t.Fatalf("disabled node accepted %s: HTTP %d %s", kind, response.Code, response.Body.String())
			}
			// A task writer that loaded the node before it was disabled must
			// also be rejected inside the database transaction.
			if err := a.Store.QueueNodeTask(ctx, n, task); !errors.Is(err, store.ErrConflict) {
				t.Fatalf("stale task writer bypassed disabled state: %v", err)
			}
		})
	}
	tasks, err := a.nodeTasks(ctx, n.ID, false)
	if err != nil || len(tasks) != 0 {
		t.Fatalf("rejected task left queued work: tasks=%v err=%v", tasks, err)
	}
	got := currentTaskNode(t, a, n.ID)
	if got.Enabled || got.Revision != disabled.Revision || got.DerperImage != n.DerperImage {
		t.Fatalf("rejected task changed desired state: %+v", got)
	}
	disabled.Enabled = true
	disabled.Revision++
	if err := a.Store.Save(ctx, "node", n.ID, "", disabled.Revision, disabled, nil); err != nil {
		t.Fatal(err)
	}
	response := authenticatedRequest(t, a, model.User{ID: "task-admin", Admin: true}, "POST", "/api/v1/nodes/"+n.ID+"/tasks", model.Task{Type: "restart", Payload: json.RawMessage(`{"component":"derper"}`)}, a.Config.PublicURL)
	if response.Code != http.StatusCreated {
		t.Fatalf("re-enabled node rejected task: HTTP %d %s", response.Code, response.Body.String())
	}
}
