package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/AS214933/derpers-contorller/internal/model"
	"github.com/AS214933/derpers-contorller/internal/store"
)

func TestIntegrationOperationLockAcrossConnectionsAndRelease(t *testing.T) {
	a := integrationApp(t)
	ctx := context.Background()
	key := "node-operation:" + store.ID()
	release, err := a.Store.Lock(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	held := true
	t.Cleanup(func() {
		if held {
			release()
		}
	})
	if duplicate, err := a.Store.Lock(ctx, key); !errors.Is(err, store.ErrConflict) {
		if err == nil {
			duplicate()
		}
		t.Fatalf("second connection acquired held lock: %v", err)
	}
	independent, err := a.Store.Lock(ctx, key+"-independent")
	if err != nil {
		t.Fatalf("unrelated node lock blocked: %v", err)
	}
	independent()
	release()
	held = false
	after, err := a.Store.Lock(ctx, key)
	if err != nil {
		t.Fatalf("released lock remained held: %v", err)
	}
	after()
}

func TestIntegrationHeldNodeOperationBlocksManagementMutations(t *testing.T) {
	a := integrationApp(t)
	ctx := context.Background()
	node := taskNode(t, a)
	before, err := a.Store.Get(ctx, "node", node.ID)
	if err != nil {
		t.Fatal(err)
	}
	release, err := a.Store.Lock(ctx, "node-operation:"+node.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	edited := node
	edited.Name = "should-not-be-written"
	for _, test := range []struct {
		name, method, path string
		body               any
	}{
		{"edit", "PUT", "/api/v1/nodes/" + node.ID, edited},
		{"delete", "DELETE", "/api/v1/nodes/" + node.ID, nil},
		{"ownership import", "POST", "/api/v1/nodes/" + node.ID + "/dns-import", map[string]any{"record_ids": []string{"record-never-read"}}},
		{"DNS cleanup", "POST", "/api/v1/nodes/" + node.ID + "/dns-cleanup", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := authenticatedRequest(t, a, model.User{ID: "operation-lock-admin", Admin: true}, test.method, test.path, test.body, a.Config.PublicURL)
			if response.Code != http.StatusConflict {
				t.Fatalf("held operation returned HTTP %d instead of 409: %s", response.Code, response.Body.String())
			}
			after, err := a.Store.Get(ctx, "node", node.ID)
			if err != nil {
				t.Fatal("node was deleted while its operation lock was held:", err)
			}
			if after.Revision != before.Revision || !bytes.Equal(after.Data, before.Data) {
				t.Fatalf("node mutation escaped operation lock: before=%s after=%s", before.Data, after.Data)
			}
		})
	}
}

func TestIntegrationProvisionQueueAndWorkerWaitForNodeOperation(t *testing.T) {
	a := integrationApp(t)
	ctx := context.Background()
	node := taskNode(t, a)
	account := model.DNSAccount{ID: store.ID(), Name: "lock-fixture", Provider: "cloudflare", Zone: "example.test", Suffix: "example.test"}
	// No DNS credentials are installed: even a failing regression must never
	// contact a real provider. Queue validates metadata; a prematurely running
	// worker would change task status before rejecting the missing credentials.
	if err := a.Store.Save(ctx, "dns", account.ID, "", 1, account, map[string]string{}); err != nil {
		t.Fatal(err)
	}
	node.DNSAccountID = account.ID
	node.IPv4 = "203.0.113.10"
	node.Revision++
	if err := a.Store.Save(ctx, "node", node.ID, "", node.Revision, node, nil); err != nil {
		t.Fatal(err)
	}
	a.Config.ACMEEmail = "ci@example.test"
	task := model.Task{ID: store.ID(), NodeID: node.ID, Type: "provision", Status: "pending", Payload: json.RawMessage(`{}`), CreatedAt: time.Now().UTC()}
	if err := a.Store.Save(ctx, "task", task.ID, "", 1, task, nil); err != nil {
		t.Fatal(err)
	}
	before, err := a.Store.Get(ctx, "task", task.ID)
	if err != nil {
		t.Fatal(err)
	}
	release, err := a.Store.Lock(ctx, "node-operation:"+node.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := a.queueProvision(ctx, node.ID, "admin"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("queue ignored held node operation lock: %v", err)
	}
	workerCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	a.runProvision(workerCtx, task)
	after, err := a.Store.Get(ctx, "task", task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision != before.Revision || !bytes.Equal(after.Data, before.Data) {
		t.Fatalf("worker began side effects under another node operation: before=%s after=%s", before.Data, after.Data)
	}
	var count int
	if err := a.Store.Pool.QueryRow(ctx, "SELECT count(*) FROM resources WHERE kind='task' AND data->>'node_id'=$1", node.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("blocked queue created a second task: %d", count)
	}
	if err := a.Store.Pool.QueryRow(ctx, "SELECT count(*) FROM dns_records WHERE node_id=$1", node.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("blocked worker wrote DNS ownership: %d", count)
	}
}
