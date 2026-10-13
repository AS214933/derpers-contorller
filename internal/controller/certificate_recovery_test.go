package controller

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/AS214933/derpers-contorller/internal/model"
	"github.com/AS214933/derpers-contorller/internal/store"
)

func TestCertificateRolloutRequiresAppliedRevisionAndFreshProbe(t *testing.T) {
	now := time.Now()
	n := model.Node{Enabled: true, AppliedRevision: 3, LastSeen: &now, Metrics: map[string]float64{"derper_up": 1, "derper_probe_timestamp_seconds": float64(now.Unix())}}
	if !relayRevisionApplied(n, 3, now) {
		t.Fatal("applied healthy revision was not acknowledged")
	}
	if relayRevisionApplied(n, 4, now) {
		t.Fatal("old configuration acknowledged a new certificate")
	}
	n.Metrics["derper_up"] = 0
	if relayRevisionApplied(n, 3, now) {
		t.Fatal("failed TLS probe acknowledged rollout")
	}
	n.Metrics["derper_up"] = 1
	n.Metrics["derper_probe_timestamp_seconds"] = float64(now.Add(-2 * time.Minute).Unix())
	if relayRevisionApplied(n, 3, now) {
		t.Fatal("stale probe acknowledged rollout")
	}
	n.Metrics["derper_probe_timestamp_seconds"] = float64(now.Unix())
	old := now.Add(-2 * time.Minute)
	n.LastSeen = &old
	if relayRevisionApplied(n, 3, now) {
		t.Fatal("offline Agent acknowledged rollout")
	}
	n.LastSeen = &now
	n.Enabled = false
	if relayRevisionApplied(n, 3, now) {
		t.Fatal("disabled node acknowledged rollout")
	}
}
func TestIntegrationCertificateTaskRecoversPersistedIssuance(t *testing.T) {
	a := integrationApp(t)
	ctx := context.Background()
	taskID := store.ID()
	accountID := store.ID()
	// An unsupported provider fails locally if provisioning is mistakenly repeated.
	// This fixture therefore cannot contact a public DNS API or an ACME service.
	account := model.DNSAccount{ID: accountID, Name: "checkpoint guard", Provider: "checkpoint-only", Zone: "example.test", Suffix: "derp.example.test"}
	if e := a.Store.Save(ctx, "dns", accountID, "", 1, account, nil); e != nil {
		t.Fatal(e)
	}
	cert, private, _ := testCertificate(t, "checkpoint.derp.example.test", time.Now().Add(-time.Minute), time.Now().Add(48*time.Hour))
	n, e := a.AddNode(ctx, model.Node{Name: "checkpoint", Hostname: "checkpoint.derp.example.test", IPv4: "203.0.113.10", DNSAccountID: accountID}, map[string]string{"certificate_pem": cert, "certificate_key_pem": private, "certificate_task_id": taskID})
	if e != nil {
		t.Fatal(e)
	}
	task := model.Task{ID: taskID, NodeID: n.ID, Type: "provision", Status: "running", Payload: json.RawMessage(`{}`), CreatedAt: time.Now().UTC()}
	if e = a.Store.Save(ctx, "task", taskID, "", 1, task, nil); e != nil {
		t.Fatal(e)
	}
	a.runProvision(ctx, task)
	r, e := a.Store.Get(ctx, "task", taskID)
	if e != nil {
		t.Fatal(e)
	}
	got, e := store.Decode[model.Task](r)
	if e != nil {
		t.Fatal(e)
	}
	if got.Status != "succeeded" {
		t.Fatalf("persisted issuance was repeated instead of recovered: %+v", got)
	}
	after, e := a.Store.Get(ctx, "node", n.ID)
	if e != nil {
		t.Fatal(e)
	}
	if after.Revision != n.Revision {
		t.Fatal("recovery issued a replacement certificate")
	}
	sec, e := a.Store.Secrets(after)
	if e != nil || sec["certificate_pem"] != cert || sec["certificate_task_id"] != taskID {
		t.Fatal("persisted certificate checkpoint was changed")
	}
}
func TestIntegrationOperationLocksDoNotExhaustAdmissionConnections(t *testing.T) {
	a := integrationApp(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	releases := []func(){}
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	for i := range 16 {
		release, e := a.Store.Lock(ctx, "isolated-operation:"+string(rune('a'+i)))
		if e != nil {
			t.Fatal(e)
		}
		releases = append(releases, release)
	}
	ping, cancelPing := context.WithTimeout(ctx, time.Second)
	defer cancelPing()
	if e := a.Store.Pool.Ping(ping); e != nil {
		t.Fatalf("operation locks starved admission/database reads: %v", e)
	}
	started := time.Now()
	_, e := a.Store.Lock(ctx, "lock-pool-at-capacity")
	if !errors.Is(e, store.ErrConflict) || time.Since(started) > 2*time.Second {
		t.Fatalf("saturated operation pool did not return a bounded conflict: %v", e)
	}
}
