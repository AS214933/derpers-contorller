package controller

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/AS214933/derpers-contorller/internal/model"
	"github.com/AS214933/derpers-contorller/internal/store"
	"tailscale.com/types/key"
)

func TestIntegrationNetworkWritesNotifyAfterCommitButHealthPatchesDoNot(t *testing.T) {
	a := integrationApp(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	listener, err := a.Store.Pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Release()
	if _, err = listener.Exec(ctx, "LISTEN derpers_network"); err != nil {
		t.Fatal(err)
	}
	defer listener.Exec(context.Background(), "UNLISTEN derpers_network")

	expectNotification := func(id string) {
		t.Helper()
		wait, stop := context.WithTimeout(ctx, 2*time.Second)
		defer stop()
		for {
			notification, err := listener.Conn().WaitForNotification(wait)
			if err != nil {
				t.Fatalf("network change notification missing: %v", err)
			}
			if notification.Channel == "derpers_network" && notification.Payload == id {
				return
			}
		}
	}
	expectQuiet := func(ids ...string) {
		t.Helper()
		wait, stop := context.WithTimeout(ctx, 200*time.Millisecond)
		defer stop()
		for {
			notification, err := listener.Conn().WaitForNotification(wait)
			if errors.Is(err, context.DeadlineExceeded) {
				return
			}
			if err != nil {
				t.Fatalf("notification listener failed: %v", err)
			}
			for _, id := range ids {
				if notification.Payload == id {
					t.Fatalf("operation should not notify: %+v", notification)
				}
			}
		}
	}

	n := model.Network{ID: store.ID(), OwnerID: "cli-owner", Name: "notify", Kind: "tailscale", Tailnet: "team.example.com", Status: "approved", Revision: 1}
	if err = a.Store.Save(ctx, "network", n.ID, n.OwnerID, n.Revision, n, officialTestCredentials); err != nil {
		t.Fatal(err)
	}
	expectNotification(n.ID)
	record, err := a.Store.Get(ctx, "network", n.ID)
	if err != nil || record.Revision != 1 {
		t.Fatalf("notification preceded committed create: %+v %v", record, err)
	}

	n.Revision = 2
	n.Name = "updated"
	if err = a.Store.Save(ctx, "network", n.ID, n.OwnerID, n.Revision, n, nil); err != nil {
		t.Fatal(err)
	}
	expectNotification(n.ID)
	record, err = a.Store.Get(ctx, "network", n.ID)
	if err != nil || record.Revision != 2 {
		t.Fatalf("notification preceded committed update: %+v %v", record, err)
	}

	if err = a.Store.Patch(ctx, "network", n.ID, n.Revision, map[string]any{"health": "healthy", "device_count": 3, "last_error": ""}); err != nil {
		t.Fatal(err)
	}
	expectQuiet(n.ID)
	if err = a.Store.Save(ctx, "network", n.ID, n.OwnerID, n.Revision, n, nil); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale update error=%v", err)
	}
	expectQuiet(n.ID)
	otherID := store.ID()
	if err = a.Store.Save(ctx, "settings", otherID, "", 1, map[string]string{"approval_mode": "manual"}, nil); err != nil {
		t.Fatal(err)
	}
	expectQuiet(otherID)

	if err = a.Store.Delete(ctx, "network", n.ID); err != nil {
		t.Fatal(err)
	}
	expectNotification(n.ID)
	if _, err = a.Store.Get(ctx, "network", n.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("notification preceded committed deletion: %v", err)
	}
	if err = a.Store.Delete(ctx, "network", n.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("repeated delete error=%v", err)
	}
	expectQuiet(n.ID)
}

func TestIntegrationNetworkWatcherObservesIndependentCLIStoreImmediately(t *testing.T) {
	a := integrationApp(t)
	fixture := officialAPI(t)
	oldKey, newKey := key.NewNode().Public(), key.NewNode().Public()
	fixture.set([]device{{NodeKey: oldKey.String(), Authorized: true, ExpiryDisabled: true}}, 200, "")
	ctx, cancel := context.WithCancel(fixture.context())
	writer, err := store.Open(ctx, a.Store.Pool.Config().ConnConfig.ConnString(), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x39}, 32)))
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(writer.Close)
	done := make(chan struct{})
	go func() { defer close(done); a.watchNetworks(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("network watcher did not stop after cancellation")
		}
	})
	await := func(description string, condition func() bool) {
		t.Helper()
		deadline := time.NewTimer(4 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			if condition() {
				return
			}
			select {
			case <-deadline.C:
				t.Fatalf("%s did not happen promptly; watcher must not wait for five-minute polling", description)
			case <-tick.C:
			}
		}
	}
	n := model.Network{ID: store.ID(), OwnerID: "cli-owner", Name: "cli-created", Kind: "tailscale", Tailnet: "team.example.com", Status: "approved", Revision: 1}
	hasSnapshot := func(revision int64, expected string, absent string) bool {
		a.mu.RLock()
		defer a.mu.RUnlock()
		snapshot, ok := a.snapshots[n.ID]
		if !ok || snapshot.Revision != revision || !time.Now().Before(snapshot.Expires) {
			return false
		}
		_, exists := snapshot.Keys[expected]
		_, oldExists := snapshot.Keys[absent]
		return exists && !oldExists
	}
	missingSnapshot := func() bool { a.mu.RLock(); defer a.mu.RUnlock(); _, exists := a.snapshots[n.ID]; return !exists }

	// This writes through a separately connected Store, as the management CLI
	// does. The serving App's background listener is the only sync trigger.
	if err = writer.Save(ctx, "network", n.ID, n.OwnerID, n.Revision, n, officialTestCredentials); err != nil {
		t.Fatal(err)
	}
	await("newly approved CLI source synchronization", func() bool { return hasSnapshot(1, oldKey.String(), newKey.String()) })
	if fixture.tokenCalls.Load() < 1 || fixture.deviceCalls.Load() < 1 {
		t.Fatal("watcher did not execute real OAuth/devices fixture calls")
	}
	// Repeated change notifications for a revision already synchronized must
	// not create redundant OAuth/API traffic.
	before := fixture.deviceCalls.Load()
	a.refreshChangedSource(ctx, n.ID)
	if fixture.deviceCalls.Load() != before {
		t.Fatal("fresh unchanged source was synchronized again")
	}

	n.Revision++
	n.Status = "disabled"
	if err = writer.Save(ctx, "network", n.ID, n.OwnerID, n.Revision, n, nil); err != nil {
		t.Fatal(err)
	}
	await("disabled source cache invalidation", missingSnapshot)

	fixture.set([]device{{NodeKey: newKey.String(), Authorized: true, ExpiryDisabled: true}}, 200, "")
	n.Revision++
	n.Status = "approved"
	if err = writer.Save(ctx, "network", n.ID, n.OwnerID, n.Revision, n, nil); err != nil {
		t.Fatal(err)
	}
	await("re-approved updated source synchronization", func() bool { return hasSnapshot(n.Revision, newKey.String(), oldKey.String()) })

	if err = writer.Delete(ctx, "network", n.ID); err != nil {
		t.Fatal(err)
	}
	await("deleted source cache invalidation", missingSnapshot)
}
