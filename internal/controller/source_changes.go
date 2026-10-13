package controller

import (
	"context"
	"log/slog"
	"time"

	"github.com/AS214933/derpers-contorller/internal/model"
	"github.com/AS214933/derpers-contorller/internal/store"
)

// PostgreSQL notifications also reach a running daemon when an operator uses
// the local CLI. The mutation and notification commit in the same statement.
// Reconnecting rebuilds snapshots because notifications are not a durable queue.
func (a *App) watchNetworks(ctx context.Context) {
	jobs := make(chan string, 128)
	for range 8 {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case id := <-jobs:
					a.refreshChangedSource(ctx, id)
				}
			}
		}()
	}
	for ctx.Err() == nil {
		conn, e := a.Store.Pool.Acquire(ctx)
		if e == nil {
			_, e = conn.Exec(ctx, "LISTEN derpers_network")
			if e == nil {
				a.syncAll(ctx)
				for ctx.Err() == nil {
					notification, x := conn.Conn().WaitForNotification(ctx)
					if x != nil {
						e = x
						break
					}
					select {
					case jobs <- notification.Payload:
					case <-ctx.Done():
					}
				}
			}
			cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			if _, x := conn.Exec(cleanup, "UNLISTEN *"); x != nil {
				_ = conn.Conn().Close(cleanup)
			}
			cancel()
			conn.Release()
		}
		if ctx.Err() != nil {
			return
		}
		slog.Warn("authorization change listener reconnecting")
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}
func (a *App) refreshChangedSource(ctx context.Context, id string) {
	rec, e := a.Store.Get(ctx, "network", id)
	if e != nil {
		a.invalidate(id)
		return
	}
	n, e := store.Decode[model.Network](rec)
	if e != nil {
		a.invalidate(id)
		return
	}
	a.mu.RLock()
	snap, ok := a.snapshots[id]
	a.mu.RUnlock()
	if !ok || snap.Revision != n.Revision || n.Status != "approved" {
		a.invalidate(id)
	}
	if n.Status == "approved" && n.Kind == "tailscale" {
		_ = a.syncNetwork(ctx, id, false)
	}
}
