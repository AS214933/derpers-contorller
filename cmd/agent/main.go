package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/AS214933/derpers-contorller/internal/agent"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := agent.ConfigFromEnvironment()
	if err != nil {
		logger.Error("invalid agent configuration", "error", err)
		os.Exit(1)
	}
	a, err := agent.New(cfg, logger)
	if err != nil {
		logger.Error("initialize agent", "error", err)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := a.Run(ctx); err != nil {
		logger.Error("agent stopped", "error", err)
		os.Exit(1)
	}
}
