package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/sync-worker/internal/config"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/sync-worker/internal/queue"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/sync-worker/internal/worker"
	"github.com/SomeonesDads/seleksilabpro-2/shared/logging"
)

func main() {
	logger := logging.NewLogger("sync-worker")

	cfg, err := config.Load()
	if err != nil {
		logger.Error("config load failed", slog.Any("err", err))
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	conn, err := queue.Connect(cfg.BrokerURL)
	if err != nil {
		logger.Error("queue connect failed", slog.Any("err", err))
		os.Exit(1)
	}
	defer conn.Close()

	// TODO: also open a pgx pool to the primary DB here if the worker
	// reads `applications`/`event_deliveries` directly rather than via
	// the server's internal API.

	// TODO: start the outbox publisher goroutine — polls `events` where
	// published_at IS NULL, calls conn.Publish, then marks published_at.
	// Run it on a short interval (e.g. every 500ms-1s) or, better, use
	// LISTEN/NOTIFY from Postgres to wake it immediately on insert.

	w := &worker.Worker{
		Logger:      logger,
		MaxRetries:  cfg.MaxRetries,
		BaseBackoff: cfg.BaseBackoff,
		MaxBackoff:  cfg.MaxBackoff,
	}

	deliveries, err := conn.Consume()
	if err != nil {
		logger.Error("consume setup failed", slog.Any("err", err))
		os.Exit(1)
	}

	logger.Info("sync-worker started, consuming events")

	for {
		select {
		case <-ctx.Done():
			logger.Info("shutdown signal received, stopping consumption")
			// TODO [B04]: stop accepting new deliveries, let any in-flight
			// HandleDelivery calls finish (with a timeout), then return.
			return
		case d, ok := <-deliveries:
			if !ok {
				logger.Warn("delivery channel closed, exiting")
				return
			}
			w.HandleDelivery(ctx, d)
		}
	}
}
