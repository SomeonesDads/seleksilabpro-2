package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/sync-worker/internal/config"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/sync-worker/internal/queue"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/sync-worker/internal/store"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/sync-worker/internal/worker"
	"github.com/SomeonesDads/seleksilabpro-2/shared/logging"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	amqp "github.com/rabbitmq/amqp091-go"
)

func main() {
	logger := logging.NewLogger("sync-worker")

	cfg, err := config.Load()
	if err != nil {
		logger.Error("config load failed", slog.Any("err", err))
		os.Exit(1)
	}

	signalCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	conn, err := queue.Connect(cfg.BrokerURL)
	if err != nil {
		logger.Error("queue connect failed", slog.Any("err", err))
		os.Exit(1)
	}
	defer conn.Close()

	dbPool, err := pgxpool.New(signalCtx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("database pool creation failed", slog.Any("err", err))
		os.Exit(1)
	}
	defer dbPool.Close()
	if err := dbPool.Ping(signalCtx); err != nil {
		logger.Error("database ping failed", slog.Any("err", err))
		os.Exit(1)
	}
	dbStore := store.New(dbPool)

	targets := make([]worker.AppTarget, 0, len(cfg.Targets))
	for _, target := range cfg.Targets {
		applicationID, err := uuid.Parse(target.ApplicationID)
		if err != nil {
			logger.Error("application target configuration invalid", slog.Any("err", err))
			os.Exit(1)
		}
		targets = append(targets, worker.AppTarget{
			ApplicationID:     applicationID,
			Name:              target.Name,
			LogoutNotifyURL:   target.LogoutNotifyURL,
			InternalAuthToken: target.InternalAuthToken,
		})
	}
	if err := dbStore.ValidateTargets(signalCtx, targets); err != nil {
		logger.Error("application target validation failed", slog.Any("err", err))
		os.Exit(1)
	}

	publisher := queue.NewOutboxPublisher(conn, dbStore, logger, cfg.OutboxInterval)
	workCtx, cancelWork := context.WithCancel(context.Background())
	defer cancelWork()
	var active sync.WaitGroup
	active.Add(1)
	go func() {
		defer active.Done()
		publisher.Run(signalCtx)
	}()

	w := worker.New(logger, dbStore, dbStore, targets, cfg.MaxRetries, cfg.BaseBackoff, cfg.MaxBackoff)

	if err := conn.SetConsumerPrefetch(); err != nil {
		logger.Error("consumer QoS setup failed", slog.Any("err", err))
		os.Exit(1)
	}
	deliveries, err := conn.Consume()
	if err != nil {
		logger.Error("consume setup failed", slog.Any("err", err))
		os.Exit(1)
	}

	logger.Info("sync-worker started, consuming events")

	stopping := false
	for !stopping {
		select {
		case <-signalCtx.Done():
			stopping = true
			if err := conn.StopConsuming(); err != nil {
				logger.Error("stopping consumption failed", slog.Any("err", err))
			}
		case d, ok := <-deliveries:
			if !ok {
				stopping = true
				stop()
				break
			}
			active.Add(1)
			go func(delivery amqp.Delivery) {
				defer active.Done()
				w.HandleDelivery(workCtx, delivery)
			}(d)
		}
	}

	logger.Info("shutdown signal received, draining in-flight work")
	if drainWork(&active, cancelWork, cfg.ShutdownTimeout) {
		logger.Info("shutdown drain complete")
	} else {
		logger.Error("shutdown timeout reached")
	}
}

func drainWork(active *sync.WaitGroup, cancelWork context.CancelFunc, timeout time.Duration) bool {
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), timeout)
	defer cancelShutdown()
	drained := make(chan struct{})
	go func() {
		active.Wait()
		close(drained)
	}()
	select {
	case <-drained:
		return true
	case <-shutdownCtx.Done():
		cancelWork()
		return false
	}
}
