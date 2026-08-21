package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/sync-worker/internal/config"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/sync-worker/internal/metrics"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/sync-worker/internal/store"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/sync-worker/internal/worker"
	"github.com/SomeonesDads/seleksilabpro-2/shared/logging"
	"github.com/SomeonesDads/seleksilabpro-2/shared/queue"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

	// active tracks every goroutine that holds broker/DB resources (publisher,
	// delivery handlers, metrics refresh) so drainWork can wait for them before
	// the connections are released.
	var active sync.WaitGroup

	conn, err := queue.Connect(cfg.BrokerURL)
	if err != nil {
		logger.Error("queue connect failed", slog.Any("err", err))
		os.Exit(1)
	}

	dbPool, err := pgxpool.New(signalCtx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("database pool creation failed", slog.Any("err", err))
		os.Exit(1)
	}
	if err := dbPool.Ping(signalCtx); err != nil {
		logger.Error("database ping failed", slog.Any("err", err))
		os.Exit(1)
	}
	dbStore := store.New(dbPool)

	// Cancellable work context shared by the publisher, deliveries, metrics
	// refresh, and the final outbox drain. drainWork cancels it at the end of
	// the graceful-drain window so any still-running work is aborted before
	// the connection is closed.
	workCtx, cancelWork := context.WithCancel(context.Background())
	defer cancelWork()

	// Metrics (B02): expose worker delivery + dependency-health collectors.
	metricsInstance := metrics.New(nil)
	metricsAddr := os.Getenv("METRICS_ADDR")
	if metricsAddr == "" {
		metricsAddr = ":9091"
	}
	metricsMux := http.NewServeMux()
	metricsMux.Handle("GET /metrics", promhttp.Handler())
	metricsSrv := &http.Server{Addr: metricsAddr, Handler: metricsMux}
	metricsShutdownCh := make(chan context.Context, 1)
	go func() {
		logger.Info("metrics listening", slog.String("addr", metricsAddr))
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("metrics server error", slog.Any("err", err))
		}
	}()
	// Close the metrics listener as soon as the shutdown signal arrives so no
	// probe request can race the connection teardown during the work drain.
	// Shut down once, within the shared shutdown budget, and tracked by active
	// so the post-drain join waits for the listener to release before teardown.
	active.Add(1)
	go func() {
		defer active.Done()
		shutdownCtx := <-metricsShutdownCh
		if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
			logger.Error("metrics shutdown failed", slog.Any("err", err))
		}
	}()

	refreshWorkerMetricsOnce(context.Background(), logger, conn, dbPool, metricsInstance)
	active.Add(1)
	go func() {
		defer active.Done()
		refreshWorkerMetrics(workCtx, logger, conn, dbPool, metricsInstance)
	}()

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

	// Arm a single absolute shutdown deadline (signal time + SHUTDOWN_TIMEOUT)
	// and hand it to the consumer intake drain, the publisher's final drain,
	// and drainWork via separate buffered channels so each consumer gets its
	// own value (a shared channel would let one consumer steal it and block or
	// fall back to the cancelled loop context). Every phase shares one budget
	// and the publisher's final drain is cancellable by that same deadline.
	shutdownDone := make(chan struct{})
	defer close(shutdownDone)
	consumerShutdownCh := make(chan context.Context, 1)
	drainShutdownCh := make(chan context.Context, 1)
	publisherDrainCh := make(chan context.Context, 1)
	go func() {
		<-signalCtx.Done()
		dctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		deadline, _ := dctx.Deadline()
		conn.SetShutdownDeadline(deadline)
		phaseCtx, phaseCancel := context.WithDeadline(dctx, deadline.Add(-finalizationReserve(cfg.ShutdownTimeout)))
		consumerShutdownCh <- phaseCtx
		drainShutdownCh <- dctx
		publisherDrainCh <- dctx
		metricsShutdownCh <- dctx
		<-shutdownDone
		phaseCancel()
		cancel()
	}()

	publisher := queue.NewOutboxPublisher(conn, dbStore, logger, cfg.OutboxInterval)
	active.Add(1)
	go func() {
		defer active.Done()
		publisher.Run(signalCtx, workCtx, publisherDrainCh)
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

	runConsumerLoop(signalCtx, deliveries, conn.StopConsuming, stop, w, workCtx, consumerShutdownCh, signalCtx, &active, func() { _ = conn.CloseUntil(time.Now()) }, logger)

	logger.Info("shutdown signal received, draining in-flight work")
	shutdownCtx := <-drainShutdownCh

	// Reserve a small finalization window inside the hard deadline; the
	// graceful drain uses the rest, then work is cancelled and the remaining
	// tracked goroutines are joined within the reserve.
	deadline, _ := shutdownCtx.Deadline()
	drainCtx, drainCancel := context.WithDeadline(shutdownCtx, deadline.Add(-finalizationReserve(cfg.ShutdownTimeout)))
	defer drainCancel()
	if drainWork(&active, cancelWork, drainCtx) {
		logger.Info("shutdown drain complete")
	} else {
		logger.Error("shutdown timeout reached")
	}
	// Join remaining in-flight goroutines (deliveries, publisher, metrics,
	// intake) within the finalization window before the broker connection is
	// force-closed, so a goroutine mid-call is not raced by teardown.
	clean := joinActive(&active, shutdownCtx, logger)

	// Force-close the broker connection inside the hard deadline. This is
	// idempotent, so a force-close already triggered by a timed-out intake is
	// a harmless no-op.
	_ = conn.Close()
	if clean {
		dbPool.Close()
	} else {
		logger.Error("shutdown incomplete: database connections left open for the OS to reclaim")
	}
}

// finalizationReserve returns the small slice of the shutdown budget reserved
// for joining cancelled work, capped so it stays a small finalization window
// rather than eating the graceful-drain time.
func finalizationReserve(timeout time.Duration) time.Duration {
	r := timeout / 4
	if r > 2*time.Second {
		r = 2 * time.Second
	}
	if r <= 0 {
		r = timeout
	}
	return r
}

// joinActive waits for every in-flight goroutine tracked by active to finish,
// bounded by the shared shutdown deadline (not a fresh timeout, so total
// shutdown stays within budget). cancelWork has already been called at the
// deadline, so the work goroutines return promptly; the bound is a safety net
// against a handler that ignores its context so teardown can never hang.
func joinActive(active *sync.WaitGroup, shutdownCtx context.Context, logger *slog.Logger) bool {
	done := make(chan struct{})
	go func() {
		active.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-shutdownCtx.Done():
		logger.Error("active work did not finish before teardown, proceeding")
		return false
	}
}

// runConsumerLoop dispatches broker deliveries to the worker until a shutdown
// signal arrives (intake is stopped via stopConsuming) or the delivery channel
// closes (broker connection lost, in which case stopSignals halts further
// signal handling). It is extracted from main so the intake-stop and
// no-new-message behavior can be unit tested without a live broker.
func runConsumerLoop(signalCtx context.Context, deliveries <-chan amqp.Delivery, stopConsuming func() error, stopSignals func(), w *worker.Worker, workCtx context.Context, shutdownCh <-chan context.Context, fallbackCtx context.Context, active *sync.WaitGroup, forceClose func(), logger *slog.Logger) {
	for {
		select {
		case <-signalCtx.Done():
			haltIntake(deliveries, stopConsuming, stopSignals, shutdownCh, fallbackCtx, active, forceClose, logger)
			return
		case d, ok := <-deliveries:
			if !ok {
				haltIntake(deliveries, stopConsuming, stopSignals, shutdownCh, fallbackCtx, active, forceClose, logger)
				return
			}
			// A shutdown signal may have fired between this select arming and
			// a buffered delivery being chosen. Do not start new work once
			// intake is stopped; the delivery is left unacked and the broker
			// redelivers it.
			if signalCtx.Err() != nil {
				haltIntake(deliveries, stopConsuming, stopSignals, shutdownCh, fallbackCtx, active, forceClose, logger)
				return
			}
			active.Add(1)
			go func(delivery amqp.Delivery) {
				defer active.Done()
				// Final guard: a signal may have arrived between the recheck
				// and dispatch. Leave the delivery unacked so the broker
				// redelivers it rather than starting new work post-shutdown.
				if signalCtx.Err() != nil {
					return
				}
				w.HandleDelivery(workCtx, delivery)
			}(d)
		}
	}
}

// haltIntake stops the broker consumer and drains any prefetched-but-unread
// deliveries concurrently (so a slow cancel cannot block the other), leaving
// undelivered messages unacked for redelivery. The intake goroutine is tracked
// in active (registered before launch) so the post-drain join waits for
// StopConsuming to finish instead of racing it. If StopConsuming is still hung
// when the intake budget is exhausted, forceClose forcibly closes the AMQP
// connection (unblocking the stuck channel call). It then stops further signal
// handling. When the deliveries channel closed because the broker disconnected
// (no shutdown signal), the armed context is absent; the fallback context
// bounds the drain instead of blocking forever.
func haltIntake(deliveries <-chan amqp.Delivery, stopConsuming func() error, stopSignals func(), shutdownCh <-chan context.Context, fallbackCtx context.Context, active *sync.WaitGroup, forceClose func(), logger *slog.Logger) {
	sdctx := recvShutdownCtx(shutdownCh, fallbackCtx)

	intakeDone := make(chan struct{})
	// Track the intake goroutines in active BEFORE launch so the post-drain
	// join (and thus the connection teardown) waits for StopConsuming to
	// finish, instead of racing its AMQP channel use.
	active.Add(1)
	go func() {
		defer active.Done()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := stopConsuming(); err != nil {
				logger.Error("stopping consumption failed", slog.Any("err", err))
			}
		}()
		go func() {
			defer wg.Done()
			drainDeliveriesUnacked(deliveries, sdctx)
		}()
		wg.Wait()
		close(intakeDone)
	}()

	// Bound the whole intake step by the shutdown deadline (or a fixed fallback
	// when no deadline is armed, e.g. broker disconnect without a signal) so a
	// hung StopConsuming cannot block shutdown forever; on timeout, force-close
	// the AMQP connection to unblock it and reclaim resources.
	intakeLimit := 10 * time.Second
	if d, ok := sdctx.Deadline(); ok {
		if rem := time.Until(d); rem > 0 {
			intakeLimit = rem
		} else {
			intakeLimit = 0
		}
	}
	timer := time.NewTimer(intakeLimit)
	defer timer.Stop()
	select {
	case <-intakeDone:
	case <-timer.C:
		logger.Error("intake halt exceeded deadline, force-closing AMQP connection")
		if forceClose != nil {
			forceClose()
		}
	}
	if stopSignals != nil {
		stopSignals()
	}
}

// recvShutdownCtx returns the armed shutdown-deadline context if it has been
// sent, otherwise the fallback context. A late arm (race with the signal
// goroutine) is waited for briefly so the deadline is not missed, and a
// broker-disconnect path without a signal falls back instead of blocking.
func recvShutdownCtx(ch <-chan context.Context, fallbackCtx context.Context) context.Context {
	select {
	case ctx := <-ch:
		return ctx
	default:
	}
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case ctx := <-ch:
		return ctx
	case <-timer.C:
		return fallbackCtx
	}
}

// drainDeliveriesUnacked reads any remaining prefetched deliveries from the
// channel and discards them without acknowledging, so they remain unacked and
// are redelivered by the broker. Bounded by the shutdown context's deadline so
// a stuck channel cannot block shutdown.
func drainDeliveriesUnacked(deliveries <-chan amqp.Delivery, ctx context.Context) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(2 * time.Second)
	}
	limit := time.Until(deadline)
	if limit < 0 {
		limit = 0
	}
	dl := time.After(limit)
	for {
		select {
		case _, ok := <-deliveries:
			if !ok {
				return
			}
		case <-dl:
			return
		}
	}
}

// drainWork waits for every in-flight delivery (and the publisher) to finish
// within the graceful-drain deadline (hard deadline minus the finalization
// reserve) so the total shutdown never exceeds the configured budget. Only
// when that window is exhausted is the work context cancelled (aborting stuck
// network I/O); the post-drain join then consumes the finalization reserve.
func drainWork(active *sync.WaitGroup, cancelWork context.CancelFunc, drainCtx context.Context) bool {
	drained := make(chan struct{})
	go func() {
		active.Wait()
		close(drained)
	}()
	select {
	case <-drained:
		return true
	case <-drainCtx.Done():
		// Budget exhausted: abort remaining in-flight work so its AMQP/DB
		// calls return, then let the deferred connection close reclaim
		// resources.
		cancelWork()
		return false
	}
}

// refreshWorkerMetrics periodically updates the broker/db health gauges so
// /metrics reflects live dependency state. The refresh uses ctx so it is
// cancelled by the shutdown signal and joined by drainWork before teardown.
func refreshWorkerMetrics(ctx context.Context, logger *slog.Logger, conn *queue.Connection, dbPool *pgxpool.Pool, m *metrics.Metrics) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshWorkerMetricsOnce(ctx, logger, conn, dbPool, m)
		}
	}
}

// refreshWorkerMetricsOnce performs a single health-gauge refresh so the
// /metrics endpoint reflects dependency state immediately at startup. The
// database ping honours ctx so a shutdown signal can cancel it.
func refreshWorkerMetricsOnce(ctx context.Context, logger *slog.Logger, conn *queue.Connection, dbPool *pgxpool.Pool, m *metrics.Metrics) {
	dbUp := dbPool.Ping(ctx) == nil
	brokerUp := !conn.IsClosed()
	m.SetDBHealth(dbUp)
	m.SetBrokerHealth(brokerUp)
	logger.Debug("metrics refresh", slog.Bool("dbUp", dbUp), slog.Bool("brokerUp", brokerUp))
}
