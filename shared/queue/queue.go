// Package queue wraps the RabbitMQ connection and defines the exchange/
// queue topology. Two related-but-separate jobs live here:
//
//  1. Outbox Publisher: polls the `events` table (auth-provider primary DB)
//     for rows with published_at IS NULL, publishes each to the broker,
//     then sets published_at. This can run as a goroutine in THIS binary,
//     or you can split it into its own tiny process — the spec doesn't
//     mandate either, just that the pattern (DB write + queue write don't
//     happen in the same step) is respected.
//
//  2. Consumer: the Sync Worker proper. Reads events off the queue and
//     dispatches to internal/worker for delivery to App A / App B.
//
// RabbitMQ's native dead-letter exchange receives messages nacked without
// requeue after all per-application retry attempts are exhausted.
package queue

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

const (
	ExchangeEvents   = "auth.events"
	QueueSyncWorker  = "sync-worker.main"
	QueueDLQ         = "sync-worker.dlq"
	RoutingKeyAll    = "#"
	ConsumerPrefetch = 8
)

var EventRoutingKeys = []string{"SessionRevoked", "PasswordChanged", "AccessPolicyChanged"}

func RoutingKeyForEvent(eventType string) string {
	for _, key := range EventRoutingKeys {
		if key == eventType {
			return key
		}
	}
	return ""
}

type Connection struct {
	conn             *amqp.Connection
	publishCh        *amqp.Channel
	consumeCh        *amqp.Channel
	consumerTag      string
	shutdownDeadline time.Time
	closed           atomic.Bool
}

// Connect opens the AMQP connection and two separate channels: one for
// publishing (with confirms enabled) and one for consuming/ACK/NACK. Keeping
// them separate prevents a publisher's confirm frames from interleaving with
// consumer cancellation or acknowledgement frames on the same channel during
// shutdown.
func Connect(brokerURL string) (*Connection, error) {
	conn, err := amqp.Dial(brokerURL)
	if err != nil {
		return nil, fmt.Errorf("queue: dial: %w", err)
	}
	publishCh, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("queue: open publish channel: %w", err)
	}
	consumeCh, err := conn.Channel()
	if err != nil {
		_ = publishCh.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("queue: open consume channel: %w", err)
	}

	if err := publishCh.ExchangeDeclare(ExchangeEvents, "topic", true, false, false, false, nil); err != nil {
		_ = publishCh.Close()
		_ = consumeCh.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("queue: declare exchange: %w", err)
	}
	if err := publishCh.Confirm(false); err != nil {
		_ = publishCh.Close()
		_ = consumeCh.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("queue: enable publisher confirms: %w", err)
	}

	if _, err := publishCh.QueueDeclare(QueueDLQ, true, false, false, false, nil); err != nil {
		_ = publishCh.Close()
		_ = consumeCh.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("queue: declare DLQ: %w", err)
	}

	if _, err := publishCh.QueueDeclare(QueueSyncWorker, true, false, false, false, mainQueueArguments()); err != nil {
		_ = publishCh.Close()
		_ = consumeCh.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("queue: declare main queue: %w", err)
	}
	for _, routingKey := range EventRoutingKeys {
		if err := publishCh.QueueBind(QueueSyncWorker, routingKey, ExchangeEvents, false, nil); err != nil {
			_ = publishCh.Close()
			_ = consumeCh.Close()
			_ = conn.Close()
			return nil, fmt.Errorf("queue: bind main queue: %w", err)
		}
	}

	return &Connection{conn: conn, publishCh: publishCh, consumeCh: consumeCh}, nil
}

func mainQueueArguments() amqp.Table {
	return amqp.Table{
		"x-dead-letter-exchange":    "",
		"x-dead-letter-routing-key": QueueDLQ,
	}
}

// SetShutdownDeadline records the absolute shutdown deadline so CloseUntil
// bounds the connection teardown to the configured budget.
func (c *Connection) SetShutdownDeadline(d time.Time) {
	c.shutdownDeadline = d
}

// CloseUntil closes the underlying AMQP connection (and, per the amqp library,
// all of its channels) by the given deadline, bounding teardown to the
// configured shutdown budget instead of hanging on an unresponsive broker. It
// is idempotent: once closed, subsequent calls are no-ops.
func (c *Connection) CloseUntil(deadline time.Time) error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	if c.conn == nil {
		return nil
	}
	return c.conn.CloseDeadline(deadline)
}

// Close closes the connection by the configured shutdown deadline (or a 5s
// default when none was set), bounding teardown and staying idempotent.
func (c *Connection) Close() error {
	d := c.shutdownDeadline
	if d.IsZero() {
		d = time.Now().Add(5 * time.Second)
	}
	return c.CloseUntil(d)
}

// IsClosed reports whether the underlying AMQP connection is no longer usable,
// used by health probes and the metrics dependency-health gauges.
func (c *Connection) IsClosed() bool {
	return c.conn.IsClosed()
}

// Publish sends a single event's JSON payload to the exchange on the dedicated
// publish channel. Called by the outbox publisher loop, never directly from an
// HTTP handler. The confirmation wait uses the supplied context.
func (c *Connection) Publish(ctx context.Context, routingKey string, body []byte) error {
	confirmation, err := c.publishCh.PublishWithDeferredConfirmWithContext(ctx, ExchangeEvents, routingKey, false, false, amqp.Publishing{
		ContentType:  "application/json",
		Body:         body,
		DeliveryMode: amqp.Persistent,
	})
	if err != nil {
		return err
	}
	if confirmation == nil {
		return fmt.Errorf("queue: publisher confirmation unavailable")
	}
	confirmed, err := confirmation.WaitContext(ctx)
	if err != nil {
		return err
	}
	if !confirmed {
		return fmt.Errorf("queue: broker rejected publication")
	}
	return nil
}

// Consume returns the delivery channel for the main work queue on the
// dedicated consume channel. Use manual ack (autoAck=false) so a crash
// mid-processing redelivers rather than silently drops the message — this is
// what "at-least-once" means in practice.
func (c *Connection) Consume() (<-chan amqp.Delivery, error) {
	c.consumerTag = "sync-worker"
	return c.consumeCh.Consume(QueueSyncWorker, c.consumerTag, false, false, false, false, nil)
}

func (c *Connection) StopConsuming() error {
	if c.consumerTag == "" {
		return nil
	}
	// Cancel on the consume channel only; the publish channel is untouched.
	err := c.consumeCh.Cancel(c.consumerTag, false)
	// Clear the tag so a repeated shutdown signal (which re-fires the same
	// signal context) becomes a safe no-op instead of a second Cancel.
	c.consumerTag = ""
	return err
}

func (c *Connection) SetConsumerPrefetch() error {
	return c.consumeCh.Qos(ConsumerPrefetch, 0, false)
}

type OutboxEvent struct {
	ID        string
	EventType string
	Payload   []byte
}

type Publisher interface {
	Publish(context.Context, string, []byte) error
}

type OutboxStore interface {
	ListUnpublished(context.Context, int) ([]OutboxEvent, error)
	MarkPublished(context.Context, string, time.Time) error
}

type OutboxPublisher struct {
	Broker         Publisher
	Store          OutboxStore
	Logger         *slog.Logger
	PollInterval   time.Duration
	BatchSize      int
	PublishTimeout time.Duration
}

func NewOutboxPublisher(broker Publisher, store OutboxStore, logger *slog.Logger, pollInterval time.Duration) *OutboxPublisher {
	if logger == nil {
		logger = slog.Default()
	}
	if pollInterval <= 0 {
		pollInterval = 500 * time.Millisecond
	}
	return &OutboxPublisher{Broker: broker, Store: store, Logger: logger, PollInterval: pollInterval, BatchSize: 100, PublishTimeout: 5 * time.Second}
}

// Run polls for unpublished outbox rows until loopCtx is cancelled, then
// performs a final drain (looping until the armed shutdown deadline expires) so
// any rows still arriving are published (and marked published) before the
// process exits. Steady-state batches use the cancellable workCtx so a slow
// publish is aborted when the shutdown deadline cancels work; the final drain
// uses the armed shutdown-deadline context (also stopped by workCtx) so it
// never outlives the budget yet still publishes rows inserted after the signal.
func (p *OutboxPublisher) Run(loopCtx, workCtx context.Context, drainCtxCh <-chan context.Context) {
	ticker := time.NewTicker(p.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-loopCtx.Done():
			// Final drain loops under the armed shutdown-deadline context,
			// also stopping when workCtx is cancelled at the deadline. The
			// drain channel is read ONLY here (blocking) so the single armed
			// value is never skipped or consumed by an early poll.
			p.drainUntil(readDrainCtx(drainCtxCh, workCtx), workCtx)
			return
		case <-ticker.C:
		}
		// Steady-state batches use the cancellable work context so the shutdown
		// deadline can abort an in-flight publish instead of racing the
		// connection teardown.
		p.drainOnce(workCtx)
	}
}

// drainUntil repeatedly drains the outbox under ctx until ctx or stop is
// cancelled/expired, so the post-signal final drain publishes rows that arrive
// after the shutdown signal but stops promptly when the budget is exhausted.
func (p *OutboxPublisher) drainUntil(ctx, stop context.Context) {
	p.drainOnce(ctx)
	ticker := time.NewTicker(p.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop.Done():
			return
		case <-ticker.C:
			p.drainOnce(ctx)
		}
	}
}

// readDrainCtx returns the armed shutdown-deadline context. It blocks until the
// signal goroutine delivers it (guaranteed in production, and pre-filled in
// tests), so the final drain always uses the real shared shutdown context
// rather than falling back to a cancelled loop context under a scheduling delay.
func readDrainCtx(ch <-chan context.Context, fallback context.Context) context.Context {
	ctx, ok := <-ch
	if ok {
		return ctx
	}
	return fallback
}

func (p *OutboxPublisher) drainOnce(ctx context.Context) {
	if err := p.PublishBatch(ctx); err != nil {
		p.Logger.Error("outbox publish batch failed", slog.Any("err", err))
	}
}

// operationContext returns a context for a single publish batch derived from
// the caller's ctx, capped by PublishTimeout so an unresponsive broker cannot
// hang termination beyond the shutdown budget.
func (p *OutboxPublisher) operationContext(parent context.Context) (context.Context, context.CancelFunc) {
	if p.PublishTimeout <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, p.PublishTimeout)
}

func (p *OutboxPublisher) PublishBatch(ctx context.Context) error {
	if p.Broker == nil || p.Store == nil {
		return fmt.Errorf("outbox publisher is not configured")
	}
	batchSize := p.BatchSize
	if batchSize <= 0 {
		batchSize = 100
	}
	// Derived from the caller's ctx (the shutdown-deadline context), so an
	// in-flight publish + broker confirm is bounded by and cancellable with
	// the shutdown budget.
	opCtx, cancel := p.operationContext(ctx)
	defer cancel()
	events, err := p.Store.ListUnpublished(opCtx, batchSize)
	if err != nil {
		return err
	}
	var firstErr error
	for _, event := range events {
		routingKey := RoutingKeyForEvent(event.EventType)
		if routingKey == "" {
			if firstErr == nil {
				firstErr = fmt.Errorf("unsupported event type %q", event.EventType)
			}
			continue
		}
		if err := p.Broker.Publish(opCtx, routingKey, event.Payload); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := p.Store.MarkPublished(opCtx, event.ID, time.Now().UTC()); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
