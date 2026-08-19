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
	conn        *amqp.Connection
	ch          *amqp.Channel
	consumerTag string
}

// Connect opens the AMQP connection/channel and declares the exchange +
// main queue + DLQ + bindings. Idempotent — safe to call on every boot.
func Connect(brokerURL string) (*Connection, error) {
	conn, err := amqp.Dial(brokerURL)
	if err != nil {
		return nil, fmt.Errorf("queue: dial: %w", err)
	}
	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("queue: open channel: %w", err)
	}

	if err := ch.ExchangeDeclare(ExchangeEvents, "topic", true, false, false, false, nil); err != nil {
		_ = ch.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("queue: declare exchange: %w", err)
	}
	if err := ch.Confirm(false); err != nil {
		_ = ch.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("queue: enable publisher confirms: %w", err)
	}

	if _, err := ch.QueueDeclare(QueueDLQ, true, false, false, false, nil); err != nil {
		_ = ch.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("queue: declare DLQ: %w", err)
	}

	if _, err := ch.QueueDeclare(QueueSyncWorker, true, false, false, false, mainQueueArguments()); err != nil {
		_ = ch.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("queue: declare main queue: %w", err)
	}
	for _, routingKey := range EventRoutingKeys {
		if err := ch.QueueBind(QueueSyncWorker, routingKey, ExchangeEvents, false, nil); err != nil {
			_ = ch.Close()
			_ = conn.Close()
			return nil, fmt.Errorf("queue: bind main queue: %w", err)
		}
	}

	return &Connection{conn: conn, ch: ch}, nil
}

func mainQueueArguments() amqp.Table {
	return amqp.Table{
		"x-dead-letter-exchange":    "",
		"x-dead-letter-routing-key": QueueDLQ,
	}
}

func (c *Connection) Close() error {
	if err := c.ch.Close(); err != nil {
		return err
	}
	return c.conn.Close()
}

// Publish sends a single event's JSON payload to the exchange. Called by
// the outbox publisher loop, never directly from an HTTP handler.
func (c *Connection) Publish(ctx context.Context, routingKey string, body []byte) error {
	confirmation, err := c.ch.PublishWithDeferredConfirmWithContext(ctx, ExchangeEvents, routingKey, false, false, amqp.Publishing{
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

// Consume returns the delivery channel for the main work queue. Use
// manual ack (autoAck=false) so a crash mid-processing redelivers rather
// than silently drops the message — this is what "at-least-once" means in
// practice.
func (c *Connection) Consume() (<-chan amqp.Delivery, error) {
	c.consumerTag = "sync-worker"
	return c.ch.Consume(QueueSyncWorker, c.consumerTag, false, false, false, false, nil)
}

func (c *Connection) StopConsuming() error {
	if c.consumerTag == "" {
		return nil
	}
	return c.ch.Cancel(c.consumerTag, false)
}

func (c *Connection) SetConsumerPrefetch() error {
	return c.ch.Qos(ConsumerPrefetch, 0, false)
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
	Broker       Publisher
	Store        OutboxStore
	Logger       *slog.Logger
	PollInterval time.Duration
	BatchSize    int
}

func NewOutboxPublisher(broker Publisher, store OutboxStore, logger *slog.Logger, pollInterval time.Duration) *OutboxPublisher {
	if logger == nil {
		logger = slog.Default()
	}
	if pollInterval <= 0 {
		pollInterval = 500 * time.Millisecond
	}
	return &OutboxPublisher{Broker: broker, Store: store, Logger: logger, PollInterval: pollInterval, BatchSize: 100}
}

func (p *OutboxPublisher) Run(ctx context.Context) {
	ticker := time.NewTicker(p.PollInterval)
	defer ticker.Stop()

	for {
		if err := p.PublishBatch(ctx); err != nil {
			p.Logger.Error("outbox publish batch failed", slog.Any("err", err))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (p *OutboxPublisher) PublishBatch(ctx context.Context) error {
	if p.Broker == nil || p.Store == nil {
		return fmt.Errorf("outbox publisher is not configured")
	}
	batchSize := p.BatchSize
	if batchSize <= 0 {
		batchSize = 100
	}
	events, err := p.Store.ListUnpublished(ctx, batchSize)
	if err != nil {
		return err
	}
	var firstErr error
	for _, event := range events {
		if err := ctx.Err(); err != nil {
			return err
		}
		routingKey := RoutingKeyForEvent(event.EventType)
		if routingKey == "" {
			if firstErr == nil {
				firstErr = fmt.Errorf("unsupported event type %q", event.EventType)
			}
			continue
		}
		if err := p.Broker.Publish(ctx, routingKey, event.Payload); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := p.Store.MarkPublished(ctx, event.ID, time.Now().UTC()); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
