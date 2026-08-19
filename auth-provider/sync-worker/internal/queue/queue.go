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
// RabbitMQ has native dead-letter-exchange (DLX) support — configuring a
// DLX + x-message-ttl on the main queue gets you DLQ semantics from the
// broker itself rather than hand-rolling retry counting purely in app
// code. Consider using that instead of (or alongside) a manual counter.
package queue

import (
	"context"
	"fmt"

	amqp "github.com/rabbitmq/amqp091-go"
)

const (
	ExchangeEvents   = "auth.events"       // topic exchange events are published to
	QueueSyncWorker  = "sync-worker.main"  // main work queue the worker consumes from
	QueueDLQ         = "sync-worker.dlq"   // dead-letter queue for permanently-failed events
	RoutingKeyAll    = "session.#"         // matches SessionRevoked / PasswordChanged / AccessPolicyChanged
)

type Connection struct {
	conn *amqp.Connection
	ch   *amqp.Channel
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
		return nil, fmt.Errorf("queue: declare exchange: %w", err)
	}

	// TODO: declare QueueDLQ, then declare QueueSyncWorker with args
	// amqp.Table{"x-dead-letter-exchange": ""} pointing at the DLQ, so
	// messages nacked past their retry limit land there automatically.
	// See: https://www.rabbitmq.com/dlx.html

	if _, err := ch.QueueDeclare(QueueSyncWorker, true, false, false, false, nil); err != nil {
		return nil, fmt.Errorf("queue: declare main queue: %w", err)
	}
	if err := ch.QueueBind(QueueSyncWorker, RoutingKeyAll, ExchangeEvents, false, nil); err != nil {
		return nil, fmt.Errorf("queue: bind main queue: %w", err)
	}

	return &Connection{conn: conn, ch: ch}, nil
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
	return c.ch.PublishWithContext(ctx, ExchangeEvents, routingKey, false, false, amqp.Publishing{
		ContentType:  "application/json",
		Body:         body,
		DeliveryMode: amqp.Persistent,
	})
}

// Consume returns the delivery channel for the main work queue. Use
// manual ack (autoAck=false) so a crash mid-processing redelivers rather
// than silently drops the message — this is what "at-least-once" means in
// practice.
func (c *Connection) Consume() (<-chan amqp.Delivery, error) {
	return c.ch.Consume(QueueSyncWorker, "", false, false, false, false, nil)
}
