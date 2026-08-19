// Package worker consumes events off the queue and delivers them to each
// affected relying application's POST /internal/logout endpoint.
package worker

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

// EventPayload mirrors the JSON shape defined in the spec (F05 > Payload
// Event Minimum).
type EventPayload struct {
	EventID          uuid.UUID      `json:"eventId"`
	EventType        string         `json:"eventType"` // SessionRevoked | PasswordChanged | AccessPolicyChanged
	UserID           uuid.UUID      `json:"userId"`
	CentralSessionID *uuid.UUID     `json:"centralSessionId,omitempty"`
	ApplicationID    *uuid.UUID     `json:"applicationId,omitempty"` // nil = every app the user has a session with
	Reason           string         `json:"reason"`
	OccurredAt       time.Time      `json:"occurredAt"`
	Metadata         map[string]any `json:"metadata,omitempty"`
}

// AppTarget describes one relying application the worker can notify.
type AppTarget struct {
	ApplicationID     uuid.UUID
	Name              string
	LogoutNotifyURL   string
	InternalAuthToken string // TODO: decide + implement service-to-service auth (shared secret header, mTLS, or signed JWT — document the choice in README)
}

type Worker struct {
	Logger  *slog.Logger
	Targets []AppTarget // TODO: load from DB (applications table) at startup / on a refresh interval, rather than hardcoding

	MaxRetries  int
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
}

// HandleDelivery is the per-message entrypoint wired up by main.go's
// consume loop.
//
// Steps:
//  1. Unmarshal the AMQP body into EventPayload.
//  2. Determine target application(s): if payload.ApplicationID is set,
//     just that app; if nil, every app the user currently (or recently)
//     had a session with.
//  3. For each target, independently:
//     a. Check/create an event_deliveries row (event_id, application_id)
//        — this is what makes a redelivered message idempotent from the
//        WORKER's perspective (separate from the app's own
//        processed_events table, which makes it idempotent from the
//        APP's perspective; you want both layers).
//     b. POST to target.LogoutNotifyURL with the event payload +
//        InternalAuthToken header.
//     c. On success: mark event_deliveries.status = succeeded.
//     d. On failure: increment attempt_count, set status = retrying (or
//        failed if attempt_count >= MaxRetries), record last_error.
//  4. Only ack the AMQP message once ALL targets have either succeeded or
//     been durably recorded as failed/retrying — a failure for App A must
//     never block or lose the delivery to App B (spec requirement).
//  5. If every target has exhausted MaxRetries, let the message be
//     nacked without requeue so RabbitMQ's DLX routes it to the DLQ
//     (see internal/queue's TODO on declaring that binding).
func (w *Worker) HandleDelivery(ctx context.Context, d amqp.Delivery) {
	var payload EventPayload
	if err := json.Unmarshal(d.Body, &payload); err != nil {
		w.Logger.Error("failed to unmarshal event, dead-lettering", slog.Any("err", err))
		_ = d.Nack(false, false) // don't requeue — malformed payload will never succeed
		return
	}

	w.Logger.Info("received event",
		slog.String("eventId", payload.EventID.String()),
		slog.String("eventType", payload.EventType),
		slog.String("userId", payload.UserID.String()),
	)

	// TODO: implement steps 2-5 above.

	_ = d.Ack(false) // placeholder — only do this once delivery is actually confirmed
}

// deliverToApp performs a single HTTP POST to one app's internal logout
// endpoint. Broken out so retries can call it in a loop with backoff.
func (w *Worker) deliverToApp(ctx context.Context, target AppTarget, payload EventPayload) error {
	// TODO: build request, set InternalAuthToken header, POST as JSON,
	// treat non-2xx as failure. Respect ctx for cancellation on shutdown.
	return nil
}

// backoffFor returns exponential backoff with a cap, for attempt N (0-indexed).
func backoffFor(attempt int, base, max time.Duration) time.Duration {
	d := base
	for i := 0; i < attempt; i++ {
		d *= 2
		if d > max {
			return max
		}
	}
	return d
}
