// Package worker consumes events off the queue and delivers them to each
// affected relying application's POST /internal/logout endpoint.
package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

var ErrTargetConfiguration = errors.New("target configuration is invalid")

// EventPayload mirrors the JSON shape defined in the spec (F05 > Payload
// Event Minimum).
type EventPayload struct {
	EventID          uuid.UUID      `json:"eventId"`
	EventType        string         `json:"eventType"`
	UserID           uuid.UUID      `json:"userId"`
	CentralSessionID *uuid.UUID     `json:"centralSessionId"`
	ApplicationID    *uuid.UUID     `json:"applicationId"`
	Reason           string         `json:"reason"`
	OccurredAt       time.Time      `json:"occurredAt"`
	Metadata         map[string]any `json:"metadata,omitempty"`
}

// AppTarget describes one relying application the worker can notify.
type AppTarget struct {
	ApplicationID     uuid.UUID
	Name              string
	LogoutNotifyURL   string
	InternalAuthToken string
}

type DeliveryState struct {
	Status       string
	AttemptCount int
}

type DeliveryStore interface {
	BeginDelivery(context.Context, uuid.UUID, uuid.UUID) (DeliveryState, error)
	MarkDeliverySucceeded(context.Context, uuid.UUID, uuid.UUID, time.Time) error
	MarkDeliveryRetrying(context.Context, uuid.UUID, uuid.UUID, time.Time, error) error
	MarkDeliveryFailed(context.Context, uuid.UUID, uuid.UUID, time.Time, error) error
}

type TargetResolver interface {
	ResolveTargets(context.Context, EventPayload, []AppTarget) ([]AppTarget, error)
}

type Worker struct {
	Logger   *slog.Logger
	Targets  []AppTarget
	Store    DeliveryStore
	Resolver TargetResolver
	Client   *http.Client

	MaxRetries  int
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
}

func New(logger *slog.Logger, store DeliveryStore, resolver TargetResolver, targets []AppTarget, maxRetries int, baseBackoff, maxBackoff time.Duration) *Worker {
	if logger == nil {
		logger = slog.Default()
	}
	if maxRetries <= 0 {
		maxRetries = 1
	}
	if baseBackoff < 0 {
		baseBackoff = 0
	}
	if maxBackoff <= 0 {
		maxBackoff = 2 * time.Minute
	}
	return &Worker{
		Logger:      logger,
		Targets:     append([]AppTarget(nil), targets...),
		Store:       store,
		Resolver:    resolver,
		Client:      &http.Client{Timeout: 15 * time.Second},
		MaxRetries:  maxRetries,
		BaseBackoff: baseBackoff,
		MaxBackoff:  maxBackoff,
	}
}

// HandleDelivery processes one at-least-once broker delivery. It only ACKs
// after every target has reached a durable terminal state.
func (w *Worker) HandleDelivery(ctx context.Context, d amqp.Delivery) {
	var payload EventPayload
	if err := json.Unmarshal(d.Body, &payload); err != nil || !validPayload(payload) {
		w.logger().Error("invalid event, dead-lettering", slog.Any("err", err))
		w.nack(d, false)
		return
	}

	w.logger().Info("received event",
		slog.String("eventId", payload.EventID.String()),
		slog.String("eventType", payload.EventType),
		slog.String("userId", payload.UserID.String()),
	)

	targets, err := w.targets(ctx, payload)
	if err != nil {
		w.logger().Error("event target resolution failed", slog.Any("err", err))
		w.nack(d, !errors.Is(err, ErrTargetConfiguration))
		return
	}
	if len(targets) == 0 {
		w.ack(d)
		return
	}

	transientFailure := false
	permanentFailure := false
	results := make(chan deliveryResult, len(targets))
	var waitGroup sync.WaitGroup
	for _, target := range targets {
		waitGroup.Add(1)
		go func(target AppTarget) {
			defer waitGroup.Done()
			results <- w.deliverTarget(ctx, payload, target)
		}(target)
	}
	waitGroup.Wait()
	close(results)
	for result := range results {
		if result.err != nil {
			transientFailure = true
			w.logger().Error("event delivery failed before durable completion", slog.Any("err", result.err))
			continue
		}
		if result.failed {
			permanentFailure = true
		}
	}

	if transientFailure {
		w.nack(d, true)
		return
	}
	if permanentFailure {
		w.nack(d, false)
		return
	}
	w.ack(d)
}

// deliverToApp performs one authenticated HTTP POST to an application's
// internal logout endpoint.
func (w *Worker) deliverToApp(ctx context.Context, target AppTarget, payload EventPayload) error {
	if target.LogoutNotifyURL == "" {
		return errors.New("logout notification URL is empty")
	}
	if target.InternalAuthToken == "" {
		return errors.New("internal auth token is empty")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode event: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.LogoutNotifyURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create logout request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Event-ID", payload.EventID.String())
	if target.InternalAuthToken != "" {
		request.Header.Set("X-Internal-Auth", target.InternalAuthToken)
	}
	client := w.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("send logout request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		return fmt.Errorf("logout endpoint returned HTTP %d", response.StatusCode)
	}
	return nil
}

type deliveryResult struct {
	failed bool
	err    error
}

func (w *Worker) deliverTarget(ctx context.Context, payload EventPayload, target AppTarget) deliveryResult {
	if w.Store == nil {
		return deliveryResult{err: errors.New("delivery store is not configured")}
	}
	for {
		state, err := w.Store.BeginDelivery(ctx, payload.EventID, target.ApplicationID)
		if err != nil {
			return deliveryResult{err: err}
		}
		if state.Status == "succeeded" {
			return deliveryResult{}
		}
		if state.Status == "failed" {
			return deliveryResult{}
		}
		attempt := state.AttemptCount
		if attempt <= 0 {
			return deliveryResult{err: errors.New("delivery attempt was not recorded")}
		}

		err = w.deliverToApp(ctx, target, payload)
		if err == nil {
			if markErr := w.Store.MarkDeliverySucceeded(ctx, payload.EventID, target.ApplicationID, time.Now().UTC()); markErr != nil {
				return deliveryResult{err: markErr}
			}
			return deliveryResult{}
		}
		if ctx.Err() != nil {
			return deliveryResult{err: ctx.Err()}
		}
		if attempt >= w.maxRetries() {
			if markErr := w.Store.MarkDeliveryFailed(ctx, payload.EventID, target.ApplicationID, time.Now().UTC(), err); markErr != nil {
				return deliveryResult{err: markErr}
			}
			return deliveryResult{failed: true}
		}

		nextRetryAt := time.Now().UTC().Add(backoffFor(attempt-1, w.BaseBackoff, w.MaxBackoff))
		if markErr := w.Store.MarkDeliveryRetrying(ctx, payload.EventID, target.ApplicationID, nextRetryAt, err); markErr != nil {
			return deliveryResult{err: markErr}
		}
		if err := wait(ctx, time.Until(nextRetryAt)); err != nil {
			return deliveryResult{err: err}
		}
	}
}

func (w *Worker) targets(ctx context.Context, payload EventPayload) ([]AppTarget, error) {
	if w.Resolver != nil {
		targets, err := w.Resolver.ResolveTargets(ctx, payload, w.Targets)
		if err != nil {
			return nil, err
		}
		return uniqueTargets(targets)
	}
	if payload.ApplicationID == nil {
		return uniqueTargets(w.Targets)
	}
	for _, target := range w.Targets {
		if target.ApplicationID == *payload.ApplicationID {
			return uniqueTargets([]AppTarget{target})
		}
	}
	return nil, fmt.Errorf("%w: application target %s is not configured", ErrTargetConfiguration, payload.ApplicationID)
}

func uniqueTargets(targets []AppTarget) ([]AppTarget, error) {
	seen := make(map[uuid.UUID]struct{}, len(targets))
	result := make([]AppTarget, 0, len(targets))
	for _, target := range targets {
		if target.ApplicationID == uuid.Nil {
			return nil, errors.New("application target has no ID")
		}
		if _, ok := seen[target.ApplicationID]; ok {
			continue
		}
		seen[target.ApplicationID] = struct{}{}
		result = append(result, target)
	}
	return result, nil
}

func (w *Worker) maxRetries() int {
	if w.MaxRetries > 0 {
		return w.MaxRetries
	}
	return 1
}

func (w *Worker) logger() *slog.Logger {
	if w.Logger != nil {
		return w.Logger
	}
	return slog.Default()
}

func (w *Worker) ack(d amqp.Delivery) {
	if err := d.Ack(false); err != nil {
		w.logger().Error("ack failed", slog.Any("err", err))
	}
}

func (w *Worker) nack(d amqp.Delivery, requeue bool) {
	if err := d.Nack(false, requeue); err != nil {
		w.logger().Error("nack failed", slog.Any("err", err), slog.Bool("requeue", requeue))
	}
}

func validPayload(payload EventPayload) bool {
	if payload.EventID == uuid.Nil || payload.UserID == uuid.Nil || payload.OccurredAt.IsZero() || payload.Reason == "" {
		return false
	}
	switch payload.EventType {
	case "SessionRevoked", "PasswordChanged":
		return payload.CentralSessionID != nil
	case "AccessPolicyChanged":
		return payload.ApplicationID != nil
	default:
		return false
	}
}

func wait(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// backoffFor returns exponential backoff with a cap, for attempt N (0-indexed).
func backoffFor(attempt int, base, max time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	if max <= 0 {
		max = base
	}
	d := base
	for i := 0; i < attempt; i++ {
		if d > max/2 {
			return max
		}
		d *= 2
	}
	if d > max {
		return max
	}
	return d
}
