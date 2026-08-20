package store

import (
	"context"
	"fmt"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/shared/queue"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/sync-worker/internal/worker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) ValidateTargets(ctx context.Context, configured []worker.AppTarget) error {
	if s.pool == nil {
		return fmt.Errorf("store database is not configured")
	}
	if len(configured) == 0 {
		return fmt.Errorf("no application targets are configured")
	}
	configByID := make(map[uuid.UUID]worker.AppTarget, len(configured))
	for _, target := range configured {
		if target.ApplicationID == uuid.Nil || target.LogoutNotifyURL == "" || target.InternalAuthToken == "" {
			return fmt.Errorf("application target %s has incomplete credentials", target.ApplicationID)
		}
		configByID[target.ApplicationID] = target
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id
		FROM applications
		WHERE status = 'active'`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var applicationID uuid.UUID
		if err := rows.Scan(&applicationID); err != nil {
			return err
		}
		target, ok := configByID[applicationID]
		if !ok || target.LogoutNotifyURL == "" || target.InternalAuthToken == "" {
			return fmt.Errorf("active application %s has no usable target credentials", applicationID)
		}
	}
	return rows.Err()
}

func (s *Store) ListUnpublished(ctx context.Context, limit int) ([]queue.OutboxEvent, error) {
	if s.pool == nil {
		return nil, fmt.Errorf("store database is not configured")
	}
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, event_type, payload
		FROM events
		WHERE published_at IS NULL
		ORDER BY created_at ASC, id ASC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]queue.OutboxEvent, 0)
	for rows.Next() {
		var id uuid.UUID
		var eventType string
		var payload []byte
		if err := rows.Scan(&id, &eventType, &payload); err != nil {
			return nil, err
		}
		events = append(events, queue.OutboxEvent{ID: id.String(), EventType: eventType, Payload: payload})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func (s *Store) MarkPublished(ctx context.Context, id string, publishedAt time.Time) error {
	if s.pool == nil {
		return fmt.Errorf("store database is not configured")
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE events
		SET status = 'published', published_at = $2
		WHERE id = $1 AND published_at IS NULL`, id, publishedAt)
	return err
}

func (s *Store) ResolveTargets(ctx context.Context, payload worker.EventPayload, configured []worker.AppTarget) ([]worker.AppTarget, error) {
	if s.pool == nil {
		return nil, fmt.Errorf("store database is not configured")
	}
	configByID := make(map[uuid.UUID]worker.AppTarget, len(configured))
	for _, target := range configured {
		configByID[target.ApplicationID] = target
	}

	var rows pgx.Rows
	var err error
	switch {
	case payload.ApplicationID != nil:
		rows, err = s.pool.Query(ctx, `
			SELECT id, name, logout_notification_url
			FROM applications
			WHERE id = $1 AND status = 'active'`, *payload.ApplicationID)
	case payload.CentralSessionID != nil:
		rows, err = s.pool.Query(ctx, `
			SELECT DISTINCT a.id, a.name, a.logout_notification_url
			FROM applications a
			WHERE a.status = 'active'
			  AND EXISTS (
				  SELECT 1 FROM access_tokens t
				  WHERE t.application_id = a.id
				    AND t.user_id = $1
				    AND t.session_id = $2
			  )`, payload.UserID, *payload.CentralSessionID)
	default:
		rows, err = s.pool.Query(ctx, `
			SELECT DISTINCT a.id, a.name, a.logout_notification_url
			FROM applications a
			WHERE a.status = 'active'
			  AND EXISTS (
				  SELECT 1 FROM access_tokens t
				  WHERE t.application_id = a.id AND t.user_id = $1
			  )`, payload.UserID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	targets := make([]worker.AppTarget, 0)
	for rows.Next() {
		var target worker.AppTarget
		if err := rows.Scan(&target.ApplicationID, &target.Name, &target.LogoutNotifyURL); err != nil {
			return nil, err
		}
		configuredTarget, ok := configByID[target.ApplicationID]
		if !ok || configuredTarget.InternalAuthToken == "" || configuredTarget.LogoutNotifyURL == "" {
			return nil, fmt.Errorf("%w: active application %s has no usable target credentials", worker.ErrTargetConfiguration, target.ApplicationID)
		}
		if configuredTarget.Name != "" {
			target.Name = configuredTarget.Name
		}
		target.LogoutNotifyURL = configuredTarget.LogoutNotifyURL
		target.InternalAuthToken = configuredTarget.InternalAuthToken
		targets = append(targets, target)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if payload.ApplicationID != nil && len(targets) == 0 {
		return nil, fmt.Errorf("%w: active application target %s not found", worker.ErrTargetConfiguration, payload.ApplicationID)
	}
	return targets, nil
}

func (s *Store) BeginDelivery(ctx context.Context, eventID, applicationID uuid.UUID) (worker.DeliveryState, error) {
	if s.pool == nil {
		return worker.DeliveryState{}, fmt.Errorf("store database is not configured")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return worker.DeliveryState{}, err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		INSERT INTO event_deliveries (event_id, application_id, status, attempt_count)
		VALUES ($1, $2, 'pending', 0)
		ON CONFLICT (event_id, application_id) DO NOTHING`, eventID, applicationID); err != nil {
		return worker.DeliveryState{}, err
	}

	var state worker.DeliveryState
	if err := tx.QueryRow(ctx, `
		SELECT status, attempt_count
		FROM event_deliveries
		WHERE event_id = $1 AND application_id = $2
		FOR UPDATE`, eventID, applicationID).Scan(&state.Status, &state.AttemptCount); err != nil {
		return worker.DeliveryState{}, err
	}
	if state.Status == "succeeded" || state.Status == "failed" {
		if err := tx.Commit(ctx); err != nil {
			return worker.DeliveryState{}, err
		}
		return state, nil
	}

	state.AttemptCount++
	if _, err := tx.Exec(ctx, `
		UPDATE event_deliveries
		SET status = 'processing', attempt_count = $3, last_attempt_at = $4,
		    next_retry_at = NULL, last_error = NULL
		WHERE event_id = $1 AND application_id = $2`, eventID, applicationID, state.AttemptCount, time.Now().UTC()); err != nil {
		return worker.DeliveryState{}, err
	}
	state.Status = "processing"
	if err := tx.Commit(ctx); err != nil {
		return worker.DeliveryState{}, err
	}
	return state, nil
}

func (s *Store) MarkDeliverySucceeded(ctx context.Context, eventID, applicationID uuid.UUID, processedAt time.Time) error {
	if s.pool == nil {
		return fmt.Errorf("store database is not configured")
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE event_deliveries
		SET status = 'succeeded', processed_at = $3, next_retry_at = NULL, last_error = NULL
		WHERE event_id = $1 AND application_id = $2`, eventID, applicationID, processedAt)
	return err
}

func (s *Store) MarkDeliveryRetrying(ctx context.Context, eventID, applicationID uuid.UUID, nextRetryAt time.Time, deliveryErr error) error {
	if s.pool == nil {
		return fmt.Errorf("store database is not configured")
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE event_deliveries
		SET status = 'retrying', next_retry_at = $3, last_error = $4
		WHERE event_id = $1 AND application_id = $2`, eventID, applicationID, nextRetryAt, errorText(deliveryErr))
	return err
}

func (s *Store) MarkDeliveryFailed(ctx context.Context, eventID, applicationID uuid.UUID, failedAt time.Time, deliveryErr error) error {
	if s.pool == nil {
		return fmt.Errorf("store database is not configured")
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE event_deliveries
		SET status = 'failed', last_attempt_at = $3, next_retry_at = NULL, last_error = $4
		WHERE event_id = $1 AND application_id = $2`, eventID, applicationID, failedAt, errorText(deliveryErr))
	return err
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	if len(text) > 2000 {
		return text[:2000]
	}
	return text
}
