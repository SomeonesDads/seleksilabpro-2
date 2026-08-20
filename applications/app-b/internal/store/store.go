package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Store is the persistence boundary for App A's local data. All security-
// relevant writes (session revocation, processed-event deduplication) live
// here so handlers stay thin and behavior stays testable.
type Store struct {
	DB *gorm.DB
}

func New(db *gorm.DB) *Store { return &Store{DB: db} }

func (s *Store) AutoMigrate() error {
	return s.DB.AutoMigrate(
		&LocalSession{},
		&ProfileCache{},
		&ProcessedEvent{},
		&ActivityLog{},
	)
}

// FindSessionByTokenHash returns the active local session for a cookie token
// hash, or nil when none matches. A session is active when its status is
// "active", not revoked, and not past expiry.
func (s *Store) FindSessionByTokenHash(ctx context.Context, hash string) (*LocalSession, error) {
	var sess LocalSession
	err := s.DB.WithContext(ctx).
		Where("session_token_hash = ?", hash).
		First(&sess).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s *Store) IsSessionActive(sess *LocalSession, now time.Time) bool {
	return sess != nil &&
		sess.Status == "active" &&
		sess.RevokedAt == nil &&
		now.Before(sess.ExpiresAt)
}

// ListActiveByUser returns every currently active local session for a user.
func (s *Store) ListActiveByUser(ctx context.Context, externalUserID string) ([]LocalSession, error) {
	var sessions []LocalSession
	err := s.DB.WithContext(ctx).
		Where("external_user_id = ? AND status = 'active' AND revoked_at IS NULL", externalUserID).
		Find(&sessions).Error
	return sessions, err
}

// CreateSession persists a new local session and bumps last activity. The
// caller must already have hashed the raw token.
func (s *Store) CreateSession(ctx context.Context, sess *LocalSession) error {
	now := time.Now().UTC()
	sess.CreatedAt = now
	sess.LastActivityAt = &now
	if sess.Status == "" {
		sess.Status = "active"
	}
	return s.DB.WithContext(ctx).Create(sess).Error
}

// TouchSession updates last activity without changing status.
func (s *Store) TouchSession(ctx context.Context, id uuid.UUID) error {
	now := time.Now().UTC()
	return s.DB.WithContext(ctx).
		Model(&LocalSession{}).
		Where("id = ?", id).
		Update("last_activity_at", &now).Error
}

// RevokeSession marks one local session revoked. It is idempotent: revoking an
// already-revoked session is a no-op.
func (s *Store) RevokeSession(ctx context.Context, id uuid.UUID, reason string, now time.Time) error {
	return s.DB.WithContext(ctx).
		Model(&LocalSession{}).
		Where("id = ? AND status = 'active' AND revoked_at IS NULL", id).
		Updates(map[string]any{
			"status":       "revoked",
			"revoked_at":   now,
			"revoke_reason": reason,
		}).Error
}

// RevokeSessionsByCentralSession revokes every active local session bound to a
// central session (used by SessionRevoked events).
func (s *Store) RevokeSessionsByCentralSession(ctx context.Context, centralSessionID, reason string, now time.Time) (int64, error) {
	res := s.DB.WithContext(ctx).
		Model(&LocalSession{}).
		Where("central_session_id = ? AND status = 'active' AND revoked_at IS NULL", centralSessionID).
		Updates(map[string]any{
			"status":        "revoked",
			"revoked_at":    now,
			"revoke_reason": reason,
		})
	return res.RowsAffected, res.Error
}

// RevokeSessionsByUser revokes every active local session for a user in this
// application (used by PasswordChanged and AccessPolicyChanged events).
func (s *Store) RevokeSessionsByUser(ctx context.Context, externalUserID, reason string, now time.Time) (int64, error) {
	res := s.DB.WithContext(ctx).
		Model(&LocalSession{}).
		Where("external_user_id = ? AND status = 'active' AND revoked_at IS NULL", externalUserID).
		Updates(map[string]any{
			"status":        "revoked",
			"revoked_at":    now,
			"revoke_reason": reason,
		})
	return res.RowsAffected, res.Error
}

// UpsertProfile writes or refreshes the profile cache for an external user.
func (s *Store) UpsertProfile(ctx context.Context, p *ProfileCache) error {
	now := time.Now().UTC()
	p.SyncedAt = now
	var existing ProfileCache
	err := s.DB.WithContext(ctx).
		Where("external_user_id = ?", p.ExternalUserID).
		First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		p.CreatedAt = now
		p.UpdatedAt = now
		return s.DB.WithContext(ctx).Create(p).Error
	}
	if err != nil {
		return err
	}
	p.CreatedAt = existing.CreatedAt
	p.UpdatedAt = now
	return s.DB.WithContext(ctx).Save(p).Error
}

func (s *Store) GetProfile(ctx context.Context, externalUserID string) (*ProfileCache, error) {
	var p ProfileCache
	err := s.DB.WithContext(ctx).
		Where("external_user_id = ?", externalUserID).
		First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// EventProcessed reports whether an eventId was already handled.
func (s *Store) EventProcessed(ctx context.Context, eventID uuid.UUID) (bool, error) {
	var count int64
	err := s.DB.WithContext(ctx).
		Model(&ProcessedEvent{}).
		Where("event_id = ?", eventID).
		Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// RecordEvent atomically inserts a processed event. The event_id primary key
// makes the insert idempotent: a duplicate delivery hits the unique constraint
// and reports inserted=false without error. The first successful insert returns
// inserted=true so the caller performs the revocation exactly once.
func (s *Store) RecordEvent(ctx context.Context, eventID uuid.UUID, eventType, result string) (bool, error) {
	ev := ProcessedEvent{
		EventID:    eventID,
		EventType:  eventType,
		Result:     result,
		ProcessedAt: time.Now().UTC(),
	}
	res := s.DB.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "event_id"}},
			DoNothing: true,
		}).
		Create(&ev)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

// ProcessRevocation records the processed event and performs the session
// revocation in a single database transaction. The event_id unique constraint
// makes the work exactly-once: the first transaction inserts the event and
// applies the revocation; any concurrent or replayed delivery hits the unique
// constraint (RowsAffected == 0) and skips the revocation. A crash or DB
// failure between the two steps cannot leave the session revoked while the
// event stays unrecorded, because both writes commit or roll back together.
func (s *Store) ProcessRevocation(ctx context.Context, eventID uuid.UUID, eventType, result, externalUserID, centralSessionID, reason string, now time.Time) (inserted bool, revoked int64, err error) {
	err = s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		ev := ProcessedEvent{
			EventID:    eventID,
			EventType:  eventType,
			Result:     result,
			ProcessedAt: now,
		}
		res := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "event_id"}},
			DoNothing: true,
		}).Create(&ev)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			// Already processed in a prior (or concurrent) delivery.
			inserted = false
			return nil
		}
		inserted = true

		var updates map[string]any
		switch eventType {
		case "SessionRevoked":
			updates = map[string]any{"status": "revoked", "revoked_at": now, "revoke_reason": reason}
			q := tx.Model(&LocalSession{}).
				Where("central_session_id = ? AND status = 'active' AND revoked_at IS NULL", centralSessionID)
			r := q.Updates(updates)
			revoked = r.RowsAffected
			return r.Error
		case "PasswordChanged", "AccessPolicyChanged":
			updates = map[string]any{"status": "revoked", "revoked_at": now, "revoke_reason": reason}
			q := tx.Model(&LocalSession{}).
				Where("external_user_id = ? AND status = 'active' AND revoked_at IS NULL", externalUserID)
			r := q.Updates(updates)
			revoked = r.RowsAffected
			return r.Error
		default:
			return nil
		}
	})
	return inserted, revoked, err
}

func (s *Store) ListProcessedEvents(ctx context.Context, limit int) ([]ProcessedEvent, error) {
	var events []ProcessedEvent
	err := s.DB.WithContext(ctx).
		Order("processed_at DESC").
		Limit(limit).
		Find(&events).Error
	return events, err
}

// AddActivity appends an activity-log entry.
func (s *Store) AddActivity(ctx context.Context, kind, message, correlationID string, sessionID *uuid.UUID) error {
	entry := ActivityLog{
		ID:            uuid.New(),
		LocalSessionID: sessionID,
		Kind:          kind,
		Message:       message,
		CorrelationID: correlationID,
		CreatedAt:     time.Now().UTC(),
	}
	return s.DB.WithContext(ctx).Create(&entry).Error
}

func (s *Store) ListActivity(ctx context.Context, limit int) ([]ActivityLog, error) {
	var logs []ActivityLog
	err := s.DB.WithContext(ctx).
		Order("created_at DESC").
		Limit(limit).
		Find(&logs).Error
	return logs, err
}
