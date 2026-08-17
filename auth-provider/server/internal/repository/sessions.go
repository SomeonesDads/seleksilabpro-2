package repository

import (
	"context"
	"errors"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

var ErrSessionNotFound = errors.New("session not found")

type SessionRepository struct{ db *gorm.DB }

func NewSessionRepository(db *gorm.DB) *SessionRepository { return &SessionRepository{db: db} }

func (r *SessionRepository) Create(ctx context.Context, session *models.SSOSession) error {
	return r.db.WithContext(ctx).Create(session).Error
}

func (r *SessionRepository) FindActiveByTokenHash(ctx context.Context, tokenHash string) (*models.SSOSession, error) {
	var session models.SSOSession
	err := r.db.WithContext(ctx).
		Where("session_token_hash = ? AND status = ? AND expires_at > ? AND revoked_at IS NULL", tokenHash, "active", time.Now()).
		First(&session).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (r *SessionRepository) Revoke(ctx context.Context, id uuid.UUID, reason string) error {
	return r.revoke(r.db.WithContext(ctx), id, reason)
}

// CreateSessionRevokedEvent is provided here as a convenience for callers
// that already depend on the session repository. RevokeAndCreateEvent uses
// the same helper inside its transaction.
func (r *SessionRepository) CreateSessionRevokedEvent(ctx context.Context, session *models.SSOSession, reason string) error {
	return createSessionRevokedEvent(r.db.WithContext(ctx), session, reason)
}

func (r *SessionRepository) RevokeAndCreateEvent(ctx context.Context, id uuid.UUID, reason string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var session models.SSOSession
		if err := tx.Where("id = ?", id).First(&session).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrSessionNotFound
			}
			return err
		}
		if err := r.revoke(tx, id, reason); err != nil {
			return err
		}
		return createSessionRevokedEvent(tx, &session, reason)
	})
}

func (r *SessionRepository) revoke(db *gorm.DB, id uuid.UUID, reason string) error {
	now := time.Now()
	result := db.Model(&models.SSOSession{}).Where("id = ?", id).Updates(map[string]any{
		"status":        "revoked",
		"revoked_at":    now,
		"revoke_reason": reason,
	})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrSessionNotFound
	}
	return nil
}
