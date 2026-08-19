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

func (r *SessionRepository) FindActiveByID(ctx context.Context, id uuid.UUID) (*models.SSOSession, error) {
	var session models.SSOSession
	err := r.db.WithContext(ctx).
		Where("id = ? AND status = ? AND expires_at > ? AND revoked_at IS NULL", id, "active", time.Now()).
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
		if session.Status != "active" || session.RevokedAt != nil || !time.Now().Before(session.ExpiresAt) {
			return ErrSessionNotFound
		}
		if err := r.revoke(tx, id, reason); err != nil {
			return err
		}
		return createSessionRevokedEvent(tx, &session, reason)
	})
}

func (r *SessionRepository) RevokeAllForUser(ctx context.Context, userID uuid.UUID, reason string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var sessions []models.SSOSession
		if err := tx.Where("user_id = ? AND status = ? AND revoked_at IS NULL", userID, "active").Find(&sessions).Error; err != nil {
			return err
		}
		for i := range sessions {
			if err := r.revoke(tx, sessions[i].ID, reason); err != nil {
				return err
			}
			if err := createSessionRevokedEvent(tx, &sessions[i], reason); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *SessionRepository) SetUserStatusAndRevoke(ctx context.Context, userID uuid.UUID, status, reason string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&models.User{}).Where("id = ?", userID).Update("status", status)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrUserNotFound
		}
		if status != "inactive" {
			return nil
		}
		var sessions []models.SSOSession
		if err := tx.Where("user_id = ? AND status = ? AND revoked_at IS NULL", userID, "active").Find(&sessions).Error; err != nil {
			return err
		}
		for i := range sessions {
			if err := r.revoke(tx, sessions[i].ID, reason); err != nil {
				return err
			}
			if err := createSessionRevokedEvent(tx, &sessions[i], reason); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *SessionRepository) IsAdminToken(ctx context.Context, tokenHash string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Table("sso_sessions s").
		Joins("JOIN users u ON u.id = s.user_id").
		Joins("JOIN user_groups ug ON ug.user_id = u.id").
		Joins("JOIN groups g ON g.id = ug.group_id").
		Where("s.session_token_hash = ? AND s.status = ? AND s.expires_at > ? AND s.revoked_at IS NULL AND u.status = ? AND g.name = ?", tokenHash, "active", time.Now(), "active", "administrators").
		Count(&count).Error
	return count > 0, err
}

func (r *SessionRepository) revoke(db *gorm.DB, id uuid.UUID, reason string) error {
	now := time.Now()
	result := db.Model(&models.SSOSession{}).
		Where("id = ? AND status = ? AND revoked_at IS NULL", id, "active").
		Updates(map[string]any{
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
