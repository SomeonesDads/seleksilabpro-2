package repository

import (
	"context"
	"errors"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

var ErrAccessTokenNotFound = errors.New("access token not found")

type AccessTokenRepository struct{ db *gorm.DB }

func NewAccessTokenRepository(db *gorm.DB) *AccessTokenRepository {
	return &AccessTokenRepository{db: db}
}

func (r *AccessTokenRepository) Create(ctx context.Context, token *models.AccessToken) error {
	return r.db.WithContext(ctx).Create(token).Error
}

// FindActiveByJTI keeps revocation and expiry checks in the repository so
// callers cannot accidentally validate metadata without both guards.
func (r *AccessTokenRepository) FindActiveByJTI(ctx context.Context, jti uuid.UUID) (*models.AccessToken, error) {
	var token models.AccessToken
	err := r.db.WithContext(ctx).
		Where("jti = ? AND revoked_at IS NULL AND expires_at > ?", jti, time.Now()).
		First(&token).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrAccessTokenNotFound
	}
	if err != nil {
		return nil, err
	}
	return &token, nil
}
