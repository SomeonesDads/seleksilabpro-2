package repository

import (
	"context"
	"errors"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

var ErrAuthorizationCodeNotFound = errors.New("authorization code not found")

type AuthorizationCodeRepository struct{ db *gorm.DB }

func NewAuthorizationCodeRepository(db *gorm.DB) *AuthorizationCodeRepository {
	return &AuthorizationCodeRepository{db: db}
}

func (r *AuthorizationCodeRepository) Create(ctx context.Context, code *models.AuthorizationCode) error {
	return r.db.WithContext(ctx).Create(code).Error
}

func (r *AuthorizationCodeRepository) FindByHash(ctx context.Context, codeHash string) (*models.AuthorizationCode, error) {
	var code models.AuthorizationCode
	err := r.db.WithContext(ctx).Where("code_hash = ?", codeHash).First(&code).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrAuthorizationCodeNotFound
	}
	if err != nil {
		return nil, err
	}
	return &code, nil
}

func (r *AuthorizationCodeRepository) ConsumeAtomically(ctx context.Context, id uuid.UUID) error {
	result := r.db.WithContext(ctx).Model(&models.AuthorizationCode{}).
		Where("id = ? AND used_at IS NULL AND expires_at > now()", id).
		UpdateColumn("used_at", gorm.Expr("now()"))
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrAuthorizationCodeNotFound
	}
	return nil
}

// Redeem consumes an authorization code and persists its token metadata in one
// transaction. A failed metadata insert rolls back the code consumption.
func (r *AuthorizationCodeRepository) Redeem(ctx context.Context, id uuid.UUID, token *models.AccessToken) error {
	if token == nil {
		return errors.New("access token metadata is required")
	}
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&models.AuthorizationCode{}).
			Where("id = ? AND used_at IS NULL AND expires_at > now()", id).
			UpdateColumn("used_at", gorm.Expr("now()"))
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrAuthorizationCodeNotFound
		}
		return tx.Create(token).Error
	})
}
