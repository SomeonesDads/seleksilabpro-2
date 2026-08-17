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
