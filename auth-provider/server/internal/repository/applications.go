package repository

import (
	"context"
	"errors"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var ErrApplicationNotFound = errors.New("application not found")

type ApplicationRepository struct{ db *gorm.DB }

func NewApplicationRepository(db *gorm.DB) *ApplicationRepository {
	return &ApplicationRepository{db: db}
}

func (r *ApplicationRepository) FindByClientID(ctx context.Context, clientID string) (*models.Application, error) {
	var app models.Application
	err := r.db.WithContext(ctx).Where("client_id = ?", clientID).First(&app).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrApplicationNotFound
	}
	if err != nil {
		return nil, err
	}
	return &app, nil
}

func (r *ApplicationRepository) HasExactRedirectURI(ctx context.Context, applicationID uuid.UUID, redirectURI string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.ApplicationRedirectURI{}).
		Where("application_id = ? AND redirect_uri = ?", applicationID, redirectURI).
		Count(&count).Error
	return count == 1, err
}

func (r *ApplicationRepository) VerifyClientSecret(ctx context.Context, clientID, clientSecret string) (bool, error) {
	app, err := r.FindByClientID(ctx, clientID)
	if err != nil {
		return false, err
	}
	if app.ClientSecretHash == nil {
		return false, nil
	}
	return bcrypt.CompareHashAndPassword([]byte(*app.ClientSecretHash), []byte(clientSecret)) == nil, nil
}
