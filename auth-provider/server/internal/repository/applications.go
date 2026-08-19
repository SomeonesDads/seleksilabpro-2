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

func (r *ApplicationRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.Application, error) {
	var app models.Application
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&app).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrApplicationNotFound
	}
	if err != nil {
		return nil, err
	}
	return &app, nil
}

func (r *ApplicationRepository) List(ctx context.Context) ([]models.Application, error) {
	var applications []models.Application
	err := r.db.WithContext(ctx).Order("created_at ASC").Find(&applications).Error
	return applications, err
}

func (r *ApplicationRepository) CreateWithSecret(ctx context.Context, application *models.Application, clientSecret string) error {
	return r.createWithSecret(ctx, r.db.WithContext(ctx), application, clientSecret)
}

func (r *ApplicationRepository) CreateWithSecretAndRedirect(ctx context.Context, application *models.Application, clientSecret, redirectURI string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := r.createWithSecret(ctx, tx, application, clientSecret); err != nil {
			return err
		}
		return tx.Create(&models.ApplicationRedirectURI{ApplicationID: application.ID, RedirectURI: redirectURI}).Error
	})
}

func (r *ApplicationRepository) createWithSecret(ctx context.Context, db *gorm.DB, application *models.Application, clientSecret string) error {
	if clientSecret != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		hashText := string(hash)
		application.ClientSecretHash = &hashText
	}
	return db.WithContext(ctx).Create(application).Error
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

func (r *ApplicationRepository) AddRedirectURI(ctx context.Context, redirectURI *models.ApplicationRedirectURI) error {
	return r.db.WithContext(ctx).Create(redirectURI).Error
}
