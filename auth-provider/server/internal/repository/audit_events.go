package repository

import (
	"context"
	"errors"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"gorm.io/gorm"
)

var ErrEventNotFound = errors.New("event not found")

type AuditRepository struct{ db *gorm.DB }

func NewAuditRepository(db *gorm.DB) *AuditRepository { return &AuditRepository{db: db} }

func (r *AuditRepository) WriteAuditLog(ctx context.Context, log *models.AuditLog) error {
	return r.db.WithContext(ctx).Create(log).Error
}

type EventRepository struct{ db *gorm.DB }

func NewEventRepository(db *gorm.DB) *EventRepository { return &EventRepository{db: db} }

func (r *EventRepository) CreateSessionRevokedEvent(ctx context.Context, session *models.SSOSession, reason string) error {
	return createSessionRevokedEvent(r.db.WithContext(ctx), session, reason)
}

func createSessionRevokedEvent(db *gorm.DB, session *models.SSOSession, reason string) error {
	event := &models.Event{
		EventType:        models.EventSessionRevoked,
		UserID:           session.UserID,
		CentralSessionID: &session.ID,
		Payload:          map[string]any{"reason": reason},
		Status:           "pending",
	}
	return db.Create(event).Error
}
