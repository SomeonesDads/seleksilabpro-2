package repository

import (
	"context"
	"errors"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/google/uuid"
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
	return db.Create(buildSessionRevokedEvent(session, reason)).Error
}

func buildSessionRevokedEvent(session *models.SSOSession, reason string) *models.Event {
	eventID := uuid.New()
	occurredAt := time.Now().UTC()
	return &models.Event{
		ID:               eventID,
		EventType:        models.EventSessionRevoked,
		UserID:           session.UserID,
		CentralSessionID: &session.ID,
		Payload: map[string]any{
			"eventId":          eventID.String(),
			"eventType":        models.EventSessionRevoked,
			"userId":           session.UserID.String(),
			"centralSessionId": session.ID.String(),
			"applicationId":    nil,
			"reason":           reason,
			"occurredAt":       occurredAt.Format(time.RFC3339Nano),
			"metadata":         map[string]any{},
		},
		Status:    "pending",
		CreatedAt: occurredAt,
	}
}
