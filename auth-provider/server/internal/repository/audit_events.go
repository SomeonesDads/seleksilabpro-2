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
	return buildRevocationEvent(models.EventSessionRevoked, session.UserID, &session.ID, nil, reason)
}

func createPasswordChangedEvent(db *gorm.DB, session *models.SSOSession, reason string) error {
	return db.Create(buildPasswordChangedEvent(session, reason)).Error
}

func buildPasswordChangedEvent(session *models.SSOSession, reason string) *models.Event {
	return buildRevocationEvent(models.EventPasswordChanged, session.UserID, &session.ID, nil, reason)
}

func createAccessPolicyChangedEvent(db *gorm.DB, userID, applicationID uuid.UUID, reason string) error {
	return db.Create(buildAccessPolicyChangedEvent(userID, applicationID, reason)).Error
}

func buildAccessPolicyChangedEvent(userID, applicationID uuid.UUID, reason string) *models.Event {
	return buildRevocationEvent(models.EventAccessPolicyChanged, userID, nil, &applicationID, reason)
}

func buildRevocationEvent(eventType string, userID uuid.UUID, sessionID, applicationID *uuid.UUID, reason string) *models.Event {
	eventID := uuid.New()
	occurredAt := time.Now().UTC()
	return &models.Event{
		ID:               eventID,
		EventType:        eventType,
		UserID:           userID,
		CentralSessionID: sessionID,
		ApplicationID:    applicationID,
		Payload: map[string]any{
			"eventId":          eventID.String(),
			"eventType":        eventType,
			"userId":           userID.String(),
			"centralSessionId": uuidString(sessionID),
			"applicationId":    uuidString(applicationID),
			"reason":           reason,
			"occurredAt":       occurredAt.Format(time.RFC3339Nano),
			"metadata":         map[string]any{},
		},
		Status:    "pending",
		CreatedAt: occurredAt,
	}
}

func uuidString(id *uuid.UUID) any {
	if id == nil {
		return nil
	}
	return id.String()
}
