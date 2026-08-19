package repository

import (
	"testing"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/google/uuid"
)

func TestPasswordChangedEventUsesPasswordChangedType(t *testing.T) {
	session := &models.SSOSession{ID: uuid.New(), UserID: uuid.New()}
	event := buildPasswordChangedEvent(session, "password_changed")

	if event.EventType != models.EventPasswordChanged || event.Payload["eventType"] != models.EventPasswordChanged {
		t.Fatalf("password event type = %q/%v", event.EventType, event.Payload["eventType"])
	}
	if event.Payload["centralSessionId"] != session.ID.String() || event.Payload["applicationId"] != nil {
		t.Fatalf("password event target = %+v", event.Payload)
	}
}

func TestAccessPolicyChangedEventTargetsApplication(t *testing.T) {
	userID := uuid.New()
	applicationID := uuid.New()
	event := buildAccessPolicyChangedEvent(userID, applicationID, "access_policy_changed")

	if event.EventType != models.EventAccessPolicyChanged || event.UserID != userID || event.ApplicationID == nil || *event.ApplicationID != applicationID {
		t.Fatalf("policy event = %+v", event)
	}
	if event.Payload["eventType"] != models.EventAccessPolicyChanged || event.Payload["userId"] != userID.String() || event.Payload["applicationId"] != applicationID.String() || event.Payload["centralSessionId"] != nil {
		t.Fatalf("policy payload = %+v", event.Payload)
	}
}
