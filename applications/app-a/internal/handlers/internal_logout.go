package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// revocationEvent mirrors the event payload published by the Auth Provider and
// delivered by the Sync Worker (F05 payload contract).
type revocationEvent struct {
	EventID          uuid.UUID  `json:"eventId"`
	EventType        string     `json:"eventType"`
	UserID           uuid.UUID  `json:"userId"`
	CentralSessionID *uuid.UUID `json:"centralSessionId"`
	ApplicationID    *uuid.UUID `json:"applicationId"`
	Reason           string     `json:"reason"`
	OccurredAt       time.Time  `json:"occurredAt"`
	Metadata         map[string]any `json:"metadata,omitempty"`
}

// InternalLogout receives asynchronous revocation events from the Sync Worker.
// It authenticates the caller with the shared X-Internal-Auth token, processes
// each event idempotently by eventId, and revokes the affected local sessions.
func (a *App) InternalLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.writeError(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	if a.Config.InternalAuthToken == "" {
		a.log().Error("internal auth token not configured")
		a.writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "revocation unavailable")
		return
	}
	if r.Header.Get("X-Internal-Auth") != a.Config.InternalAuthToken {
		a.log().Warn("rejected internal logout with invalid auth token")
		a.writeError(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "invalid internal authentication")
		return
	}

	var event revocationEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		a.writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid event payload")
		return
	}
	if event.EventID == uuid.Nil || event.UserID == uuid.Nil || event.EventType == "" {
		a.writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid event payload")
		return
	}

	now := time.Now().UTC()
	reason := event.Reason
	if reason == "" {
		reason = event.EventType
	}

	// Validate the event's semantics BEFORE performing any side effect or
	// recording it, so malformed or misrouted events are rejected (400) rather
	// than silently recorded as processed.
	switch event.EventType {
	case "SessionRevoked":
		if event.CentralSessionID == nil {
			a.writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "SessionRevoked event missing centralSessionId")
			return
		}
	case "AccessPolicyChanged":
		if event.ApplicationID == nil {
			a.writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "AccessPolicyChanged event missing applicationId")
			return
		}
		if a.Config.AppID != "" && event.ApplicationID.String() != a.Config.AppID {
			a.writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "event not targeted at this application")
			return
		}
	case "PasswordChanged":
		// Revokes every local session this application holds for the user.
	default:
		a.writeError(w, r, http.StatusBadRequest, "UNSUPPORTED_EVENT", "unsupported event type")
		return
	}

	// Record the processed event and apply the revocation in a single
	// transaction. The event_id unique constraint makes this exactly-once: the
	// first delivery inserts and revokes; a concurrent or replayed duplicate
	// hits the unique constraint and skips the revocation, so the update is
	// applied at most once.
	csid := ""
	if event.CentralSessionID != nil {
		csid = event.CentralSessionID.String()
	}
	inserted, revoked, procErr := a.Store.ProcessRevocation(r.Context(), event.EventID, event.EventType, "local_sessions_revoked", event.UserID.String(), csid, reason, now)
	if procErr != nil {
		a.log().Error("revocation processing failed", "err", procErr)
		a.writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "revocation unavailable")
		return
	}
	if !inserted {
		_ = a.Store.AddActivity(r.Context(), "event_duplicate", "Duplicate "+event.EventType+" acknowledged", event.EventID.String(), nil)
		w.WriteHeader(http.StatusOK)
		return
	}

	_ = a.Store.AddActivity(r.Context(), "event_processed",
		event.EventType+" revoked "+itoa(revoked)+" local session(s)", event.EventID.String(), nil)

	w.WriteHeader(http.StatusOK)
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

var _ = errors.New
var _ = slog.Default
