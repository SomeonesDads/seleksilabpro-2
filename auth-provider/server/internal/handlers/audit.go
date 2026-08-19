package handlers

import (
	"log/slog"
	"net/http"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/google/uuid"
)

// audit records only identifiers and caller context. Credentials, raw
// cookies, authorization codes, and client secrets never enter metadata.
func (h *AuthHandler) audit(r *http.Request, eventType, result string, userID, applicationID, sessionID *uuid.UUID, metadata map[string]any) {
	if h.Audit == nil {
		return
	}
	entry := &models.AuditLog{
		EventType:     eventType,
		UserID:        userID,
		ApplicationID: applicationID,
		SessionID:     sessionID,
		Result:        result,
		Metadata:      metadata,
		IPAddress:     stringPtr(r.RemoteAddr),
	}
	if err := h.Audit.WriteAuditLog(r.Context(), entry); err != nil {
		h.log().Error("audit write failed", slog.String("eventType", eventType), slog.Any("err", err))
	}
}
