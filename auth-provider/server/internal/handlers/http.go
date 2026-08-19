package handlers

import (
	"net/http"
	"time"

	sharederrors "github.com/SomeonesDads/seleksilabpro-2/shared/errors"
	"github.com/SomeonesDads/seleksilabpro-2/shared/logging"
	"github.com/google/uuid"
)

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	requestID := logging.RequestID(r.Context())
	if requestID == "" {
		requestID = r.Header.Get("X-Request-Id")
	}
	if requestID == "" {
		requestID = uuid.NewString()
	}
	sharederrors.Write(w, status, code, message, requestID)
}

func setAuthCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
		Expires:  time.Now().Add(ttl),
	})
}

func clearAuthCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
	})
}
