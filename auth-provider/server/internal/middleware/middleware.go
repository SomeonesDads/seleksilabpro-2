package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	sharederrors "github.com/SomeonesDads/seleksilabpro-2/shared/errors"
	"github.com/SomeonesDads/seleksilabpro-2/shared/idgen"
	"github.com/SomeonesDads/seleksilabpro-2/shared/logging"
	"github.com/google/uuid"
)

// RequestLogger logs method, path, status, and duration for every request,
// tagged with the correlation id set by logging.WithRequestID.
func RequestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)
			logger.Info("request",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", sw.status),
				slog.Duration("duration", time.Since(start)),
				slog.String("requestId", logging.RequestID(r.Context())),
			)
		})
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// RequireAdmin keeps legacy callers fail-closed. Production wiring should use
// RequireAdminWithAuthenticator with the session repository.
type AdminAuthenticator interface {
	IsAdminToken(context.Context, string) (bool, error)
}

func RequireAdmin(next http.Handler) http.Handler {
	return RequireAdminWithAuthenticator(nil, next)
}

func RequireAdminWithAuthenticator(auth AdminAuthenticator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := logging.RequestID(r.Context())
		if requestID == "" {
			requestID = r.Header.Get("X-Request-Id")
		}
		if requestID == "" {
			requestID = uuid.NewString()
		}
		cookie, err := r.Cookie("sso_session")
		if err != nil || cookie.Value == "" || auth == nil {
			sharederrors.Write(w, http.StatusUnauthorized,
				sharederrors.CodeUnauthorized,
				"authentication required",
				requestID)
			return
		}
		authenticated, err := auth.IsAdminToken(r.Context(), idgen.HashToken(cookie.Value))
		if err != nil {
			sharederrors.Write(w, http.StatusInternalServerError,
				sharederrors.CodeInternal,
				"authentication unavailable",
				requestID)
			return
		}
		if !authenticated {
			sharederrors.Write(w, http.StatusForbidden,
				sharederrors.CodeAccessDenied,
				"access denied",
				requestID)
			return
		}
		next.ServeHTTP(w, r)
	})
}
