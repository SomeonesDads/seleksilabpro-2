package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/repository"
	"github.com/SomeonesDads/seleksilabpro-2/shared/idgen"
	"github.com/google/uuid"
)

type logoutSessionStore struct {
	session       *models.SSOSession
	lookupHash    string
	revocationID  uuid.UUID
	revocationWhy string
	revocationErr error
	revocations   int
}

func (s *logoutSessionStore) FindActiveByTokenHash(_ context.Context, hash string) (*models.SSOSession, error) {
	s.lookupHash = hash
	if s.session == nil || !s.session.IsValid(time.Now()) {
		return nil, repository.ErrSessionNotFound
	}
	return s.session, nil
}

func (s *logoutSessionStore) FindActiveByID(context.Context, uuid.UUID) (*models.SSOSession, error) {
	return nil, repository.ErrSessionNotFound
}

func (s *logoutSessionStore) RevokeAndCreateEvent(_ context.Context, id uuid.UUID, reason string) error {
	if s.revocationErr != nil {
		return s.revocationErr
	}
	s.revocations++
	s.revocationID = id
	s.revocationWhy = reason
	if s.session == nil || !s.session.IsValid(time.Now()) {
		return repository.ErrSessionNotFound
	}
	now := time.Now()
	s.session.Status = "revoked"
	s.session.RevokedAt = &now
	s.session.RevokeReason = &reason
	return nil
}

func TestLogoutHashesCookieAndCommitsBeforeClearing(t *testing.T) {
	rawToken := "raw-session-token"
	session := &models.SSOSession{ID: uuid.New(), UserID: uuid.New(), Status: "active", ExpiresAt: time.Now().Add(time.Hour)}
	store := &logoutSessionStore{session: session}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{
		SessionLookup:     store,
		SessionRevocation: store,
	}, AuthHandlerConfig{}, nil)

	request := httptest.NewRequest(http.MethodPost, "/logout", nil)
	request.AddCookie(&http.Cookie{Name: ssoSessionCookie, Value: rawToken})
	response := httptest.NewRecorder()
	handler.Logout(response, request)

	if response.Code != http.StatusOK || store.lookupHash != idgen.HashToken(rawToken) {
		t.Fatalf("logout status/hash = %d/%q", response.Code, store.lookupHash)
	}
	if store.revocationID != session.ID || store.revocationWhy != "sso_logout" || store.revocations != 1 {
		t.Fatalf("revocation = id:%s reason:%q calls:%d", store.revocationID, store.revocationWhy, store.revocations)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != ssoSessionCookie || cookies[0].MaxAge != -1 {
		t.Fatalf("logout did not clear cookie after commit: %+v", cookies)
	}
}

func TestLogoutDoesNotClearCookieWhenRevocationFails(t *testing.T) {
	rawToken := "raw-session-token"
	store := &logoutSessionStore{
		session:       &models.SSOSession{ID: uuid.New(), UserID: uuid.New(), Status: "active", ExpiresAt: time.Now().Add(time.Hour)},
		revocationErr: errors.New("database unavailable"),
	}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{
		SessionLookup:     store,
		SessionRevocation: store,
	}, AuthHandlerConfig{}, nil)

	request := httptest.NewRequest(http.MethodPost, "/logout", nil)
	request.AddCookie(&http.Cookie{Name: ssoSessionCookie, Value: rawToken})
	response := httptest.NewRecorder()
	handler.Logout(response, request)

	if response.Code != http.StatusInternalServerError || len(response.Result().Cookies()) != 0 {
		t.Fatalf("failed logout changed cookie/status: status=%d cookies=%v", response.Code, response.Result().Cookies())
	}
}

func TestLogoutRepeatIsIdempotentWithoutDuplicateRevocation(t *testing.T) {
	rawToken := "raw-session-token"
	store := &logoutSessionStore{session: &models.SSOSession{ID: uuid.New(), UserID: uuid.New(), Status: "active", ExpiresAt: time.Now().Add(time.Hour)}}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{
		SessionLookup:     store,
		SessionRevocation: store,
	}, AuthHandlerConfig{}, nil)

	for range 2 {
		request := httptest.NewRequest(http.MethodPost, "/logout", nil)
		request.AddCookie(&http.Cookie{Name: ssoSessionCookie, Value: rawToken})
		response := httptest.NewRecorder()
		handler.Logout(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("repeat logout status = %d", response.Code)
		}
	}
	if store.revocations != 1 {
		t.Fatalf("repeat logout created %d revocations", store.revocations)
	}
}
