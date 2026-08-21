package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthHandlerConfigWithDefaultsCopiesSigningKey(t *testing.T) {
	key := []byte("signing-key")
	cfg := (AuthHandlerConfig{JWTSigningKey: key}).withDefaults()
	key[0] = 'X'

	if cfg.AuthCodeTTL != 3*time.Minute {
		t.Fatalf("unexpected auth-code TTL: %s", cfg.AuthCodeTTL)
	}
	if cfg.AccessTokenTTL != 15*time.Minute {
		t.Fatalf("unexpected access-token TTL: %s", cfg.AccessTokenTTL)
	}
	if cfg.SessionTTL != 12*time.Hour {
		t.Fatalf("unexpected session TTL: %s", cfg.SessionTTL)
	}
	if cfg.JWTIssuer != "auth-provider" || cfg.TokenStrategy != "jwt" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if string(cfg.JWTSigningKey) != "signing-key" {
		t.Fatalf("signing key was not copied")
	}
	if cfg.SecureCookies == nil || !*cfg.SecureCookies {
		t.Fatalf("secure-cookie default missing: %+v", cfg)
	}

	insecure := false
	explicit := (AuthHandlerConfig{SecureCookies: &insecure}).withDefaults()
	if explicit.SecureCookies == nil || *explicit.SecureCookies {
		t.Fatalf("explicit insecure-cookie setting was overridden: %+v", explicit)
	}
}

func TestSetAuthCookieUsesRequiredSecurityAttributes(t *testing.T) {
	response := httptest.NewRecorder()
	setAuthCookie(response, "sso_session", "raw-token", time.Hour, true)

	cookie := response.Result().Cookies()[0]
	if cookie.Value != "raw-token" {
		t.Fatalf("raw cookie value changed: %q", cookie.Value)
	}
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" {
		t.Fatalf("insecure cookie attributes: %+v", cookie)
	}
	if cookie.MaxAge != 3600 || cookie.Expires.IsZero() {
		t.Fatalf("cookie expiry missing: %+v", cookie)
	}
}

func TestWriteErrorUsesStandardEnvelopeAndRequestID(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/login", nil)
	request.Header.Set("X-Request-Id", "request-123")
	response := httptest.NewRecorder()

	writeError(response, request, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")

	var body struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"requestId"`
		} `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if body.Error.Code != "UNAUTHORIZED" || body.Error.Message != "invalid credentials" || body.Error.RequestID != "request-123" {
		t.Fatalf("unexpected error envelope: %+v", body)
	}
}
