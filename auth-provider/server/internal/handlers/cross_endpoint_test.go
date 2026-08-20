package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/SomeonesDads/seleksilabpro-2/shared/idgen"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// TestAuthorizeNegativePathsCreateNoCodeOrSession closes the finals.md item 5
// acceptance line: no authorization code or central session is created on an
// invalid redirect URI or on policy denial.
func TestAuthorizeNegativePathsCreateNoCodeOrSession(t *testing.T) {
	application := models.Application{ID: uuid.New(), ClientID: "app-client", Status: "active"}
	userID := uuid.New()
	rawSession := "session-token"
	session := &models.SSOSession{ID: uuid.New(), UserID: userID, SessionTokenHash: idgen.HashToken(rawSession), Status: "active", ExpiresAt: time.Now().Add(time.Hour)}

	cases := []struct {
		name          string
		policyAllowed bool
		redirectURI   string
	}{
		{name: "invalid redirect uri", policyAllowed: true, redirectURI: "https://app.example/callback.evil"},
		{name: "policy denied", policyAllowed: false, redirectURI: "https://app.example/callback"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sessions := &flowSessions{byHash: map[string]*models.SSOSession{session.SessionTokenHash: session}}
			codes := &flowCodes{}
			handler := NewAuthHandlerWithDependencies(AuthRepositories{
				Users:             &flowUsers{user: models.User{ID: userID, Status: "active"}},
				Applications:      &flowApplications{application: application},
				Policies:          flowPolicy{allowed: tc.policyAllowed},
				Sessions:          sessions,
				AuthorizationCode: codes,
			}, AuthHandlerConfig{}, nil)

			path := "/authorize?response_type=code&client_id=app-client&redirect_uri=" + url.QueryEscape(tc.redirectURI) + "&state=state&code_challenge=" + testPKCEChallenge + "&code_challenge_method=S256"
			request := httptest.NewRequest(http.MethodGet, path, nil)
			request.AddCookie(&http.Cookie{Name: ssoSessionCookie, Value: rawSession})
			response := httptest.NewRecorder()
			handler.Authorize(response, request)

			if codes.code != nil {
				t.Fatalf("%s unexpectedly created an authorization code: %+v", tc.name, codes.code)
			}
			if sessions.created != nil {
				t.Fatalf("%s unexpectedly created a central session: %+v", tc.name, sessions.created)
			}
		})
	}
}

// TestLoginPageRendersSafeForm closes SPECS B1: GET /login renders a login
// form and only accepts re-validated login intents (no trusted hidden fields).
func TestLoginPageRendersSafeForm(t *testing.T) {
	handler := NewAuthHandlerWithDependencies(AuthRepositories{}, AuthHandlerConfig{}, nil)

	request := httptest.NewRequest(http.MethodGet, "/login", nil)
	response := httptest.NewRecorder()
	handler.LoginPage(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("login page status = %d, body = %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `<form method="post" action="/login"`) ||
		!strings.Contains(body, `name="email"`) ||
		!strings.Contains(body, `name="password"`) {
		t.Fatalf("login page did not render the expected form: %s", body)
	}
}

// TestLoginPersistsSessionSecurityContext closes SPECS B6: a successful login
// persists the session with active status, future expiry, and the request's
// IP address and user agent for audit.
func TestLoginPersistsSessionSecurityContext(t *testing.T) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	sessions := &flowSessions{byHash: make(map[string]*models.SSOSession)}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{
		Users:    &flowUsers{user: models.User{ID: uuid.New(), Email: "ada@example.com", PasswordHash: string(passwordHash), Status: "active"}},
		TOTP:     emptyFlowTOTP{},
		Sessions: sessions,
	}, AuthHandlerConfig{SessionTTL: time.Minute}, nil)

	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"email":"ada@example.com","password":"password"}`))
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "203.0.113.7:54321"
	request.Header.Set("User-Agent", "test-agent")
	response := httptest.NewRecorder()
	handler.Login(response, request)

	if response.Code != http.StatusOK || sessions.created == nil {
		t.Fatalf("login failed: status=%d body=%s", response.Code, response.Body.String())
	}
	s := sessions.created
	if s.Status != "active" {
		t.Fatalf("session status = %q, want active", s.Status)
	}
	if s.ExpiresAt.IsZero() || !s.ExpiresAt.After(time.Now()) {
		t.Fatalf("session has no future expiry: %+v", s.ExpiresAt)
	}
	if s.IPAddress == nil || *s.IPAddress != "203.0.113.7:54321" {
		t.Fatalf("session IP address not captured: %v", s.IPAddress)
	}
	if s.UserAgent == nil || *s.UserAgent != "test-agent" {
		t.Fatalf("session user agent not captured: %v", s.UserAgent)
	}
}

// TestLoginRejectsDuplicateReturnToParameter closes the cross-endpoint
// validation gap: /login must reject duplicate return_to (login-intent)
// parameters instead of silently taking the first, mirroring /authorize.
func TestLoginRejectsDuplicateReturnToParameter(t *testing.T) {
	sessions := &flowSessions{byHash: make(map[string]*models.SSOSession)}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{
		Users:    &flowUsers{},
		TOTP:     emptyFlowTOTP{},
		Sessions: sessions,
	}, AuthHandlerConfig{}, nil)

	body := "email=ada@example.com&password=password&return_to=/authorize%3Fa&return_to=/authorize%3Fb"
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.Login(response, request)

	if response.Code != http.StatusUnauthorized || sessions.created != nil {
		t.Fatalf("duplicate return_to was not rejected: status=%d session=%+v", response.Code, sessions.created)
	}
}

// TestLoginMalformedBodyAuditsFailure closes the audit gap: a malformed login
// body still records a LoginFailed audit event (it must not return silently).
func TestLoginMalformedBodyAuditsFailure(t *testing.T) {
	audit := &flowAudit{}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{
		Users: &flowUsers{},
		Audit: audit,
	}, AuthHandlerConfig{}, nil)

	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{not json`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.Login(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("malformed login body status = %d", response.Code)
	}
	if len(audit.events) != 1 || audit.events[0].EventType != "LoginFailed" || audit.events[0].Result != "failed" {
		t.Fatalf("malformed login body was not audited: %+v", audit.events)
	}
}

// TestLoginPageRejectsDuplicateReturnToParameter closes the cross-endpoint
// validation gap for the GET /login page: duplicate return_to (login-intent)
// query parameters must be rejected, not silently read via Query().Get().
func TestLoginPageRejectsDuplicateReturnToParameter(t *testing.T) {
	handler := NewAuthHandlerWithDependencies(AuthRepositories{}, AuthHandlerConfig{}, nil)
	request := httptest.NewRequest(http.MethodGet, "/login?return_to=/authorize%3Fa&return_to=/authorize%3Fb", nil)
	response := httptest.NewRecorder()
	handler.LoginPage(response, request)
	if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), "<form") {
		t.Fatalf("duplicate return_to was not rejected by login page: status=%d body=%s", response.Code, response.Body.String())
	}
}

// TestLoginMFADuplicateParameterRejected closes the validation gap for
// POST /login/mfa: duplicate form fields (code/return_to) must be rejected.
func TestLoginMFADuplicateParameterRejected(t *testing.T) {
	handler := NewAuthHandlerWithDependencies(AuthRepositories{}, AuthHandlerConfig{}, nil)
	body := "code=123456&return_to=/authorize%3Fa&return_to=/authorize%3Fb"
	request := httptest.NewRequest(http.MethodPost, "/login/mfa", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.LoginMFA(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate MFA parameter was not rejected: status=%d body=%s", response.Code, response.Body.String())
	}
}
