package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/repository"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/tokens"
	sharederrors "github.com/SomeonesDads/seleksilabpro-2/shared/errors"
	"github.com/SomeonesDads/seleksilabpro-2/shared/idgen"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func acceptanceCookie(t *testing.T, response *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("response did not set %q cookie: %v", name, response.Result().Cookies())
	return nil
}

func assertAcceptanceError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d, want %d, body = %s", response.Code, status, response.Body.String())
	}
	var body struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"requestId"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error envelope: %v; body=%s", err, response.Body.String())
	}
	if body.Error.Code != code || body.Error.Message == "" || body.Error.RequestID == "" {
		t.Fatalf("invalid error envelope: %+v", body)
	}
}

func acceptanceAuthorizeURL(redirectURI, challenge string) string {
	return "/authorize?response_type=code&client_id=app-client&redirect_uri=" + url.QueryEscape(redirectURI) + "&state=state-123&code_challenge=" + url.QueryEscape(challenge) + "&code_challenge_method=S256"
}

func TestLoginAcceptanceCoversCredentialFailuresCookieSecurityAndAudit(t *testing.T) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name        string
		user        *models.User
		password    string
		wantStatus  int
		wantSession bool
	}{
		{
			name:        "valid credential",
			user:        &models.User{ID: uuid.New(), Name: "Ada", Email: "ada@example.com", PasswordHash: string(passwordHash), Status: "active"},
			password:    "password",
			wantStatus:  http.StatusOK,
			wantSession: true,
		},
		{
			name:       "wrong password",
			user:       &models.User{ID: uuid.New(), Email: "ada@example.com", PasswordHash: string(passwordHash), Status: "active"},
			password:   "wrong",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "unknown user",
			password:   "password",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "inactive user",
			user:       &models.User{ID: uuid.New(), Email: "ada@example.com", PasswordHash: string(passwordHash), Status: "inactive"},
			password:   "password",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			users := &flowUsers{}
			if tc.user != nil {
				users.user = *tc.user
			}
			sessions := &flowSessions{byHash: make(map[string]*models.SSOSession)}
			audit := &flowAudit{}
			handler := NewAuthHandlerWithDependencies(AuthRepositories{
				Users:    users,
				TOTP:     emptyFlowTOTP{},
				Sessions: sessions,
				Audit:    audit,
			}, AuthHandlerConfig{SessionTTL: time.Minute}, nil)

			request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"email":"ada@example.com","password":"`+tc.password+`"}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Request-Id", "login-request")
			response := httptest.NewRecorder()
			handler.Login(response, request)

			if response.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d, body = %s", response.Code, tc.wantStatus, response.Body.String())
			}
			if tc.wantSession {
				cookie := acceptanceCookie(t, response, ssoSessionCookie)
				if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.MaxAge != 60 || cookie.Expires.IsZero() {
					t.Fatalf("insecure or non-expiring session cookie: %+v", cookie)
				}
				if sessions.created == nil || sessions.created.SessionTokenHash != idgen.HashToken(cookie.Value) || sessions.created.SessionTokenHash == cookie.Value {
					t.Fatalf("session token was not persisted hash-only: session=%+v cookie=%q", sessions.created, cookie.Value)
				}
				if len(audit.events) != 1 || audit.events[0].EventType != "LoginSucceeded" || audit.events[0].Result != "success" {
					t.Fatalf("successful login was not audited: %+v", audit.events)
				}
				return
			}

			assertAcceptanceError(t, response, http.StatusUnauthorized, sharederrors.CodeUnauthorized)
			if sessions.created != nil || strings.Contains(response.Body.String(), "ada@example.com") || strings.Contains(response.Body.String(), tc.password) {
				t.Fatalf("credential failure leaked state or created session: body=%s session=%+v", response.Body.String(), sessions.created)
			}
			if len(audit.events) != 1 || audit.events[0].EventType != "LoginFailed" || audit.events[0].Result != "failed" {
				t.Fatalf("failed login was not audited: %+v", audit.events)
			}
		})
	}
}

func TestMFAAcceptanceCoversPendingExpiryAttemptLimitFinalAttemptAndReplay(t *testing.T) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	mfa := &flowMFA{}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{
		Users: &flowUsers{user: models.User{ID: uuid.New(), Email: "ada@example.com", PasswordHash: string(passwordHash), Status: "active"}},
		TOTP:  flowTOTP{},
		MFA:   mfa,
	}, AuthHandlerConfig{}, nil)
	handler.VerifyMFA = func(context.Context, uuid.UUID, string) bool { return false }

	loginRequest := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"email":"ada@example.com","password":"password"}`))
	loginRequest.Header.Set("Content-Type", "application/json")
	loginResponse := httptest.NewRecorder()
	handler.Login(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusOK || mfa.challenge == nil {
		t.Fatalf("pending MFA state was not created: status=%d body=%s", loginResponse.Code, loginResponse.Body.String())
	}
	pendingCookie := acceptanceCookie(t, loginResponse, mfaPendingCookie)
	if !pendingCookie.HttpOnly || !pendingCookie.Secure || pendingCookie.SameSite != http.SameSiteLaxMode || pendingCookie.Path != "/" || pendingCookie.MaxAge != int(mfaChallengeTTL.Seconds()) || pendingCookie.Expires.IsZero() {
		t.Fatalf("insecure or non-expiring pending-MFA cookie: %+v", pendingCookie)
	}
	if pendingCookie.Value == mfa.challenge.TokenHash {
		t.Fatalf("pending MFA token was persisted raw: cookie=%q hash=%q", pendingCookie.Value, mfa.challenge.TokenHash)
	}
	if mfa.createdSession != nil {
		t.Fatal("password verification created central session before MFA")
	}

	invalidRequest := httptest.NewRequest(http.MethodPost, "/login/mfa", strings.NewReader(`{"code":"000000"}`))
	invalidRequest.Header.Set("Content-Type", "application/json")
	invalidRequest.AddCookie(pendingCookie)
	invalidResponse := httptest.NewRecorder()
	handler.LoginMFA(invalidResponse, invalidRequest)
	assertAcceptanceError(t, invalidResponse, http.StatusUnauthorized, sharederrors.CodeUnauthorized)
	if mfa.createdSession != nil {
		t.Fatal("invalid MFA code created central session")
	}

	mfa.challenge.ExpiresAt = time.Now().Add(-time.Second)
	expiredRequest := httptest.NewRequest(http.MethodPost, "/login/mfa", strings.NewReader(`{"code":"123456"}`))
	expiredRequest.Header.Set("Content-Type", "application/json")
	expiredRequest.AddCookie(pendingCookie)
	expiredResponse := httptest.NewRecorder()
	handler.LoginMFA(expiredResponse, expiredRequest)
	assertAcceptanceError(t, expiredResponse, http.StatusUnauthorized, sharederrors.CodeUnauthorized)
	if mfa.createdSession != nil {
		t.Fatal("expired MFA state created central session")
	}

	mfa.challenge.ExpiresAt = time.Now().Add(time.Minute)
	mfa.challenge.Attempts = mfaMaxAttempts
	limitedRequest := httptest.NewRequest(http.MethodPost, "/login/mfa", strings.NewReader(`{"code":"123456"}`))
	limitedRequest.Header.Set("Content-Type", "application/json")
	limitedRequest.AddCookie(pendingCookie)
	limitedResponse := httptest.NewRecorder()
	handler.LoginMFA(limitedResponse, limitedRequest)
	assertAcceptanceError(t, limitedResponse, http.StatusUnauthorized, sharederrors.CodeUnauthorized)
	if mfa.createdSession != nil {
		t.Fatal("attempt-limited MFA state created central session")
	}

	mfa.challenge.Attempts = mfaMaxAttempts - 1
	handler.VerifyMFA = func(context.Context, uuid.UUID, string) bool { return true }
	finalRequest := httptest.NewRequest(http.MethodPost, "/login/mfa", strings.NewReader(`{"code":"123456"}`))
	finalRequest.Header.Set("Content-Type", "application/json")
	finalRequest.AddCookie(pendingCookie)
	finalResponse := httptest.NewRecorder()
	handler.LoginMFA(finalResponse, finalRequest)
	if finalResponse.Code != http.StatusOK || mfa.createdSession == nil {
		t.Fatalf("valid final MFA attempt failed: status=%d body=%s", finalResponse.Code, finalResponse.Body.String())
	}
	acceptanceCookie(t, finalResponse, ssoSessionCookie)
	clearedPending := acceptanceCookie(t, finalResponse, mfaPendingCookie)
	if clearedPending.MaxAge != -1 || clearedPending.Value != "" {
		t.Fatalf("pending MFA cookie was not cleared: %+v", clearedPending)
	}

	replayRequest := httptest.NewRequest(http.MethodPost, "/login/mfa", strings.NewReader(`{"code":"123456"}`))
	replayRequest.Header.Set("Content-Type", "application/json")
	replayRequest.AddCookie(pendingCookie)
	replayResponse := httptest.NewRecorder()
	handler.LoginMFA(replayResponse, replayRequest)
	assertAcceptanceError(t, replayResponse, http.StatusUnauthorized, sharederrors.CodeUnauthorized)
}

func TestAuthorizeAcceptancePreservesStateAndStoresShortLivedCodeHash(t *testing.T) {
	user := models.User{ID: uuid.New(), Status: "active"}
	application := models.Application{ID: uuid.New(), ClientID: "app-client", Status: "active"}
	rawSession := "session-token"
	session := &models.SSOSession{ID: uuid.New(), UserID: user.ID, SessionTokenHash: idgen.HashToken(rawSession), Status: "active", ExpiresAt: time.Now().Add(time.Hour)}
	codes := &flowCodes{}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{
		Users:             &flowUsers{user: user},
		Applications:      &flowApplications{application: application},
		Policies:          flowPolicy{allowed: true},
		Sessions:          &flowSessions{byHash: map[string]*models.SSOSession{session.SessionTokenHash: session}},
		AuthorizationCode: codes,
	}, AuthHandlerConfig{AuthCodeTTL: time.Minute}, nil)

	verifier := "verifier"
	request := httptest.NewRequest(http.MethodGet, acceptanceAuthorizeURL("https://app.example/callback", idgen.PKCEChallengeS256(verifier)), nil)
	request.AddCookie(&http.Cookie{Name: ssoSessionCookie, Value: rawSession})
	response := httptest.NewRecorder()
	handler.Authorize(response, request)
	if response.Code != http.StatusFound {
		t.Fatalf("authorize status = %d, body = %s", response.Code, response.Body.String())
	}
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Query().Get("state") != "state-123" || location.Query().Get("code") == "" {
		t.Fatalf("authorize redirect lost state or code: %q", location.String())
	}
	if codes.code == nil || codes.code.CodeHash == location.Query().Get("code") || codes.code.ExpiresAt.Before(time.Now()) || codes.code.ExpiresAt.After(time.Now().Add(2*time.Minute)) {
		t.Fatalf("authorization code was not short-lived and hash-only: %+v", codes.code)
	}
	if codes.code.RedirectURI != "https://app.example/callback" || codes.code.CodeChallenge != idgen.PKCEChallengeS256(verifier) || codes.code.CodeChallengeMethod != "S256" {
		t.Fatalf("authorization code binding incomplete: %+v", codes.code)
	}
}

func TestAuthorizeAcceptanceRejectsInvalidClientRedirectAndPKCEWithoutRedirecting(t *testing.T) {
	cases := []struct {
		name string
		app  models.Application
		path string
	}{
		{
			name: "unknown client",
			app:  models.Application{ID: uuid.New(), ClientID: "different-client", Status: "active"},
			path: acceptanceAuthorizeURL("https://app.example/callback", testPKCEChallenge),
		},
		{
			name: "inactive client",
			app:  models.Application{ID: uuid.New(), ClientID: "app-client", Status: "inactive"},
			path: acceptanceAuthorizeURL("https://app.example/callback", testPKCEChallenge),
		},
		{
			name: "prefix redirect",
			app:  models.Application{ID: uuid.New(), ClientID: "app-client", Status: "active"},
			path: acceptanceAuthorizeURL("https://app.example/callback.evil", testPKCEChallenge),
		},
		{
			name: "invalid PKCE",
			app:  models.Application{ID: uuid.New(), ClientID: "app-client", Status: "active"},
			path: acceptanceAuthorizeURL("https://app.example/callback", "not-a-challenge"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := NewAuthHandlerWithDependencies(AuthRepositories{Applications: &flowApplications{application: tc.app}}, AuthHandlerConfig{}, nil)
			response := httptest.NewRecorder()
			handler.Authorize(response, httptest.NewRequest(http.MethodGet, tc.path, nil))
			assertAcceptanceError(t, response, http.StatusBadRequest, sharederrors.CodeInvalidRequest)
			if response.Header().Get("Location") != "" {
				t.Fatalf("invalid authorization request redirected to %q", response.Header().Get("Location"))
			}
		})
	}
}

func acceptanceUserInfoToken(t *testing.T, key []byte, issuer, audience, sessionID string, expiresAt time.Time, algorithm string) string {
	t.Helper()
	claims := tokens.Claims{
		Scope: tokens.DefaultScope,
		SID:   sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   uuid.New().String(),
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			ID:        uuid.NewString(),
		},
	}
	method := jwt.SigningMethodHS256
	if algorithm == "HS384" {
		method = jwt.SigningMethodHS384
	}
	token := jwt.NewWithClaims(method, claims)
	value, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestUserInfoAcceptanceRejectsMalformedTokensAndReturnsSafeProfile(t *testing.T) {
	key := []byte("test-signing-key")
	user := models.User{ID: uuid.New(), Name: "Ada", Email: "ada@example.com", Status: "active"}
	application := models.Application{ID: uuid.New(), ClientID: "app-client", Status: "active"}
	session := &models.SSOSession{ID: uuid.New(), UserID: user.ID, Status: "active", ExpiresAt: time.Now().Add(time.Hour)}
	validToken, err := tokens.IssueAccessToken(key, "auth-provider", user.ID.String(), application.ID.String(), session.ID.String(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	validClaims, err := tokens.ValidateAccessToken(validToken, key, "auth-provider", application.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	jti, err := uuid.Parse(validClaims.ID)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{
		Users:        &flowUsers{user: user},
		Applications: &flowApplications{application: application},
		Sessions:     &flowSessions{created: session},
		AccessTokens: &flowTokens{token: &models.AccessToken{JTI: jti, UserID: user.ID, ApplicationID: application.ID, SessionID: session.ID, ExpiresAt: time.Now().Add(time.Minute)}},
		Groups:       flowGroups{},
		Policies:     flowPolicy{allowed: true},
	}, AuthHandlerConfig{JWTSigningKey: key}, nil)

	expired := acceptanceUserInfoToken(t, key, "auth-provider", application.ID.String(), session.ID.String(), time.Now().Add(-time.Second), "HS256")
	wrongIssuer := acceptanceUserInfoToken(t, key, "other-provider", application.ID.String(), session.ID.String(), time.Now().Add(time.Minute), "HS256")
	wrongAudience := acceptanceUserInfoToken(t, key, "auth-provider", uuid.NewString(), session.ID.String(), time.Now().Add(time.Minute), "HS256")
	wrongAlgorithm := acceptanceUserInfoToken(t, key, "auth-provider", application.ID.String(), session.ID.String(), time.Now().Add(time.Minute), "HS384")
	wrongSignature, err := tokens.IssueAccessToken([]byte("other-signing-key"), "auth-provider", user.ID.String(), application.ID.String(), session.ID.String(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		token  string
		client string
	}{
		{name: "missing bearer", client: application.ClientID},
		{name: "malformed bearer", token: "Bearer", client: application.ClientID},
		{name: "bad signature", token: wrongSignature, client: application.ClientID},
		{name: "wrong algorithm", token: wrongAlgorithm, client: application.ClientID},
		{name: "wrong issuer", token: wrongIssuer, client: application.ClientID},
		{name: "wrong audience", token: wrongAudience, client: application.ClientID},
		{name: "expired", token: expired, client: application.ClientID},
		{name: "wrong caller application", token: validToken, client: "other-client"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
			if tc.token != "" {
				request.Header.Set("Authorization", tc.token)
			} else if tc.name == "missing bearer" {
				request.Header.Set("Authorization", "")
			}
			if tc.name != "malformed bearer" && tc.name != "missing bearer" {
				request.Header.Set("Authorization", "Bearer "+tc.token)
			}
			request.Header.Set("X-Client-ID", tc.client)
			response := httptest.NewRecorder()
			handler.UserInfo(response, request)
			assertAcceptanceError(t, response, http.StatusUnauthorized, sharederrors.CodeUnauthorized)
		})
	}

	validRequest := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	validRequest.Header.Set("Authorization", "Bearer "+validToken)
	validRequest.Header.Set("X-Client-ID", application.ClientID)
	validResponse := httptest.NewRecorder()
	handler.UserInfo(validResponse, validRequest)
	if validResponse.Code != http.StatusOK {
		t.Fatalf("valid UserInfo request failed: status=%d body=%s", validResponse.Code, validResponse.Body.String())
	}
	var profile map[string]any
	if err := json.Unmarshal(validResponse.Body.Bytes(), &profile); err != nil {
		t.Fatal(err)
	}
	if profile["sub"] != user.ID.String() || profile["email"] != user.Email || profile["name"] != user.Name {
		t.Fatalf("profile claims incorrect: %+v", profile)
	}
	groups, ok := profile["groups"].([]any)
	if !ok || len(groups) != 1 || groups[0] != "app-users" {
		t.Fatalf("groups missing from profile: %+v", profile)
	}
	// SPECS E: only sub, email, name, and groups may be returned. centralSessionId
	// is internal metadata and must not leak here (relying apps derive it from
	// the access-token `sid` claim instead).
	allowed := map[string]bool{"sub": true, "email": true, "name": true, "groups" :true}
	if len(profile) != 4 {
		t.Fatalf("UserInfo returned unexpected field set: %+v", profile)
	}
	for key := range profile {
		if !allowed[key] {
			t.Fatalf("UserInfo returned unexpected field %q: %+v", key, profile)
		}
	}
	if _, present := profile["centralSessionId"]; present {
		t.Fatalf("UserInfo leaked internal metadata centralSessionId: %+v", profile)
	}
	for _, sensitive := range []string{"password", "password_hash", "client_secret", "session_token", "session_token_hash", "raw_token", "metadata"} {
		if _, found := profile[sensitive]; found {
			t.Fatalf("UserInfo leaked sensitive field %q: %+v", sensitive, profile)
		}
	}
}

func TestLogoutAcceptanceHandlesStaleSessionIdempotently(t *testing.T) {
	store := &logoutSessionStore{
		session:       &models.SSOSession{ID: uuid.New(), UserID: uuid.New(), Status: "active", ExpiresAt: time.Now().Add(time.Hour)},
		revocationErr: repository.ErrSessionNotFound,
	}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{SessionLookup: store, SessionRevocation: store}, AuthHandlerConfig{}, nil)
	request := httptest.NewRequest(http.MethodPost, "/logout", nil)
	request.AddCookie(&http.Cookie{Name: ssoSessionCookie, Value: "raw-session-token"})
	request.Header.Set("X-Request-Id", "logout-request")
	response := httptest.NewRecorder()
	handler.Logout(response, request)

	// A stale session is idempotent and therefore still clears the cookie.
	if response.Code != http.StatusOK || len(response.Result().Cookies()) != 1 || response.Result().Cookies()[0].MaxAge != -1 {
		t.Fatalf("stale logout was not idempotent: status=%d cookies=%v", response.Code, response.Result().Cookies())
	}
}
