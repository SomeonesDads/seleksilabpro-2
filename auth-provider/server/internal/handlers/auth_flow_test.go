package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/repository"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/tokens"
	"github.com/SomeonesDads/seleksilabpro-2/shared/idgen"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const testPKCEChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

type flowUsers struct {
	user        models.User
	missingByID bool
}

func (s *flowUsers) FindByEmail(_ context.Context, email string) (*models.User, error) {
	if s.user.Email != email {
		return nil, repository.ErrUserNotFound
	}
	return &s.user, nil
}

func (s *flowUsers) FindByID(_ context.Context, id uuid.UUID) (*models.User, error) {
	if s.missingByID {
		return nil, repository.ErrUserNotFound
	}
	if s.user.ID != id {
		return nil, repository.ErrUserNotFound
	}
	return &s.user, nil
}

type flowApplications struct {
	application    models.Application
	clientSecretOK *bool
	verifiedClient string
	verifiedSecret string
}

func (s *flowApplications) FindByClientID(_ context.Context, clientID string) (*models.Application, error) {
	if s.application.ClientID != clientID {
		return nil, repository.ErrApplicationNotFound
	}
	return &s.application, nil
}

func (s *flowApplications) HasExactRedirectURI(_ context.Context, id uuid.UUID, redirectURI string) (bool, error) {
	return id == s.application.ID && redirectURI == "https://app.example/callback", nil
}

func (s *flowApplications) VerifyClientSecret(_ context.Context, clientID, clientSecret string) (bool, error) {
	s.verifiedClient = clientID
	s.verifiedSecret = clientSecret
	if s.clientSecretOK != nil {
		return *s.clientSecretOK, nil
	}
	return true, nil
}

type flowPolicy struct {
	allowed bool
}

func (p flowPolicy) UserHasApplicationAccess(context.Context, uuid.UUID, uuid.UUID) (bool, error) {
	return p.allowed, nil
}

func (p flowPolicy) GroupsAllowedForApplication(_ context.Context, _ uuid.UUID, _ uuid.UUID) ([]string, error) {
	if !p.allowed {
		return []string{}, nil
	}
	return []string{"app-users"}, nil
}

type flowSessions struct {
	byHash           map[string]*models.SSOSession
	created          *models.SSOSession
	revoked          bool
	bypassStateCheck bool
}

func (s *flowSessions) Create(_ context.Context, session *models.SSOSession) error {
	if session.ID == uuid.Nil {
		session.ID = uuid.New()
	}
	s.created = session
	s.byHash[session.SessionTokenHash] = session
	return nil
}

func (s *flowSessions) FindActiveByTokenHash(_ context.Context, hash string) (*models.SSOSession, error) {
	session := s.byHash[hash]
	if session == nil || !session.IsValid(time.Now()) {
		return nil, repository.ErrSessionNotFound
	}
	return session, nil
}

func (s *flowSessions) FindActiveByID(_ context.Context, id uuid.UUID) (*models.SSOSession, error) {
	if s.created == nil || s.created.ID != id || s.revoked || (!s.bypassStateCheck && !s.created.IsValid(time.Now())) {
		return nil, repository.ErrSessionNotFound
	}
	return s.created, nil
}

func (s *flowSessions) RevokeAndCreateEvent(context.Context, uuid.UUID, string) error {
	s.revoked = true
	return nil
}

type flowCodes struct {
	code      *models.AuthorizationCode
	tokens    AccessTokenStore
	redeemErr error
	mu        sync.Mutex
}

func (s *flowCodes) Create(_ context.Context, code *models.AuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if code.ID == uuid.Nil {
		code.ID = uuid.New()
	}
	s.code = code
	return nil
}

func (s *flowCodes) FindByHash(_ context.Context, codeHash string) (*models.AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.code == nil || s.code.CodeHash != codeHash {
		return nil, repository.ErrAuthorizationCodeNotFound
	}
	copy := *s.code
	return &copy, nil
}

func (s *flowCodes) ConsumeAtomically(context.Context, uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.code == nil || s.code.UsedAt != nil {
		return repository.ErrAuthorizationCodeNotFound
	}
	now := time.Now()
	s.code.UsedAt = &now
	return nil
}

func (s *flowCodes) Redeem(ctx context.Context, id uuid.UUID, token *models.AccessToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.code == nil || s.code.ID != id || s.code.UsedAt != nil || !time.Now().Before(s.code.ExpiresAt) {
		return repository.ErrAuthorizationCodeNotFound
	}
	if s.redeemErr != nil {
		return s.redeemErr
	}
	if s.tokens == nil {
		return errors.New("token store is not configured")
	}
	if err := s.tokens.Create(ctx, token); err != nil {
		return err
	}
	now := time.Now()
	s.code.UsedAt = &now
	return nil
}

type flowTokens struct {
	token            *models.AccessToken
	createErr        error
	bypassStateCheck bool
}

func (s *flowTokens) Create(_ context.Context, token *models.AccessToken) error {
	if s.createErr != nil {
		return s.createErr
	}
	s.token = token
	return nil
}

func (s *flowTokens) FindActiveByJTI(_ context.Context, jti uuid.UUID) (*models.AccessToken, error) {
	if s.token == nil || s.token.JTI != jti || (!s.bypassStateCheck && (s.token.RevokedAt != nil || !time.Now().Before(s.token.ExpiresAt))) {
		return nil, repository.ErrAccessTokenNotFound
	}
	return s.token, nil
}

type flowGroups struct{}

func (flowGroups) FindByUserID(context.Context, uuid.UUID) ([]models.Group, error) {
	return []models.Group{{Name: "app-users"}}, nil
}

type flowAudit struct {
	events []models.AuditLog
}

func (s *flowAudit) WriteAuditLog(_ context.Context, entry *models.AuditLog) error {
	s.events = append(s.events, *entry)
	return nil
}

type flowTOTP struct{}

func (flowTOTP) FindByUserID(context.Context, uuid.UUID) (*models.UserTOTP, error) {
	return &models.UserTOTP{Confirmed: true}, nil
}
func (flowTOTP) EnrollPending(context.Context, uuid.UUID, []byte) error { return nil }
func (flowTOTP) Confirm(context.Context, uuid.UUID) error               { return nil }

type flowMFA struct {
	challenge      *models.MFALoginChallenge
	createdSession *models.SSOSession
}

func (s *flowMFA) Create(_ context.Context, challenge *models.MFALoginChallenge) error {
	if challenge.ID == uuid.Nil {
		challenge.ID = uuid.New()
	}
	s.challenge = challenge
	return nil
}

func (s *flowMFA) FindActiveByToken(_ context.Context, tokenHash string, maxAttempts int) (*models.MFALoginChallenge, error) {
	if s.challenge == nil || s.challenge.TokenHash != tokenHash || s.challenge.UsedAt != nil || !time.Now().Before(s.challenge.ExpiresAt) || s.challenge.Attempts >= maxAttempts {
		return nil, repository.ErrMFAChallengeNotFound
	}
	return s.challenge, nil
}

func (s *flowMFA) ClaimAttempt(context.Context, uuid.UUID, int) (bool, error) {
	if s.challenge == nil {
		return false, nil
	}
	s.challenge.Attempts++
	return true, nil
}

func (s *flowMFA) ConsumeAndCreateSession(_ context.Context, _ uuid.UUID, session *models.SSOSession, maxAttempts int) error {
	if s.challenge == nil || s.challenge.UsedAt != nil || s.challenge.Attempts > maxAttempts {
		return repository.ErrMFAChallengeNotFound
	}
	now := time.Now()
	s.challenge.UsedAt = &now
	if session.ID == uuid.Nil {
		session.ID = uuid.New()
	}
	s.createdSession = session
	return nil
}

type emptyFlowTOTP struct{}

func (emptyFlowTOTP) FindByUserID(context.Context, uuid.UUID) (*models.UserTOTP, error) {
	return nil, nil
}
func (emptyFlowTOTP) EnrollPending(context.Context, uuid.UUID, []byte) error { return nil }
func (emptyFlowTOTP) Confirm(context.Context, uuid.UUID) error               { return nil }

func TestLoginIntentIsRevalidatedAgainstAuthorizationRequest(t *testing.T) {
	application := models.Application{ID: uuid.New(), ClientID: "app-client", Status: "active"}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{
		Applications: &flowApplications{application: application},
	}, AuthHandlerConfig{}, nil)

	invalidIntent := "/authorize?response_type=code&client_id=app-client&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback.evil&state=state&code_challenge=" + testPKCEChallenge + "&code_challenge_method=S256"
	pageRequest := httptest.NewRequest(http.MethodGet, "/login?return_to="+url.QueryEscape(invalidIntent), nil)
	pageResponse := httptest.NewRecorder()
	handler.LoginPage(pageResponse, pageRequest)
	if pageResponse.Code != http.StatusBadRequest || strings.Contains(pageResponse.Body.String(), "<form") {
		t.Fatalf("invalid login intent was accepted by login page: status=%d body=%s", pageResponse.Code, pageResponse.Body.String())
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	sessions := &flowSessions{byHash: make(map[string]*models.SSOSession)}
	handler = NewAuthHandlerWithDependencies(AuthRepositories{
		Users:        &flowUsers{user: models.User{ID: uuid.New(), Email: "ada@example.com", PasswordHash: string(passwordHash), Status: "active"}},
		Applications: &flowApplications{application: application},
		Sessions:     sessions,
	}, AuthHandlerConfig{}, nil)
	loginRequest := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"email":"ada@example.com","password":"password","return_to":"`+invalidIntent+`"}`))
	loginRequest.Header.Set("Content-Type", "application/json")
	loginResponse := httptest.NewRecorder()
	handler.Login(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusBadRequest || sessions.created != nil {
		t.Fatalf("invalid login intent was accepted by login handler: status=%d body=%s", loginResponse.Code, loginResponse.Body.String())
	}
}

func TestLoginTreatsNilTOTPRecordAsNoMFA(t *testing.T) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	sessions := &flowSessions{byHash: make(map[string]*models.SSOSession)}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{
		Users:    &flowUsers{user: models.User{ID: uuid.New(), Email: "ada@example.com", PasswordHash: string(passwordHash), Status: "active"}},
		TOTP:     emptyFlowTOTP{},
		Sessions: sessions,
	}, AuthHandlerConfig{}, nil)

	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"email":"ada@example.com","password":"password"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.Login(response, request)
	if response.Code != http.StatusOK || sessions.created == nil || strings.Contains(response.Body.String(), "mfa_required\":true") {
		t.Fatalf("nil TOTP record incorrectly required MFA: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAuthFlowLoginAuthorizeTokenUserInfoLogout(t *testing.T) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	user := models.User{ID: uuid.New(), Name: "Ada", Email: "ada@example.com", PasswordHash: string(passwordHash), Status: "active"}
	application := models.Application{ID: uuid.New(), Name: "App", ClientID: "app-client", Status: "active"}
	sessions := &flowSessions{byHash: make(map[string]*models.SSOSession)}
	tokensStore := &flowTokens{}
	codes := &flowCodes{tokens: tokensStore}
	audit := &flowAudit{}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{
		Users:             &flowUsers{user: user},
		Applications:      &flowApplications{application: application},
		Policies:          flowPolicy{allowed: true},
		Sessions:          sessions,
		AuthorizationCode: codes,
		AccessTokens:      tokensStore,
		Groups:            flowGroups{},
		Audit:             audit,
	}, AuthHandlerConfig{JWTSigningKey: []byte("test-signing-key")}, nil)

	loginRequest := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"email":"ada@example.com","password":"password"}`))
	loginRequest.Header.Set("Content-Type", "application/json")
	loginResponse := httptest.NewRecorder()
	handler.Login(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", loginResponse.Code, loginResponse.Body.String())
	}
	sessionCookie := loginResponse.Result().Cookies()[0]
	if sessions.created == nil || sessions.created.SessionTokenHash == sessionCookie.Value || sessions.created.SessionTokenHash != idgen.HashToken(sessionCookie.Value) {
		t.Fatalf("session token was not hash-only persisted: cookie=%q stored=%q", sessionCookie.Value, sessions.created.SessionTokenHash)
	}

	verifier := "verifier"
	authorizeURL := "/authorize?response_type=code&client_id=app-client&redirect_uri=" + url.QueryEscape("https://app.example/callback") + "&state=state-1&code_challenge=" + url.QueryEscape(idgen.PKCEChallengeS256(verifier)) + "&code_challenge_method=S256"
	authorizeRequest := httptest.NewRequest(http.MethodGet, authorizeURL, nil)
	authorizeRequest.AddCookie(sessionCookie)
	authorizeResponse := httptest.NewRecorder()
	handler.Authorize(authorizeResponse, authorizeRequest)
	if authorizeResponse.Code != http.StatusFound {
		t.Fatalf("authorize status = %d, body = %s", authorizeResponse.Code, authorizeResponse.Body.String())
	}
	redirect, err := url.Parse(authorizeResponse.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := redirect.Query().Get("code")
	if code == "" || codes.code.CodeHash == code {
		t.Fatal("authorization code was not issued as a raw value distinct from its stored hash")
	}

	tokenBody := `{"grant_type":"authorization_code","code":"` + code + `","redirect_uri":"https://app.example/callback","client_id":"app-client","code_verifier":"` + verifier + `"}`
	tokenRequest := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenBody))
	tokenRequest.Header.Set("Content-Type", "application/json")
	tokenResponse := httptest.NewRecorder()
	handler.Token(tokenResponse, tokenRequest)
	if tokenResponse.Code != http.StatusOK {
		t.Fatalf("token status = %d, body = %s", tokenResponse.Code, tokenResponse.Body.String())
	}
	var tokenPayload struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(tokenResponse.Body.Bytes(), &tokenPayload); err != nil || tokenPayload.AccessToken == "" {
		t.Fatalf("invalid token response: %s", tokenResponse.Body.String())
	}
	claims, err := tokens.ValidateAccessToken(tokenPayload.AccessToken, []byte("test-signing-key"), "auth-provider", application.ID.String())
	if err != nil || claims.Subject != user.ID.String() || claims.SID != sessions.created.ID.String() || claims.Scope != tokens.DefaultScope {
		t.Fatalf("invalid access-token claims: claims=%+v err=%v", claims, err)
	}

	userinfoRequest := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	userinfoRequest.Header.Set("Authorization", "Bearer "+tokenPayload.AccessToken)
	userinfoRequest.Header.Set("X-Client-ID", "app-client")
	userinfoResponse := httptest.NewRecorder()
	handler.UserInfo(userinfoResponse, userinfoRequest)
	if userinfoResponse.Code != http.StatusOK {
		t.Fatalf("userinfo status = %d, body = %s", userinfoResponse.Code, userinfoResponse.Body.String())
	}
	var profile map[string]any
	if err := json.Unmarshal(userinfoResponse.Body.Bytes(), &profile); err != nil {
		t.Fatal(err)
	}
	for _, sensitive := range []string{"password", "password_hash", "client_secret", "session_token", "session_token_hash"} {
		if _, found := profile[sensitive]; found {
			t.Fatalf("userinfo leaked sensitive field %q: %v", sensitive, profile)
		}
	}

	logoutRequest := httptest.NewRequest(http.MethodPost, "/logout", nil)
	logoutRequest.AddCookie(sessionCookie)
	logoutResponse := httptest.NewRecorder()
	handler.Logout(logoutResponse, logoutRequest)
	if logoutResponse.Code != http.StatusOK || !sessions.revoked {
		t.Fatalf("logout status = %d, revoked = %v, body = %s", logoutResponse.Code, sessions.revoked, logoutResponse.Body.String())
	}
	events := map[string]bool{}
	for _, event := range audit.events {
		events[event.EventType] = true
	}
	for _, eventType := range []string{"LoginSucceeded", "AuthorizationCodeIssued", "TokenIssued", "Logout"} {
		if !events[eventType] {
			t.Fatalf("missing audit event %q: %+v", eventType, audit.events)
		}
	}
}

func TestAuthorizeMissingUserAuditsPolicyDenied(t *testing.T) {
	userID := uuid.New()
	application := models.Application{ID: uuid.New(), ClientID: "app-client", Status: "active"}
	rawSession := "session-token"
	session := &models.SSOSession{ID: uuid.New(), UserID: userID, SessionTokenHash: idgen.HashToken(rawSession), Status: "active", ExpiresAt: time.Now().Add(time.Hour)}
	sessions := &flowSessions{byHash: map[string]*models.SSOSession{session.SessionTokenHash: session}}
	audit := &flowAudit{}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{
		Users:             &flowUsers{user: models.User{ID: userID}, missingByID: true},
		Applications:      &flowApplications{application: application},
		Policies:          flowPolicy{allowed: true},
		Sessions:          sessions,
		AuthorizationCode: &flowCodes{},
		Audit:             audit,
	}, AuthHandlerConfig{}, nil)

	request := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&client_id=app-client&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&state=state&code_challenge="+testPKCEChallenge+"&code_challenge_method=S256", nil)
	request.AddCookie(&http.Cookie{Name: ssoSessionCookie, Value: rawSession})
	response := httptest.NewRecorder()
	handler.Authorize(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("authorize status = %d, body = %s", response.Code, response.Body.String())
	}
	if len(audit.events) != 1 || audit.events[0].EventType != "PolicyDenied" || audit.events[0].Result != "failed" {
		t.Fatalf("missing PolicyDenied audit: %+v", audit.events)
	}
	if audit.events[0].ApplicationID == nil || *audit.events[0].ApplicationID != application.ID || audit.events[0].SessionID == nil || *audit.events[0].SessionID != session.ID {
		t.Fatalf("audit context missing: %+v", audit.events[0])
	}
}

func TestAuthorizeRejectsUnvalidatedRedirect(t *testing.T) {
	application := models.Application{ID: uuid.New(), ClientID: "app-client", Status: "active"}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{
		Applications: &flowApplications{application: application},
	}, AuthHandlerConfig{}, nil)
	request := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&client_id=app-client&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback.evil&state=state&code_challenge="+testPKCEChallenge+"&code_challenge_method=S256", nil)
	response := httptest.NewRecorder()
	handler.Authorize(response, request)
	if response.Code != http.StatusBadRequest || response.Header().Get("Location") != "" {
		t.Fatalf("invalid redirect was not rejected safely: status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
}

func TestAuthorizeRedirectsUnauthenticatedRequestBeforePolicyDependencies(t *testing.T) {
	application := models.Application{ID: uuid.New(), ClientID: "app-client", Status: "active"}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{
		Applications: &flowApplications{application: application},
	}, AuthHandlerConfig{}, nil)
	request := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&client_id=app-client&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&state=state&code_challenge="+testPKCEChallenge+"&code_challenge_method=S256", nil)
	response := httptest.NewRecorder()
	handler.Authorize(response, request)

	location, err := url.Parse(response.Header().Get("Location"))
	if response.Code != http.StatusFound || err != nil || location.Path != "/login" || location.Query().Get("return_to") == "" {
		t.Fatalf("unauthenticated request was not sent to login: status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
}

func TestAuthorizeInactiveUserReturnsToLogin(t *testing.T) {
	user := models.User{ID: uuid.New(), Status: "inactive"}
	application := models.Application{ID: uuid.New(), ClientID: "app-client", Status: "active"}
	rawSession := "session-token"
	session := &models.SSOSession{ID: uuid.New(), UserID: user.ID, SessionTokenHash: idgen.HashToken(rawSession), Status: "active", ExpiresAt: time.Now().Add(time.Hour)}
	audit := &flowAudit{}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{
		Users:             &flowUsers{user: user},
		Applications:      &flowApplications{application: application},
		Policies:          flowPolicy{allowed: true},
		Sessions:          &flowSessions{byHash: map[string]*models.SSOSession{session.SessionTokenHash: session}},
		AuthorizationCode: &flowCodes{},
		Audit:             audit,
	}, AuthHandlerConfig{}, nil)
	request := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&client_id=app-client&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&state=state&code_challenge="+testPKCEChallenge+"&code_challenge_method=S256", nil)
	request.AddCookie(&http.Cookie{Name: ssoSessionCookie, Value: rawSession})
	response := httptest.NewRecorder()
	handler.Authorize(response, request)

	location, err := url.Parse(response.Header().Get("Location"))
	if response.Code != http.StatusFound || err != nil || location.Path != "/login" || location.Query().Get("return_to") == "" {
		t.Fatalf("inactive user was not sent to login: status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
	if len(audit.events) != 1 || audit.events[0].EventType != "PolicyDenied" {
		t.Fatalf("inactive-user denial was not audited: %+v", audit.events)
	}
}

func TestAuthorizeRejectsDuplicateOAuthParameters(t *testing.T) {
	application := models.Application{ID: uuid.New(), ClientID: "app-client", Status: "active"}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{
		Applications: &flowApplications{application: application},
	}, AuthHandlerConfig{}, nil)
	request := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&response_type=token&client_id=app-client&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&state=state&code_challenge="+testPKCEChallenge+"&code_challenge_method=S256", nil)
	response := httptest.NewRecorder()
	handler.Authorize(response, request)
	if response.Code != http.StatusBadRequest || response.Header().Get("Location") != "" {
		t.Fatalf("duplicate OAuth parameter was accepted: status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
}

func TestAuthorizeRejectsInvalidS256Challenge(t *testing.T) {
	application := models.Application{ID: uuid.New(), ClientID: "app-client", Status: "active"}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{
		Applications: &flowApplications{application: application},
	}, AuthHandlerConfig{}, nil)
	request := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&client_id=app-client&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&state=state&code_challenge=challenge&code_challenge_method=S256", nil)
	response := httptest.NewRecorder()
	handler.Authorize(response, request)
	if response.Code != http.StatusBadRequest || response.Header().Get("Location") != "" {
		t.Fatalf("invalid PKCE challenge was accepted: status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
}

func TestAuthorizePolicyDeniedAuditsAndRedirects(t *testing.T) {
	userID := uuid.New()
	application := models.Application{ID: uuid.New(), ClientID: "app-client", Status: "active"}
	rawSession := "session-token"
	session := &models.SSOSession{ID: uuid.New(), UserID: userID, SessionTokenHash: idgen.HashToken(rawSession), Status: "active", ExpiresAt: time.Now().Add(time.Hour)}
	audit := &flowAudit{}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{
		Users:             &flowUsers{user: models.User{ID: userID, Status: "active"}},
		Applications:      &flowApplications{application: application},
		Policies:          flowPolicy{allowed: false},
		Sessions:          &flowSessions{byHash: map[string]*models.SSOSession{session.SessionTokenHash: session}},
		AuthorizationCode: &flowCodes{},
		Audit:             audit,
	}, AuthHandlerConfig{}, nil)
	request := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&client_id=app-client&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&state=state&code_challenge="+testPKCEChallenge+"&code_challenge_method=S256", nil)
	request.AddCookie(&http.Cookie{Name: ssoSessionCookie, Value: rawSession})
	response := httptest.NewRecorder()
	handler.Authorize(response, request)
	redirect, err := url.Parse(response.Header().Get("Location"))
	if response.Code != http.StatusFound || err != nil || redirect.Query().Get("error") != "access_denied" || redirect.Query().Get("state") != "state" {
		t.Fatalf("policy denial was not redirected safely: status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
	if len(audit.events) != 1 || audit.events[0].EventType != "PolicyDenied" {
		t.Fatalf("policy denial audit missing: %+v", audit.events)
	}
}

func TestAuthorizeRejectsUnknownInactiveAndInvalidSessionsSafely(t *testing.T) {
	baseApplication := models.Application{ID: uuid.New(), ClientID: "app-client", Status: "active"}
	baseUser := models.User{ID: uuid.New(), Status: "active"}
	authorizeRequest := func(cookieValue string) *http.Request {
		request := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&client_id=app-client&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&state=state&code_challenge="+testPKCEChallenge+"&code_challenge_method=S256", nil)
		if cookieValue != "" {
			request.AddCookie(&http.Cookie{Name: ssoSessionCookie, Value: cookieValue})
		}
		return request
	}

	for _, tc := range []struct {
		name string
		app  models.Application
	}{
		{name: "unknown client", app: models.Application{ID: baseApplication.ID, ClientID: "different-client", Status: "active"}},
		{name: "inactive client", app: models.Application{ID: baseApplication.ID, ClientID: baseApplication.ClientID, Status: "inactive"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := NewAuthHandlerWithDependencies(AuthRepositories{Applications: &flowApplications{application: tc.app}}, AuthHandlerConfig{}, nil)
			response := httptest.NewRecorder()
			handler.Authorize(response, authorizeRequest(""))
			if response.Code != http.StatusBadRequest || response.Header().Get("Location") != "" {
				t.Fatalf("client validation was unsafe: status=%d location=%q", response.Code, response.Header().Get("Location"))
			}
		})
	}

	for _, tc := range []struct {
		name    string
		session *models.SSOSession
	}{
		{name: "expired", session: &models.SSOSession{ID: uuid.New(), UserID: baseUser.ID, Status: "active", ExpiresAt: time.Now().Add(-time.Minute)}},
		{name: "revoked", session: &models.SSOSession{ID: uuid.New(), UserID: baseUser.ID, Status: "revoked", ExpiresAt: time.Now().Add(time.Hour)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rawSession := tc.name + "-session"
			tc.session.SessionTokenHash = idgen.HashToken(rawSession)
			handler := NewAuthHandlerWithDependencies(AuthRepositories{
				Users:             &flowUsers{user: baseUser},
				Applications:      &flowApplications{application: baseApplication},
				Policies:          flowPolicy{allowed: true},
				Sessions:          &flowSessions{byHash: map[string]*models.SSOSession{tc.session.SessionTokenHash: tc.session}},
				AuthorizationCode: &flowCodes{},
			}, AuthHandlerConfig{}, nil)
			response := httptest.NewRecorder()
			handler.Authorize(response, authorizeRequest(rawSession))
			if response.Code != http.StatusFound || !strings.HasPrefix(response.Header().Get("Location"), "/login?") {
				t.Fatalf("invalid session was not sent to login: status=%d location=%q", response.Code, response.Header().Get("Location"))
			}
		})
	}
}

func TestTokenRejectsWrongVerifierAndReplay(t *testing.T) {
	user := models.User{ID: uuid.New(), Name: "Ada", Email: "ada@example.com", Status: "active"}
	application := models.Application{ID: uuid.New(), ClientID: "app-client", Status: "active"}
	rawSession := "session-token"
	session := &models.SSOSession{ID: uuid.New(), UserID: user.ID, SessionTokenHash: idgen.HashToken(rawSession), Status: "active", ExpiresAt: time.Now().Add(time.Hour)}
	verifier := "verifier"
	rawCode := "authorization-code"
	code := &models.AuthorizationCode{ID: uuid.New(), CodeHash: idgen.HashToken(rawCode), UserID: user.ID, ApplicationID: application.ID, SSOSessionID: session.ID, RedirectURI: "https://app.example/callback", CodeChallenge: idgen.PKCEChallengeS256(verifier), CodeChallengeMethod: "S256", ExpiresAt: time.Now().Add(time.Minute)}
	tokensStore := &flowTokens{}
	codes := &flowCodes{code: code, tokens: tokensStore}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{
		Users:             &flowUsers{user: user},
		Applications:      &flowApplications{application: application},
		Sessions:          &flowSessions{created: session, byHash: map[string]*models.SSOSession{session.SessionTokenHash: session}},
		AuthorizationCode: codes,
		AccessTokens:      tokensStore,
	}, AuthHandlerConfig{JWTSigningKey: []byte("test-signing-key")}, nil)

	requestToken := func(codeVerifier string) *httptest.ResponseRecorder {
		body := `{"grant_type":"authorization_code","code":"` + rawCode + `","redirect_uri":"https://app.example/callback","client_id":"app-client","code_verifier":"` + codeVerifier + `"}`
		request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.Token(response, request)
		return response
	}
	if response := requestToken("wrong"); response.Code != http.StatusBadRequest || code.UsedAt != nil {
		t.Fatalf("wrong PKCE verifier was accepted or consumed code: status=%d used=%v", response.Code, code.UsedAt != nil)
	}
	if response := requestToken(verifier); response.Code != http.StatusOK {
		t.Fatalf("valid verifier failed: status=%d body=%s", response.Code, response.Body.String())
	}
	if response := requestToken(verifier); response.Code != http.StatusBadRequest {
		t.Fatalf("authorization-code replay was accepted: status=%d", response.Code)
	}
}

func TestTokenAcceptsBasicClientAuthenticationAndFormBody(t *testing.T) {
	user := models.User{ID: uuid.New(), Status: "active"}
	secretHash := "stored-client-secret-hash"
	application := models.Application{ID: uuid.New(), ClientID: "confidential-client", ClientSecretHash: &secretHash, Status: "active"}
	session := &models.SSOSession{ID: uuid.New(), UserID: user.ID, Status: "active", ExpiresAt: time.Now().Add(time.Hour)}
	verifier := "verifier"
	rawCode := "authorization-code"
	tokensStore := &flowTokens{}
	codes := &flowCodes{tokens: tokensStore, code: &models.AuthorizationCode{
		ID:                  uuid.New(),
		CodeHash:            idgen.HashToken(rawCode),
		UserID:              user.ID,
		ApplicationID:       application.ID,
		SSOSessionID:        session.ID,
		RedirectURI:         "https://app.example/callback",
		CodeChallenge:       idgen.PKCEChallengeS256(verifier),
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(time.Minute),
	}}
	applications := &flowApplications{application: application}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{
		Users:             &flowUsers{user: user},
		Applications:      applications,
		Sessions:          &flowSessions{created: session},
		AuthorizationCode: codes,
		AccessTokens:      tokensStore,
	}, AuthHandlerConfig{JWTSigningKey: []byte("test-signing-key")}, nil)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {rawCode},
		"redirect_uri":  {"https://app.example/callback"},
		"code_verifier": {verifier},
	}
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(application.ClientID, "client-secret")
	response := httptest.NewRecorder()
	handler.Token(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("token status = %d, body = %s", response.Code, response.Body.String())
	}
	if applications.verifiedClient != application.ClientID || applications.verifiedSecret != "client-secret" {
		t.Fatalf("client credentials were not passed to repository: client=%q secret=%q", applications.verifiedClient, applications.verifiedSecret)
	}
}

func TestUserInfoRejectsMissingOrWrongCaller(t *testing.T) {
	key := []byte("test-signing-key")
	user := models.User{ID: uuid.New(), Name: "Ada", Email: "ada@example.com", Status: "active"}
	application := models.Application{ID: uuid.New(), ClientID: "app-client", Status: "active"}
	session := &models.SSOSession{ID: uuid.New(), UserID: user.ID, Status: "active", ExpiresAt: time.Now().Add(time.Hour)}
	accessToken, err := tokens.IssueAccessToken(key, "auth-provider", user.ID.String(), application.ID.String(), session.ID.String(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := tokens.ValidateAccessToken(accessToken, key, "auth-provider", application.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	jti, err := uuid.Parse(claims.ID)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{
		Users:        &flowUsers{user: user},
		Applications: &flowApplications{application: application},
		Sessions:     &flowSessions{created: session},
		AccessTokens: &flowTokens{token: &models.AccessToken{JTI: jti, UserID: user.ID, ApplicationID: application.ID, SessionID: session.ID, ExpiresAt: time.Now().Add(time.Minute)}},
		Groups:       flowGroups{},
	}, AuthHandlerConfig{JWTSigningKey: key}, nil)

	missingCaller := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	missingCaller.Header.Set("Authorization", "Bearer "+accessToken)
	missingResponse := httptest.NewRecorder()
	handler.UserInfo(missingResponse, missingCaller)
	if missingResponse.Code != http.StatusUnauthorized {
		t.Fatalf("missing caller identity status = %d", missingResponse.Code)
	}

	wrongCaller := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	wrongCaller.Header.Set("Authorization", "Bearer "+accessToken)
	wrongCaller.Header.Set("X-Client-ID", "other-client")
	wrongResponse := httptest.NewRecorder()
	handler.UserInfo(wrongResponse, wrongCaller)
	if wrongResponse.Code != http.StatusUnauthorized {
		t.Fatalf("wrong caller identity status = %d", wrongResponse.Code)
	}
}

func TestUserInfoRejectsStaleTokenAndSessionRecords(t *testing.T) {
	key := []byte("test-signing-key")
	user := models.User{ID: uuid.New(), Name: "Ada", Email: "ada@example.com", Status: "active"}
	application := models.Application{ID: uuid.New(), ClientID: "app-client", Status: "active"}
	for _, test := range []struct {
		name  string
		setup func(*models.AccessToken, *models.SSOSession)
	}{
		{name: "expired metadata", setup: func(token *models.AccessToken, _ *models.SSOSession) { token.ExpiresAt = time.Now().Add(-time.Minute) }},
		{name: "revoked metadata", setup: func(token *models.AccessToken, _ *models.SSOSession) { now := time.Now(); token.RevokedAt = &now }},
		{name: "expired session", setup: func(_ *models.AccessToken, session *models.SSOSession) {
			session.ExpiresAt = time.Now().Add(-time.Minute)
		}},
		{name: "revoked session", setup: func(_ *models.AccessToken, session *models.SSOSession) { session.Status = "revoked" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := &models.SSOSession{ID: uuid.New(), UserID: user.ID, Status: "active", ExpiresAt: time.Now().Add(time.Hour)}
			accessToken, err := tokens.IssueAccessToken(key, "auth-provider", user.ID.String(), application.ID.String(), session.ID.String(), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			claims, err := tokens.ValidateAccessToken(accessToken, key, "auth-provider", application.ID.String())
			if err != nil {
				t.Fatal(err)
			}
			jti, err := uuid.Parse(claims.ID)
			if err != nil {
				t.Fatal(err)
			}
			metadata := &models.AccessToken{JTI: jti, UserID: user.ID, ApplicationID: application.ID, SessionID: session.ID, ExpiresAt: time.Now().Add(time.Minute)}
			test.setup(metadata, session)
			handler := NewAuthHandlerWithDependencies(AuthRepositories{
				Users:        &flowUsers{user: user},
				Applications: &flowApplications{application: application},
				Sessions:     &flowSessions{created: session, bypassStateCheck: true},
				AccessTokens: &flowTokens{token: metadata, bypassStateCheck: true},
				Groups:       flowGroups{},
			}, AuthHandlerConfig{JWTSigningKey: key}, nil)
			request := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
			request.Header.Set("Authorization", "Bearer "+accessToken)
			request.Header.Set("X-Client-ID", application.ClientID)
			response := httptest.NewRecorder()
			handler.UserInfo(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("stale state was accepted: status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestLogoutWithoutSessionClearsCookieIdempotently(t *testing.T) {
	handler := NewAuthHandlerWithDependencies(AuthRepositories{}, AuthHandlerConfig{}, nil)
	request := httptest.NewRequest(http.MethodPost, "/logout", nil)
	response := httptest.NewRecorder()
	handler.Logout(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("logout status = %d", response.Code)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != ssoSessionCookie || cookies[0].MaxAge != -1 {
		t.Fatalf("logout did not clear cookie: %+v", cookies)
	}
}

func TestLoginRejectsUnknownAndInactiveUsersGenerically(t *testing.T) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		user *models.User
	}{
		{name: "unknown", user: nil},
		{name: "inactive", user: &models.User{ID: uuid.New(), Email: "ada@example.com", PasswordHash: string(passwordHash), Status: "inactive"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			users := &flowUsers{}
			if tc.user != nil {
				users.user = *tc.user
			}
			handler := NewAuthHandlerWithDependencies(AuthRepositories{Users: users, Sessions: &flowSessions{byHash: make(map[string]*models.SSOSession)}}, AuthHandlerConfig{}, nil)
			request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"email":"ada@example.com","password":"password"}`))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.Login(response, request)
			if response.Code != http.StatusUnauthorized || strings.Contains(response.Body.String(), "password") {
				t.Fatalf("credential failure leaked or returned wrong status: status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestMFARequiresSecondFactorAndAllowsFinalAttempt(t *testing.T) {
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
	if loginResponse.Code != http.StatusOK || mfa.challenge == nil || mfa.challenge.TokenHash == "" {
		t.Fatalf("MFA challenge was not created: status=%d body=%s", loginResponse.Code, loginResponse.Body.String())
	}
	mfaCookie := loginResponse.Result().Cookies()[0]
	if mfaCookie.Name != mfaPendingCookie || mfaCookie.Value == "" || mfaCookie.Value == mfa.challenge.TokenHash {
		t.Fatalf("pending MFA cookie was not raw/hash separated: cookie=%+v challenge=%+v", mfaCookie, mfa.challenge)
	}

	invalidRequest := httptest.NewRequest(http.MethodPost, "/login/mfa", strings.NewReader(`{"code":"000000"}`))
	invalidRequest.Header.Set("Content-Type", "application/json")
	invalidRequest.AddCookie(mfaCookie)
	invalidResponse := httptest.NewRecorder()
	handler.LoginMFA(invalidResponse, invalidRequest)
	if invalidResponse.Code != http.StatusUnauthorized || mfa.createdSession != nil {
		t.Fatalf("invalid MFA code created session or returned wrong status: status=%d", invalidResponse.Code)
	}

	mfa.challenge.Attempts = mfaMaxAttempts - 1
	handler.VerifyMFA = func(context.Context, uuid.UUID, string) bool { return true }
	validRequest := httptest.NewRequest(http.MethodPost, "/login/mfa", strings.NewReader(`{"code":"123456"}`))
	validRequest.Header.Set("Content-Type", "application/json")
	validRequest.AddCookie(mfaCookie)
	validResponse := httptest.NewRecorder()
	handler.LoginMFA(validResponse, validRequest)
	if validResponse.Code != http.StatusOK || mfa.createdSession == nil {
		t.Fatalf("valid final MFA attempt failed: status=%d body=%s", validResponse.Code, validResponse.Body.String())
	}

	replayRequest := httptest.NewRequest(http.MethodPost, "/login/mfa", strings.NewReader(`{"code":"123456"}`))
	replayRequest.Header.Set("Content-Type", "application/json")
	replayRequest.AddCookie(mfaCookie)
	replayResponse := httptest.NewRecorder()
	handler.LoginMFA(replayResponse, replayRequest)
	if replayResponse.Code != http.StatusUnauthorized {
		t.Fatalf("MFA challenge replay was accepted: status=%d", replayResponse.Code)
	}
}

func TestMFASettingsPageRendersEnrollmentForm(t *testing.T) {
	session := &models.SSOSession{ID: uuid.New(), UserID: uuid.New(), Status: "active", ExpiresAt: time.Now().Add(time.Hour)}
	sessions := &flowSessions{
		byHash:  map[string]*models.SSOSession{idgen.HashToken("mfa-page-session"): session},
		created: session,
	}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{
		TOTP:              &flowTOTP{},
		Sessions:          sessions,
		SessionLookup:     sessions,
		SessionRevocation: sessions,
	}, AuthHandlerConfig{MFAEncryptionKey: []byte("0123456789abcdef0123456789abcdef")}, nil)
	handler.VerifyMFA = func(context.Context, uuid.UUID, string) bool { return true }

	pageRequest := httptest.NewRequest(http.MethodGet, "/mfa/enroll", nil)
	pageRequest.AddCookie(&http.Cookie{Name: ssoSessionCookie, Value: "mfa-page-session"})
	pageResponse := httptest.NewRecorder()
	handler.MFASettingsPage(pageResponse, pageRequest)
	if pageResponse.Code != http.StatusOK {
		t.Fatalf("MFA settings page failed: status=%d body=%s", pageResponse.Code, pageResponse.Body.String())
	}
	body := pageResponse.Body.String()
	if !strings.Contains(body, "otpauth") || !strings.Contains(body, "/mfa/enroll/confirm") {
		t.Fatalf("MFA settings page missing enrollment form: %s", body)
	}

	confirmRequest := httptest.NewRequest(http.MethodPost, "/mfa/enroll/confirm", strings.NewReader("code=123456"))
	confirmRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	confirmRequest.AddCookie(&http.Cookie{Name: ssoSessionCookie, Value: "mfa-page-session"})
	confirmResponse := httptest.NewRecorder()
	handler.ConfirmMFAEnrollment(confirmResponse, confirmRequest)
	if confirmResponse.Code != http.StatusOK {
		t.Fatalf("MFA confirm via form failed: status=%d body=%s", confirmResponse.Code, confirmResponse.Body.String())
	}
	if !strings.Contains(confirmResponse.Body.String(), "MFA activated") {
		t.Fatalf("MFA confirm did not render success page: %s", confirmResponse.Body.String())
	}
}
