package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/SomeonesDads/seleksilabpro-2/shared/idgen"
	"github.com/google/uuid"
)

type tokenFixture struct {
	user     *flowUsers
	app      *flowApplications
	session  *models.SSOSession
	code     *models.AuthorizationCode
	codes    *flowCodes
	tokens   *flowTokens
	handler  *AuthHandler
	rawCode  string
	verifier string
	redirect string
}

func newTokenFixture() *tokenFixture {
	user := models.User{ID: uuid.New(), Name: "Ada", Email: "ada@example.com", Status: "active"}
	application := models.Application{ID: uuid.New(), ClientID: "app-client", Status: "active"}
	session := &models.SSOSession{ID: uuid.New(), UserID: user.ID, Status: "active", ExpiresAt: time.Now().Add(time.Hour)}
	rawCode := "authorization-code"
	verifier := "verifier"
	redirect := "https://app.example/callback"
	tokens := &flowTokens{}
	codes := &flowCodes{
		tokens: tokens,
		code: &models.AuthorizationCode{
			ID:                  uuid.New(),
			CodeHash:            idgen.HashToken(rawCode),
			UserID:              user.ID,
			ApplicationID:       application.ID,
			SSOSessionID:        session.ID,
			RedirectURI:         redirect,
			CodeChallenge:       idgen.PKCEChallengeS256(verifier),
			CodeChallengeMethod: "S256",
			ExpiresAt:           time.Now().Add(time.Minute),
		},
	}
	users := &flowUsers{user: user}
	applications := &flowApplications{application: application}
	handler := NewAuthHandlerWithDependencies(AuthRepositories{
		Users:             users,
		Applications:      applications,
		Sessions:          &flowSessions{created: session},
		AuthorizationCode: codes,
		AccessTokens:      tokens,
	}, AuthHandlerConfig{JWTSigningKey: []byte("test-signing-key")}, nil)
	return &tokenFixture{
		user:     users,
		app:      applications,
		session:  session,
		code:     codes.code,
		codes:    codes,
		tokens:   tokens,
		handler:  handler,
		rawCode:  rawCode,
		verifier: verifier,
		redirect: redirect,
	}
}

func (f *tokenFixture) request(clientID, clientSecret, redirectURI, codeVerifier, code string) *httptest.ResponseRecorder {
	body := `{"grant_type":"authorization_code","code":"` + code + `","redirect_uri":"` + redirectURI + `","client_id":"` + clientID + `","client_secret":"` + clientSecret + `","code_verifier":"` + codeVerifier + `"}`
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	f.handler.Token(response, request)
	return response
}

func TestTokenRejectsExpiredAndUsedCodes(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*tokenFixture)
	}{
		{name: "expired", setup: func(f *tokenFixture) { f.code.ExpiresAt = time.Now().Add(-time.Minute) }},
		{name: "used", setup: func(f *tokenFixture) { now := time.Now(); f.code.UsedAt = &now }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTokenFixture()
			test.setup(fixture)
			response := fixture.request(fixture.app.application.ClientID, "", fixture.redirect, fixture.verifier, fixture.rawCode)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestTokenRejectsWrongClientAndRedirectURI(t *testing.T) {
	tests := []struct {
		name        string
		clientID    string
		redirectURI string
		status      int
	}{
		{name: "wrong client", clientID: "other-client", redirectURI: "https://app.example/callback", status: http.StatusUnauthorized},
		{name: "wrong redirect URI", clientID: "app-client", redirectURI: "https://app.example/other", status: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTokenFixture()
			response := fixture.request(test.clientID, "", test.redirectURI, fixture.verifier, fixture.rawCode)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d, body = %s", response.Code, test.status, response.Body.String())
			}
			if fixture.code.UsedAt != nil {
				t.Fatal("invalid request consumed authorization code")
			}
		})
	}
}

func TestTokenRejectsInactiveSessionAndUser(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*tokenFixture)
	}{
		{name: "inactive session", setup: func(f *tokenFixture) { f.session.Status = "revoked" }},
		{name: "inactive user", setup: func(f *tokenFixture) { f.user.user.Status = "inactive" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTokenFixture()
			test.setup(fixture)
			response := fixture.request(fixture.app.application.ClientID, "", fixture.redirect, fixture.verifier, fixture.rawCode)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			if fixture.code.UsedAt != nil {
				t.Fatal("invalid request consumed authorization code")
			}
		})
	}
}

func TestTokenRejectsInvalidClientSecret(t *testing.T) {
	fixture := newTokenFixture()
	secretHash := "stored-secret-hash"
	valid := false
	fixture.app.application.ClientSecretHash = &secretHash
	fixture.app.clientSecretOK = &valid
	response := fixture.request(fixture.app.application.ClientID, "wrong-secret", fixture.redirect, fixture.verifier, fixture.rawCode)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if fixture.code.UsedAt != nil {
		t.Fatal("invalid client secret consumed authorization code")
	}
}

func TestTokenMetadataFailureDoesNotConsumeCode(t *testing.T) {
	fixture := newTokenFixture()
	fixture.tokens.createErr = errors.New("metadata insert failed")
	response := fixture.request(fixture.app.application.ClientID, "", fixture.redirect, fixture.verifier, fixture.rawCode)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if fixture.code.UsedAt != nil {
		t.Fatal("metadata failure consumed authorization code")
	}
}

func TestTokenConcurrentRedemptionHasOneSuccess(t *testing.T) {
	fixture := newTokenFixture()
	statuses := make(chan int, 2)
	var wait sync.WaitGroup
	wait.Add(2)
	for range 2 {
		go func() {
			defer wait.Done()
			response := fixture.request(fixture.app.application.ClientID, "", fixture.redirect, fixture.verifier, fixture.rawCode)
			statuses <- response.Code
		}()
	}
	wait.Wait()
	close(statuses)

	successes := 0
	invalidGrants := 0
	for status := range statuses {
		switch status {
		case http.StatusOK:
			successes++
		case http.StatusBadRequest:
			invalidGrants++
		}
	}
	if successes != 1 || invalidGrants != 1 {
		t.Fatalf("redemption statuses = success:%d invalid_grant:%d", successes, invalidGrants)
	}
}

func TestTokenRejectsCodeHashMismatch(t *testing.T) {
	fixture := newTokenFixture()
	fixture.code.CodeHash = idgen.HashToken("different-code")
	response := fixture.request(fixture.app.application.ClientID, "", fixture.redirect, fixture.verifier, fixture.rawCode)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if fixture.code.UsedAt != nil {
		t.Fatal("hash mismatch consumed authorization code")
	}
}
