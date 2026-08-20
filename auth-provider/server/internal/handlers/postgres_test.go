package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	appdb "github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/db"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/mfa"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/repository"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/tokens"
	"github.com/SomeonesDads/seleksilabpro-2/shared/idgen"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const integrationJWTKey = "integration-test-signing-key"

var acceptanceDatabaseURL string
var acceptanceContainerName string

// TestMain provisions a disposable database when callers do not provide one.
// This keeps PostgreSQL acceptance coverage mandatory instead of silently
// turning transaction and end-to-end tests into skips.
func TestMain(m *testing.M) {
	acceptanceDatabaseURL = strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if acceptanceDatabaseURL == "" {
		var err error
		acceptanceDatabaseURL, err = startAcceptancePostgres()
		if err != nil {
			// No Docker/PostgreSQL available: keep acceptanceDatabaseURL empty so
			// the DB-backed TestPostgres* tests skip gracefully instead of
			// aborting the whole package (the fake-based unit tests still run).
			fmt.Fprintf(os.Stderr, "postgres acceptance setup skipped: %v\n", err)
		}
	}

	code := m.Run()
	stopAcceptancePostgres()
	os.Exit(code)
}

func startAcceptancePostgres() (string, error) {
	name := "seleksilabpro-server-tests-" + uuid.NewString()
	output, err := exec.Command(
		"docker", "run", "--rm", "-d",
		"--name", name,
		"-e", "POSTGRES_USER=test",
		"-e", "POSTGRES_PASSWORD=test",
		"-e", "POSTGRES_DB=auth_test",
		"-p", "127.0.0.1::5432",
		"postgres:16-alpine",
	).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker run: %w: %s", err, strings.TrimSpace(string(output)))
	}
	acceptanceContainerName = name

	port, err := acceptancePostgresPort()
	if err != nil {
		stopAcceptancePostgres()
		return "", err
	}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if err := exec.Command("docker", "exec", acceptanceContainerName, "pg_isready", "-U", "test", "-d", "auth_test").Run(); err == nil && acceptancePostgresHostReady(port) {
			return "postgres://test:test@127.0.0.1:" + port + "/auth_test?sslmode=disable", nil
		}
		time.Sleep(500 * time.Millisecond)
	}

	logs, _ := exec.Command("docker", "logs", acceptanceContainerName).CombinedOutput()
	stopAcceptancePostgres()
	return "", fmt.Errorf("postgres container did not become ready: %s", strings.TrimSpace(string(logs)))
}

func acceptancePostgresPort() (string, error) {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		output, err := exec.Command("docker", "port", acceptanceContainerName, "5432/tcp").CombinedOutput()
		if err == nil {
			address := strings.TrimSpace(strings.SplitN(string(output), "\n", 2)[0])
			_, port, splitErr := net.SplitHostPort(address)
			if splitErr == nil && port != "" {
				return port, nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return "", fmt.Errorf("docker port lookup failed for %s", acceptanceContainerName)
}

func acceptancePostgresHostReady(port string) bool {
	connection, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), time.Second)
	if err != nil {
		return false
	}
	_ = connection.Close()
	return true
}

func stopAcceptancePostgres() {
	if acceptanceContainerName == "" {
		return
	}
	if output, err := exec.Command("docker", "rm", "-f", acceptanceContainerName).CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "postgres cleanup failed: %v: %s\n", err, strings.TrimSpace(string(output)))
	}
	acceptanceContainerName = ""
}

func openAcceptancePostgres(t *testing.T) *gorm.DB {
	t.Helper()
	databaseURL := acceptanceDatabaseURL
	if databaseURL == "" {
		t.Skip("PostgreSQL acceptance database is not configured (set TEST_DATABASE_URL or run docker)")
	}

	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve migration directory")
	}
	migrationsDir := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", "migrations"))
	deadline := time.Now().Add(30 * time.Second)
	var db *gorm.DB
	var lastErr error
	for {
		migrationContext, cancelMigration := context.WithTimeout(context.Background(), 5*time.Second)
		migrationErr := appdb.RunMigrations(migrationContext, databaseURL, migrationsDir)
		cancelMigration()
		if migrationErr != nil {
			lastErr = fmt.Errorf("run migrations: %w", migrationErr)
		} else {
			databaseContext, cancelDatabase := context.WithTimeout(context.Background(), 5*time.Second)
			db, lastErr = appdb.ConnectGORM(databaseContext, databaseURL)
			cancelDatabase()
			if lastErr == nil {
				break
			}
		}
		if acceptanceContainerName == "" || time.Now().After(deadline) {
			t.Fatalf("connect test database: %v", lastErr)
		}
		time.Sleep(500 * time.Millisecond)
	}
	resetAcceptancePostgres(t, db)
	t.Cleanup(func() {
		resetAcceptancePostgres(t, db)
		sqlDB, err := db.DB()
		if err == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

func resetAcceptancePostgres(t *testing.T, db *gorm.DB) {
	t.Helper()
	const query = `TRUNCATE TABLE
        event_deliveries,
        events,
        audit_logs,
        access_tokens,
        authorization_codes,
        mfa_login_challenges,
        user_totp_credentials,
        sso_sessions,
        application_group_policies,
        application_redirect_uris,
        user_groups,
        applications,
        groups,
        users
        RESTART IDENTITY CASCADE`
	if err := db.Exec(query).Error; err != nil {
		t.Fatalf("reset test database: %v", err)
	}
}

type postgresFlowFixture struct {
	user        models.User
	application models.Application
	session     models.SSOSession
}

func seedPostgresFlowFixture(t *testing.T, db *gorm.DB, withPolicy bool) postgresFlowFixture {
	t.Helper()
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	fixture := postgresFlowFixture{
		user: models.User{
			ID:           uuid.New(),
			Name:         "Ada",
			Email:        "ada-" + uuid.NewString() + "@example.com",
			PasswordHash: string(passwordHash),
			Status:       "active",
		},
		application: models.Application{
			ID:                    uuid.New(),
			Name:                  "Integration App",
			ClientID:              "app-client-" + uuid.NewString(),
			Status:                "active",
			LogoutNotificationURL: "http://app.example/internal/logout",
		},
		session: models.SSOSession{
			ID:               uuid.New(),
			UserID:           uuid.Nil,
			SessionTokenHash: idgen.HashToken("integration-session-" + uuid.NewString()),
			Status:           "active",
			ExpiresAt:        time.Now().Add(time.Hour),
		},
	}
	fixture.session.UserID = fixture.user.ID
	for _, value := range []any{&fixture.user, &fixture.application, &fixture.session} {
		if err := db.Create(value).Error; err != nil {
			t.Fatalf("seed flow fixture: %v", err)
		}
	}
	redirect := &models.ApplicationRedirectURI{ID: uuid.New(), ApplicationID: fixture.application.ID, RedirectURI: "https://app.example/callback"}
	if err := db.Create(redirect).Error; err != nil {
		t.Fatalf("seed redirect URI: %v", err)
	}
	if withPolicy {
		group := &models.Group{ID: uuid.New(), Name: "app-users-" + uuid.NewString()}
		if err := db.Create(group).Error; err != nil {
			t.Fatalf("seed group: %v", err)
		}
		if err := db.Create(&models.UserGroup{ID: uuid.New(), UserID: fixture.user.ID, GroupID: group.ID}).Error; err != nil {
			t.Fatalf("seed membership: %v", err)
		}
		if err := db.Create(&models.ApplicationGroupPolicy{ID: uuid.New(), ApplicationID: fixture.application.ID, GroupID: group.ID, Effect: "allow"}).Error; err != nil {
			t.Fatalf("seed policy: %v", err)
		}
	}
	return fixture
}

func postgresAuthHandler(db *gorm.DB) *AuthHandler {
	users := repository.NewUserRepository(db)
	mfa := repository.NewMFARepository(db)
	totp := repository.NewTOTPRepository(db)
	applications := repository.NewApplicationRepository(db)
	policies := repository.NewPolicyRepository(db)
	sessions := repository.NewSessionRepository(db)
	codes := repository.NewAuthorizationCodeRepository(db)
	audit := repository.NewAuditRepository(db)
	accessTokens := repository.NewAccessTokenRepository(db)
	groups := repository.NewGroupRepository(db)
	return NewAuthHandlerWithDependencies(AuthRepositories{
		Users:             users,
		UserProfiles:      users,
		MFA:               mfa,
		TOTP:              totp,
		Applications:      applications,
		Policies:          policies,
		Sessions:          sessions,
		SessionLookup:     sessions,
		SessionRevocation: sessions,
		AuthorizationCode: codes,
		TokenRedemption:   codes,
		Audit:             audit,
		AccessTokens:      accessTokens,
		Groups:            groups,
	}, AuthHandlerConfig{
		AuthCodeTTL:    time.Minute,
		AccessTokenTTL: time.Minute,
		SessionTTL:     time.Hour,
		JWTIssuer:      "auth-provider",
		JWTSigningKey:  []byte(integrationJWTKey),
		TokenStrategy:  "jwt",
	}, nil)
}

func TestPostgresAuthorizationCodeRedemptionIsAtomicAndConcurrent(t *testing.T) {
	db := openAcceptancePostgres(t)
	fixture := seedPostgresFlowFixture(t, db, false)
	codeRepo := repository.NewAuthorizationCodeRepository(db)
	code := &models.AuthorizationCode{
		ID:                  uuid.New(),
		CodeHash:            idgen.HashToken("concurrent-code"),
		UserID:              fixture.user.ID,
		ApplicationID:       fixture.application.ID,
		SSOSessionID:        fixture.session.ID,
		RedirectURI:         "https://app.example/callback",
		CodeChallenge:       testPKCEChallenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(time.Minute),
	}
	if err := codeRepo.Create(context.Background(), code); err != nil {
		t.Fatal(err)
	}

	errorsCh := make(chan error, 2)
	var wait sync.WaitGroup
	wait.Add(2)
	for range 2 {
		go func() {
			defer wait.Done()
			errorsCh <- codeRepo.Redeem(context.Background(), code.ID, &models.AccessToken{
				JTI:           uuid.New(),
				UserID:        fixture.user.ID,
				ApplicationID: fixture.application.ID,
				SessionID:     fixture.session.ID,
				ExpiresAt:     time.Now().Add(time.Minute),
			})
		}()
	}
	wait.Wait()
	close(errorsCh)

	successes := 0
	invalidGrants := 0
	for err := range errorsCh {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, repository.ErrAuthorizationCodeNotFound):
			invalidGrants++
		default:
			t.Fatalf("unexpected concurrent redemption error: %v", err)
		}
	}
	if successes != 1 || invalidGrants != 1 {
		t.Fatalf("redemption results = success:%d invalid:%d", successes, invalidGrants)
	}
	var storedCode models.AuthorizationCode
	if err := db.First(&storedCode, "id = ?", code.ID).Error; err != nil {
		t.Fatal(err)
	}
	if storedCode.UsedAt == nil {
		t.Fatal("successful redemption did not mark code used")
	}
	var tokenCount int64
	if err := db.Model(&models.AccessToken{}).Where("session_id = ?", fixture.session.ID).Count(&tokenCount).Error; err != nil {
		t.Fatal(err)
	}
	if tokenCount != 1 {
		t.Fatalf("access-token metadata rows = %d, want 1", tokenCount)
	}

	duplicateJTI := uuid.New()
	if err := db.Create(&models.AccessToken{
		JTI:           duplicateJTI,
		UserID:        fixture.user.ID,
		ApplicationID: fixture.application.ID,
		SessionID:     fixture.session.ID,
		ExpiresAt:     time.Now().Add(time.Minute),
	}).Error; err != nil {
		t.Fatal(err)
	}
	rollbackCode := &models.AuthorizationCode{
		ID:                  uuid.New(),
		CodeHash:            idgen.HashToken("rollback-code"),
		UserID:              fixture.user.ID,
		ApplicationID:       fixture.application.ID,
		SSOSessionID:        fixture.session.ID,
		RedirectURI:         "https://app.example/callback",
		CodeChallenge:       testPKCEChallenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(time.Minute),
	}
	if err := codeRepo.Create(context.Background(), rollbackCode); err != nil {
		t.Fatal(err)
	}
	if err := codeRepo.Redeem(context.Background(), rollbackCode.ID, &models.AccessToken{
		JTI:           duplicateJTI,
		UserID:        fixture.user.ID,
		ApplicationID: fixture.application.ID,
		SessionID:     fixture.session.ID,
		ExpiresAt:     time.Now().Add(time.Minute),
	}); err == nil {
		t.Fatal("duplicate token metadata unexpectedly redeemed authorization code")
	}
	var unconsumedCode models.AuthorizationCode
	if err := db.First(&unconsumedCode, "id = ?", rollbackCode.ID).Error; err != nil {
		t.Fatal(err)
	}
	if unconsumedCode.UsedAt != nil {
		t.Fatal("metadata failure committed authorization-code consumption")
	}
}

func TestPostgresMFAEnforcesExpiryAttemptLimitAndFinalAttempt(t *testing.T) {
	db := openAcceptancePostgres(t)
	fixture := seedPostgresFlowFixture(t, db, false)
	mfaRepo := repository.NewMFARepository(db)

	expired := &models.MFALoginChallenge{ID: uuid.New(), UserID: fixture.user.ID, TokenHash: idgen.HashToken("expired-mfa"), ExpiresAt: time.Now().Add(-time.Second)}
	if err := mfaRepo.Create(context.Background(), expired); err != nil {
		t.Fatal(err)
	}
	if _, err := mfaRepo.FindActiveByToken(context.Background(), expired.TokenHash, mfaMaxAttempts); !errors.Is(err, repository.ErrMFAChallengeNotFound) {
		t.Fatalf("expired MFA state lookup error = %v", err)
	}

	limited := &models.MFALoginChallenge{ID: uuid.New(), UserID: fixture.user.ID, TokenHash: idgen.HashToken("limited-mfa"), ExpiresAt: time.Now().Add(time.Minute), Attempts: mfaMaxAttempts}
	if err := mfaRepo.Create(context.Background(), limited); err != nil {
		t.Fatal(err)
	}
	if _, err := mfaRepo.FindActiveByToken(context.Background(), limited.TokenHash, mfaMaxAttempts); !errors.Is(err, repository.ErrMFAChallengeNotFound) {
		t.Fatalf("attempt-limited MFA state lookup error = %v", err)
	}

	final := &models.MFALoginChallenge{ID: uuid.New(), UserID: fixture.user.ID, TokenHash: idgen.HashToken("final-mfa"), ExpiresAt: time.Now().Add(time.Minute), Attempts: mfaMaxAttempts - 1}
	if err := mfaRepo.Create(context.Background(), final); err != nil {
		t.Fatal(err)
	}
	claimed, err := mfaRepo.ClaimAttempt(context.Background(), final.ID, mfaMaxAttempts)
	if err != nil || !claimed {
		t.Fatalf("final MFA attempt was not reserved: claimed=%v err=%v", claimed, err)
	}
	if err := mfaRepo.ConsumeAndCreateSession(context.Background(), final.ID, &models.SSOSession{
		ID:               uuid.New(),
		UserID:           fixture.user.ID,
		SessionTokenHash: idgen.HashToken("mfa-session"),
		Status:           "active",
		ExpiresAt:        time.Now().Add(time.Hour),
	}, mfaMaxAttempts); err != nil {
		t.Fatalf("valid final MFA attempt failed: %v", err)
	}
	var consumed models.MFALoginChallenge
	if err := db.First(&consumed, "id = ?", final.ID).Error; err != nil {
		t.Fatal(err)
	}
	if consumed.UsedAt == nil || consumed.Attempts != mfaMaxAttempts {
		t.Fatalf("final MFA state not consumed correctly: %+v", consumed)
	}
}

func TestPostgresSessionRevocationOutboxIsAtomicCompleteAndIdempotent(t *testing.T) {
	db := openAcceptancePostgres(t)
	fixture := seedPostgresFlowFixture(t, db, false)
	sessions := repository.NewSessionRepository(db)

	if err := db.Exec(`CREATE OR REPLACE FUNCTION test_reject_event_insert() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'forced event insert failure';
END;
$$ LANGUAGE plpgsql`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`CREATE TRIGGER test_reject_event_insert BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION test_reject_event_insert()`).Error; err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = db.Exec(`DROP TRIGGER IF EXISTS test_reject_event_insert ON events`).Error
		_ = db.Exec(`DROP FUNCTION IF EXISTS test_reject_event_insert()`).Error
	}()

	if err := sessions.RevokeAndCreateEvent(context.Background(), fixture.session.ID, "sso_logout"); err == nil {
		t.Fatal("event insert failure unexpectedly committed revocation")
	}
	var activeSession models.SSOSession
	if err := db.First(&activeSession, "id = ?", fixture.session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if activeSession.Status != "active" || activeSession.RevokedAt != nil {
		t.Fatalf("revocation was committed despite outbox failure: %+v", activeSession)
	}
	var eventCount int64
	if err := db.Model(&models.Event{}).Where("central_session_id = ?", fixture.session.ID).Count(&eventCount).Error; err != nil {
		t.Fatal(err)
	}
	if eventCount != 0 {
		t.Fatalf("outbox event survived failed transaction: %d", eventCount)
	}
	if err := db.Exec(`DROP TRIGGER test_reject_event_insert ON events`).Error; err != nil {
		t.Fatal(err)
	}

	if err := sessions.RevokeAndCreateEvent(context.Background(), fixture.session.ID, "sso_logout"); err != nil {
		t.Fatalf("successful revocation failed: %v", err)
	}
	if err := sessions.RevokeAndCreateEvent(context.Background(), fixture.session.ID, "sso_logout"); !errors.Is(err, repository.ErrSessionNotFound) {
		t.Fatalf("repeat revocation error = %v", err)
	}
	var revokedSession models.SSOSession
	if err := db.First(&revokedSession, "id = ?", fixture.session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if revokedSession.Status != "revoked" || revokedSession.RevokedAt == nil || revokedSession.RevokeReason == nil || *revokedSession.RevokeReason != "sso_logout" {
		t.Fatalf("successful revocation state incomplete: %+v", revokedSession)
	}
	var event models.Event
	if err := db.Where("central_session_id = ?", fixture.session.ID).First(&event).Error; err != nil {
		t.Fatal(err)
	}
	if event.EventType != models.EventSessionRevoked || event.ApplicationID != nil || event.PublishedAt != nil {
		t.Fatalf("event metadata incorrect: %+v", event)
	}
	for _, field := range []string{"eventId", "eventType", "userId", "centralSessionId", "applicationId", "reason", "occurredAt", "metadata"} {
		if _, ok := event.Payload[field]; !ok {
			t.Fatalf("event payload missing %q: %+v", field, event.Payload)
		}
	}
	if event.Payload["eventId"] != event.ID.String() || event.Payload["eventType"] != models.EventSessionRevoked || event.Payload["userId"] != fixture.user.ID.String() || event.Payload["centralSessionId"] != fixture.session.ID.String() || event.Payload["applicationId"] != nil || event.Payload["reason"] != "sso_logout" {
		t.Fatalf("event payload values incorrect: %+v", event.Payload)
	}
	if err := db.Model(&models.Event{}).Where("central_session_id = ?", fixture.session.ID).Count(&eventCount).Error; err != nil {
		t.Fatal(err)
	}
	if eventCount != 1 {
		t.Fatalf("repeat revocation created %d events", eventCount)
	}
}

func TestPostgresAuthFlowLoginAuthorizeTokenUserInfoLogoutAndOutbox(t *testing.T) {
	db := openAcceptancePostgres(t)
	fixture := seedPostgresFlowFixture(t, db, true)
	handler := postgresAuthHandler(db)

	loginRequest := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"email":"`+fixture.user.Email+`","password":"password"}`))
	loginRequest.Header.Set("Content-Type", "application/json")
	loginResponse := httptest.NewRecorder()
	handler.Login(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusOK {
		t.Fatalf("login failed: status=%d body=%s", loginResponse.Code, loginResponse.Body.String())
	}
	sessionCookie := acceptanceCookie(t, loginResponse, ssoSessionCookie)
	if sessionCookie.Value == "" {
		t.Fatal("login did not return central session cookie")
	}
	issuedSession, err := repository.NewSessionRepository(db).FindActiveByTokenHash(context.Background(), idgen.HashToken(sessionCookie.Value))
	if err != nil {
		t.Fatalf("lookup issued central session: %v", err)
	}

	verifier := "integration-verifier"
	authorizeURL, err := url.Parse(acceptanceAuthorizeURL("https://app.example/callback", idgen.PKCEChallengeS256(verifier)))
	if err != nil {
		t.Fatal(err)
	}
	query := authorizeURL.Query()
	query.Set("client_id", fixture.application.ClientID)
	authorizeURL.RawQuery = query.Encode()
	authorizeRequest := httptest.NewRequest(http.MethodGet, authorizeURL.String(), nil)
	authorizeRequest.AddCookie(sessionCookie)
	authorizeResponse := httptest.NewRecorder()
	handler.Authorize(authorizeResponse, authorizeRequest)
	if authorizeResponse.Code != http.StatusFound {
		t.Fatalf("authorize failed: status=%d body=%s", authorizeResponse.Code, authorizeResponse.Body.String())
	}
	location := authorizeResponse.Header().Get("Location")
	redirected, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	rawCode := redirected.Query().Get("code")
	if rawCode == "" || redirected.Query().Get("state") != "state-123" {
		t.Fatalf("authorize redirect incomplete: %q", location)
	}

	tokenRequest := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"grant_type":"authorization_code","code":"`+rawCode+`","redirect_uri":"https://app.example/callback","client_id":"`+fixture.application.ClientID+`","code_verifier":"`+verifier+`"}`))
	tokenRequest.Header.Set("Content-Type", "application/json")
	tokenResponse := httptest.NewRecorder()
	handler.Token(tokenResponse, tokenRequest)
	if tokenResponse.Code != http.StatusOK {
		t.Fatalf("token exchange failed: status=%d body=%s", tokenResponse.Code, tokenResponse.Body.String())
	}
	var tokenPayload struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(tokenResponse.Body.Bytes(), &tokenPayload); err != nil {
		t.Fatal(err)
	}
	if tokenPayload.AccessToken == "" || tokenPayload.TokenType != "Bearer" || tokenPayload.ExpiresIn != 60 {
		t.Fatalf("invalid token response: %+v", tokenPayload)
	}
	claims, err := tokens.ValidateAccessToken(tokenPayload.AccessToken, []byte(integrationJWTKey), "auth-provider", fixture.application.ID.String())
	if err != nil || claims.Subject != fixture.user.ID.String() || claims.SID != issuedSession.ID.String() || claims.Scope != tokens.DefaultScope {
		t.Fatalf("invalid integration token claims: claims=%+v err=%v", claims, err)
	}

	userinfoRequest := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	userinfoRequest.Header.Set("Authorization", "Bearer "+tokenPayload.AccessToken)
	userinfoRequest.Header.Set("X-Client-ID", fixture.application.ClientID)
	userinfoResponse := httptest.NewRecorder()
	handler.UserInfo(userinfoResponse, userinfoRequest)
	if userinfoResponse.Code != http.StatusOK {
		t.Fatalf("userinfo failed: status=%d body=%s", userinfoResponse.Code, userinfoResponse.Body.String())
	}
	var profile map[string]any
	if err := json.Unmarshal(userinfoResponse.Body.Bytes(), &profile); err != nil {
		t.Fatal(err)
	}
	if profile["sub"] != fixture.user.ID.String() || profile["email"] != fixture.user.Email || profile["name"] != fixture.user.Name {
		t.Fatalf("integration profile incorrect: %+v", profile)
	}

	logoutRequest := httptest.NewRequest(http.MethodPost, "/logout", nil)
	logoutRequest.AddCookie(sessionCookie)
	logoutResponse := httptest.NewRecorder()
	handler.Logout(logoutResponse, logoutRequest)
	if logoutResponse.Code != http.StatusOK || acceptanceCookie(t, logoutResponse, ssoSessionCookie).MaxAge != -1 {
		t.Fatalf("logout failed to clear session: status=%d cookies=%v", logoutResponse.Code, logoutResponse.Result().Cookies())
	}
	var revokedSession models.SSOSession
	if err := db.First(&revokedSession, "id = ?", issuedSession.ID).Error; err != nil {
		t.Fatal(err)
	}
	if revokedSession.Status != "revoked" {
		t.Fatalf("central session was not revoked: %+v", revokedSession)
	}
	userinfoAfterLogout := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	userinfoAfterLogout.Header.Set("Authorization", "Bearer "+tokenPayload.AccessToken)
	userinfoAfterLogout.Header.Set("X-Client-ID", fixture.application.ClientID)
	userinfoAfterLogoutResponse := httptest.NewRecorder()
	handler.UserInfo(userinfoAfterLogoutResponse, userinfoAfterLogout)
	if userinfoAfterLogoutResponse.Code != http.StatusUnauthorized {
		t.Fatalf("UserInfo accepted token after SSO logout: status=%d body=%s", userinfoAfterLogoutResponse.Code, userinfoAfterLogoutResponse.Body.String())
	}

	var event models.Event
	if err := db.Where("event_type = ? AND central_session_id = ?", models.EventSessionRevoked, issuedSession.ID).First(&event).Error; err != nil {
		t.Fatal(err)
	}
	if event.Payload["eventId"] != event.ID.String() || event.Payload["userId"] != fixture.user.ID.String() || event.Payload["centralSessionId"] != issuedSession.ID.String() || event.Payload["applicationId"] != nil || event.Payload["reason"] != "sso_logout" {
		t.Fatalf("integration outbox payload incomplete: %+v", event.Payload)
	}
	for _, eventType := range []string{"LoginSucceeded", "AuthorizationCodeIssued", "TokenIssued", "Logout"} {
		var count int64
		if err := db.Model(&models.AuditLog{}).Where("event_type = ?", eventType).Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("audit event %q count = %d, want 1", eventType, count)
		}
	}
}

// TestPostgresPolicyDeletionRevokesAppTokensAndEmitsEvent verifies Decision 016:
// deleting an allow policy revokes only the affected application's access-token
// metadata (not the central SSO session, not unrelated applications) and emits a
// single AccessPolicyChanged outbox event.
func TestPostgresPolicyDeletionRevokesAppTokensAndEmitsEvent(t *testing.T) {
	db := openAcceptancePostgres(t)
	fixture := seedPostgresFlowFixture(t, db, true)

	var policy models.ApplicationGroupPolicy
	if err := db.First(&policy, "application_id = ?", fixture.application.ID).Error; err != nil {
		t.Fatal(err)
	}

	// Active access token for the application whose policy will be deleted.
	appToken := &models.AccessToken{
		JTI:           uuid.New(),
		UserID:        fixture.user.ID,
		ApplicationID: fixture.application.ID,
		SessionID:     fixture.session.ID,
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	if err := db.Create(appToken).Error; err != nil {
		t.Fatal(err)
	}

	// Unrelated application the user keeps access to via a separate policy.
	otherApp := models.Application{ID: uuid.New(), Name: "Other App", ClientID: "other-client-" + uuid.NewString(), Status: "active", LogoutNotificationURL: "http://other.example/internal/logout"}
	otherGroup := models.Group{ID: uuid.New(), Name: "other-users-" + uuid.NewString()}
	if err := db.Create(&otherApp).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&otherGroup).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.UserGroup{ID: uuid.New(), UserID: fixture.user.ID, GroupID: otherGroup.ID}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.ApplicationGroupPolicy{ID: uuid.New(), ApplicationID: otherApp.ID, GroupID: otherGroup.ID, Effect: "allow"}).Error; err != nil {
		t.Fatal(err)
	}
	otherToken := &models.AccessToken{
		JTI:           uuid.New(),
		UserID:        fixture.user.ID,
		ApplicationID: otherApp.ID,
		SessionID:     fixture.session.ID,
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	if err := db.Create(otherToken).Error; err != nil {
		t.Fatal(err)
	}

	adminH := NewAdminHandler(AdminRepositories{Policies: repository.NewPolicyRepository(db)}, nil)
	request := httptest.NewRequest(http.MethodDelete, "/admin/applications/"+fixture.application.ID.String()+"?group_id="+policy.GroupID.String(), nil)
	request.SetPathValue("id", fixture.application.ID.String())
	response := httptest.NewRecorder()
	adminH.DeleteApplicationGroupPolicy(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("policy deletion failed: status=%d body=%s", response.Code, response.Body.String())
	}

	var revokedToken models.AccessToken
	if err := db.First(&revokedToken, "jti = ?", appToken.JTI).Error; err != nil {
		t.Fatal(err)
	}
	if revokedToken.RevokedAt == nil {
		t.Fatalf("affected application access token was not revoked: %+v", revokedToken)
	}

	var preservedToken models.AccessToken
	if err := db.First(&preservedToken, "jti = ?", otherToken.JTI).Error; err != nil {
		t.Fatal(err)
	}
	if preservedToken.RevokedAt != nil {
		t.Fatalf("unrelated application access token was wrongly revoked: %+v", preservedToken)
	}

	var session models.SSOSession
	if err := db.First(&session, "id = ?", fixture.session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if session.Status != "active" || session.RevokedAt != nil {
		t.Fatalf("central SSO session was wrongly revoked: %+v", session)
	}

	var eventCount int64
	if err := db.Model(&models.Event{}).
		Where("event_type = ? AND user_id = ? AND application_id = ?", models.EventAccessPolicyChanged, fixture.user.ID, fixture.application.ID).
		Count(&eventCount).Error; err != nil {
		t.Fatal(err)
	}
	if eventCount != 1 {
		t.Fatalf("AccessPolicyChanged event count = %d, want 1", eventCount)
	}
}

// TestPostgresMFAEnrollmentRequiresConfirmationBeforeLogin verifies the
// pending/enrolled split: a pending (unconfirmed) credential does NOT require
// MFA at login, while a confirmed one does.
func TestPostgresMFAEnrollmentRequiresConfirmationBeforeLogin(t *testing.T) {
	db := openAcceptancePostgres(t)
	mfaKey := []byte("integration-mfa-key-0123456789xy")

	passwordHash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	user := models.User{ID: uuid.New(), Name: "Ada", Email: "ada-" + uuid.NewString() + "@example.com", PasswordHash: string(passwordHash), Status: "active"}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	rawToken := "mfa-test-session-" + uuid.NewString()
	session := models.SSOSession{ID: uuid.New(), UserID: user.ID, SessionTokenHash: idgen.HashToken(rawToken), Status: "active", ExpiresAt: time.Now().Add(time.Hour)}
	if err := db.Create(&session).Error; err != nil {
		t.Fatal(err)
	}

	users := repository.NewUserRepository(db)
	totpRepo := repository.NewTOTPRepository(db)
	sessionRepo := repository.NewSessionRepository(db)
	authH := NewAuthHandlerWithDependencies(AuthRepositories{
		Users:             users,
		UserProfiles:      users,
		TOTP:              totpRepo,
		MFA:               repository.NewMFARepository(db),
		Sessions:          sessionRepo,
		SessionLookup:     sessionRepo,
		SessionRevocation: sessionRepo,
	}, AuthHandlerConfig{
		JWTIssuer:        "auth-provider",
		JWTSigningKey:    []byte(integrationJWTKey),
		TokenStrategy:    "jwt",
		MFAEncryptionKey: mfaKey,
	}, nil)
	authH.VerifyMFA = mfa.NewTOTPVerifier(totpRepo, mfaKey).Verify

	loginBody := `{"email":"` + user.Email + `","password":"password"}`

	// No TOTP yet: login succeeds without MFA.
	noMFALoginReq := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(loginBody))
	noMFALoginReq.Header.Set("Content-Type", "application/json")
	noMFALogin := httptest.NewRecorder()
	authH.Login(noMFALogin, noMFALoginReq)
	if noMFALogin.Code != http.StatusOK {
		t.Fatalf("login without MFA failed: status=%d body=%s", noMFALogin.Code, noMFALogin.Body.String())
	}
	var noMFAProfile map[string]any
	if err := json.Unmarshal(noMFALogin.Body.Bytes(), &noMFAProfile); err != nil {
		t.Fatal(err)
	}
	if noMFAProfile["mfa_required"] != false {
		t.Fatalf("expected mfa_required=false before enrollment, got %+v", noMFAProfile)
	}

	// Begin enrollment.
	enrollReq := httptest.NewRequest(http.MethodPost, "/mfa/enroll", nil)
	enrollReq.AddCookie(&http.Cookie{Name: ssoSessionCookie, Value: rawToken})
	enrollResp := httptest.NewRecorder()
	authH.EnrollMFA(enrollResp, enrollReq)
	if enrollResp.Code != http.StatusOK {
		t.Fatalf("enrollment failed: status=%d body=%s", enrollResp.Code, enrollResp.Body.String())
	}
	var enrollBody map[string]any
	if err := json.Unmarshal(enrollResp.Body.Bytes(), &enrollBody); err != nil {
		t.Fatal(err)
	}
	secret, _ := enrollBody["secret"].(string)
	if secret == "" {
		t.Fatalf("enrollment did not return a secret: %+v", enrollBody)
	}

	// Pending credential must NOT require MFA at login.
	pendingLoginReq := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(loginBody))
	pendingLoginReq.Header.Set("Content-Type", "application/json")
	pendingLogin := httptest.NewRecorder()
	authH.Login(pendingLogin, pendingLoginReq)
	if pendingLogin.Code != http.StatusOK {
		t.Fatalf("login with pending MFA failed: status=%d body=%s", pendingLogin.Code, pendingLogin.Body.String())
	}
	var pendingProfile map[string]any
	if err := json.Unmarshal(pendingLogin.Body.Bytes(), &pendingProfile); err != nil {
		t.Fatal(err)
	}
	if pendingProfile["mfa_required"] != false {
		t.Fatalf("pending MFA must not block login: %+v", pendingProfile)
	}

	// Confirm with a valid code.
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	confirmReq := httptest.NewRequest(http.MethodPost, "/mfa/enroll/confirm", strings.NewReader(`{"code":"`+code+`"}`))
	confirmReq.AddCookie(&http.Cookie{Name: ssoSessionCookie, Value: rawToken})
	confirmResp := httptest.NewRecorder()
	authH.ConfirmMFAEnrollment(confirmResp, confirmReq)
	if confirmResp.Code != http.StatusOK {
		t.Fatalf("MFA confirm failed: status=%d body=%s", confirmResp.Code, confirmResp.Body.String())
	}

	// Now login must require MFA.
	confirmedLoginReq := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(loginBody))
	confirmedLoginReq.Header.Set("Content-Type", "application/json")
	confirmedLogin := httptest.NewRecorder()
	authH.Login(confirmedLogin, confirmedLoginReq)
	if confirmedLogin.Code != http.StatusOK {
		t.Fatalf("confirmed login unexpected status: %d body=%s", confirmedLogin.Code, confirmedLogin.Body.String())
	}
	var confirmedProfile map[string]any
	if err := json.Unmarshal(confirmedLogin.Body.Bytes(), &confirmedProfile); err != nil {
		t.Fatal(err)
	}
	if confirmedProfile["mfa_required"] != true {
		t.Fatalf("confirmed MFA must require second factor: %+v", confirmedProfile)
	}
}
