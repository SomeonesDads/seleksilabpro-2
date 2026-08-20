package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/applications/app-b/internal/auth"
	"github.com/SomeonesDads/seleksilabpro-2/applications/app-b/internal/store"
	"github.com/google/uuid"
)

const testUserSub = "11111111-1111-1111-1111-111111111111"
const testCentralSession = "22222222-2222-2222-2222-222222222222"

type fakeProvider struct {
	exchangeErr bool
}

func (f *fakeProvider) AuthorizeURL(state, challenge, redirectURI string) string {
	v := url.Values{}
	v.Set("state", state)
	v.Set("redirect_uri", redirectURI)
	return "http://auth.example/authorize?" + v.Encode()
}

func (f *fakeProvider) ExchangeCode(ctx context.Context, code, redirectURI, verifier string) (string, error) {
	if f.exchangeErr || code == "bad" {
		return "", errors.New("token exchange failed")
	}
	return "fake-access-token", nil
}

func (f *fakeProvider) FetchProfile(ctx context.Context, token string) (*auth.Profile, error) {
	return &auth.Profile{
		Sub:              testUserSub,
		Email:            "user@example.com",
		Name:             "Test User",
		Groups:           []string{"app-b-users"},
		CentralSessionID: testCentralSession,
	}, nil
}

func newTestMux(a *App) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", a.Home)
	mux.HandleFunc("GET /login", a.Login)
	mux.HandleFunc("GET /auth/callback", a.Callback)
	mux.HandleFunc("POST /logout", a.Logout)
	mux.HandleFunc("POST /internal/logout", a.InternalLogout)
	return mux
}

func newClient(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	c := srv.Client()
	c.Jar = jar
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return c
}

func ptrUUID(s string) *uuid.UUID {
	u := uuid.MustParse(s)
	return &u
}

func doLogin(t *testing.T, client *http.Client, base string) string {
	t.Helper()
	resp, err := client.Get(base + "/login")
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login expected 302, got %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("redirect missing state")
	}
	return state
}

func TestHomeNoSession(t *testing.T) {
	app := newTestApp(t)
	srv := httptest.NewServer(newTestMux(app))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("home: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("home status %d", resp.StatusCode)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "Sign in") {
		t.Fatalf("expected landing page, got: %s", body)
	}
}

func TestFullLoginFlow(t *testing.T) {
	app := newTestApp(t)
	srv := httptest.NewServer(newTestMux(app))
	defer srv.Close()
	client := newClient(t, srv)

	state := doLogin(t, client, srv.URL)
	cb := srv.URL + "/auth/callback?code=good&state=" + url.QueryEscape(state)
	resp, err := client.Get(cb)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback expected 302, got %d body=%s", resp.StatusCode, readBody(t, resp))
	}
	if resp.Header.Get("Set-Cookie") == "" {
		t.Fatal("expected session cookie")
	}
	for _, c := range resp.Cookies() {
		if c.Name == cookieName && !c.HttpOnly {
			t.Fatal("session cookie must be HttpOnly")
		}
		if c.Name == cookieName && c.Secure {
			t.Fatal("test cookie should not be Secure (dev config)")
		}
	}

	// Dashboard now shows the identity from the profile cache.
	home, err := client.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("home after login: %v", err)
	}
	defer home.Body.Close()
	body := readBody(t, home)
	if !strings.Contains(body, "Hello, Test User") {
		t.Fatalf("expected greeting, got: %s", body)
	}
	if !strings.Contains(body, "APP B") {
		t.Fatal("expected app name")
	}
	if !strings.Contains(body, testUserSub) {
		t.Fatal("expected external user id shown")
	}

	// Exactly one active local session exists.
	if n := activeSessions(t, app, testUserSub); n != 1 {
		t.Fatalf("expected 1 active session, got %d", n)
	}
}

func TestStateReplayRejected(t *testing.T) {
	app := newTestApp(t)
	srv := httptest.NewServer(newTestMux(app))
	defer srv.Close()
	client := srv.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }

	state := doLogin(t, client, srv.URL)
	cb := srv.URL + "/auth/callback?code=good&state=" + url.QueryEscape(state)
	if _, err := client.Get(cb); err != nil {
		t.Fatalf("first callback: %v", err)
	}
	// Replay the same consumed state.
	replay, err := client.Get(cb)
	if err != nil {
		t.Fatalf("replay callback: %v", err)
	}
	defer replay.Body.Close()
	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay expected 400, got %d", replay.StatusCode)
	}
	if n := activeSessions(t, app, testUserSub); n != 1 {
		t.Fatalf("replay must not create a session, got %d active", n)
	}
}

func TestTamperedStateRejected(t *testing.T) {
	app := newTestApp(t)
	srv := httptest.NewServer(newTestMux(app))
	defer srv.Close()
	client := srv.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := client.Get(srv.URL + "/auth/callback?code=good&state=" + uuid.NewString())
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("tampered state expected 400, got %d", resp.StatusCode)
	}
	if n := activeSessions(t, app, testUserSub); n != 0 {
		t.Fatalf("no session expected, got %d", n)
	}
}

func TestExchangeFailureNoSession(t *testing.T) {
	app := newTestApp(t)
	srv := httptest.NewServer(newTestMux(app))
	defer srv.Close()
	client := srv.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }

	state := doLogin(t, client, srv.URL)
	cb := srv.URL + "/auth/callback?code=bad&state=" + url.QueryEscape(state)
	resp, err := client.Get(cb)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusFound {
		t.Fatal("exchange failure must not create a session")
	}
	if n := activeSessions(t, app, testUserSub); n != 0 {
		t.Fatalf("no session expected on exchange failure, got %d", n)
	}
}

func TestLocalLogout(t *testing.T) {
	app := newTestApp(t)
	srv := httptest.NewServer(newTestMux(app))
	defer srv.Close()
	client := newClient(t, srv)

	state := doLogin(t, client, srv.URL)
	cb := srv.URL + "/auth/callback?code=good&state=" + url.QueryEscape(state)
	if _, err := client.Get(cb); err != nil {
		t.Fatalf("callback: %v", err)
	}
	if n := activeSessions(t, app, testUserSub); n != 1 {
		t.Fatalf("expected 1 active session, got %d", n)
	}

	resp, err := client.Post(srv.URL+"/logout", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("logout expected 302, got %d", resp.StatusCode)
	}
	if n := activeSessions(t, app, testUserSub); n != 0 {
		t.Fatalf("expected 0 active sessions after logout, got %d", n)
	}

	home, err := client.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("home after logout: %v", err)
	}
	defer home.Body.Close()
	if strings.Contains(readBody(t, home), "Hello, Test User") {
		t.Fatal("should be logged out")
	}
}

func TestInternalLogoutRevokesAndIsIdempotent(t *testing.T) {
	app := newTestApp(t)
	srv := httptest.NewServer(newTestMux(app))
	defer srv.Close()
	client := srv.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }

	state := doLogin(t, client, srv.URL)
	cb := srv.URL + "/auth/callback?code=good&state=" + url.QueryEscape(state)
	if _, err := client.Get(cb); err != nil {
		t.Fatalf("callback: %v", err)
	}
	if n := activeSessions(t, app, testUserSub); n != 1 {
		t.Fatalf("expected 1 active session, got %d", n)
	}

	event := revocationEvent{
		EventID:          uuid.New(),
		EventType:        "SessionRevoked",
		UserID:           uuid.MustParse(testUserSub),
		CentralSessionID: ptrUUID(testCentralSession),
		Reason:           "sso_logout",
		OccurredAt:       time.Now().UTC(),
	}
	body, _ := json.Marshal(event)

	// Wrong auth token -> 401.
	br := postEvent(t, srv.URL+"/internal/logout", body, "wrong")
	if br.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong auth expected 401, got %d", br.StatusCode)
	}
	_ = br.Body.Close()
	if n := activeSessions(t, app, testUserSub); n != 1 {
		t.Fatalf("session must survive invalid auth, got %d", n)
	}

	// Valid delivery revokes the session.
	or := postEvent(t, srv.URL+"/internal/logout", body, app.Config.InternalAuthToken)
	if or.StatusCode != http.StatusOK {
		t.Fatalf("valid event expected 200, got %d", or.StatusCode)
	}
	_ = or.Body.Close()
	if n := activeSessions(t, app, testUserSub); n != 0 {
		t.Fatalf("session should be revoked, got %d", n)
	}

	// Duplicate eventId is acknowledged idempotently.
	dr := postEvent(t, srv.URL+"/internal/logout", body, app.Config.InternalAuthToken)
	if dr.StatusCode != http.StatusOK {
		t.Fatalf("duplicate event expected 200, got %d", dr.StatusCode)
	}
	_ = dr.Body.Close()
}

func postEvent(t *testing.T, url string, body []byte, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("build event request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Auth", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("event request: %v", err)
	}
	return resp
}

func TestAccessPolicyChangedRevokesOnlyTarget(t *testing.T) {
	app := newTestApp(t)
	srv := httptest.NewServer(newTestMux(app))
	defer srv.Close()
	client := srv.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }

	state := doLogin(t, client, srv.URL)
	cb := srv.URL + "/auth/callback?code=good&state=" + url.QueryEscape(state)
	if _, err := client.Get(cb); err != nil {
		t.Fatalf("callback: %v", err)
	}

	event := revocationEvent{
		EventID:       uuid.New(),
		EventType:     "AccessPolicyChanged",
		UserID:        uuid.MustParse(testUserSub),
		ApplicationID: ptrUUID(app.Config.AppID),
		Reason:        "policy_lost",
		OccurredAt:    time.Now().UTC(),
	}
	body, _ := json.Marshal(event)
	resp := postEvent(t, srv.URL+"/internal/logout", body, app.Config.InternalAuthToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("policy event expected 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if n := activeSessions(t, app, testUserSub); n != 0 {
		t.Fatalf("session should be revoked by policy loss, got %d", n)
	}
}

// TestSessionRevokedScopedToCentralSession verifies that a SessionRevoked
// event revokes only the local sessions bound to the named central session and
// leaves sessions from unrelated central sessions intact.
func TestSessionRevokedScopedToCentralSession(t *testing.T) {
	app := newTestApp(t)
	srv := httptest.NewServer(newTestMux(app))
	defer srv.Close()
	client := newClient(t, srv)

	state := doLogin(t, client, srv.URL)
	cb := srv.URL + "/auth/callback?code=good&state=" + url.QueryEscape(state)
	if _, err := client.Get(cb); err != nil {
		t.Fatalf("callback: %v", err)
	}
	// session A now carries CentralSessionID = testCentralSession.

	otherCentral := "33333333-3333-3333-3333-333333333333"
	sessB := &store.LocalSession{
		ID:               uuid.New(),
		SessionTokenHash: uuid.NewString(),
		ExternalUserID:   testUserSub,
		CentralSessionID: otherCentral,
		ApplicationID:    "app-a",
		Status:           "active",
		ExpiresAt:        time.Now().Add(time.Hour),
	}
	if err := app.Store.CreateSession(t.Context(), sessB); err != nil {
		t.Fatalf("create session B: %v", err)
	}
	if n := activeSessions(t, app, testUserSub); n != 2 {
		t.Fatalf("expected 2 active sessions, got %d", n)
	}

	event := revocationEvent{
		EventID:          uuid.New(),
		EventType:        "SessionRevoked",
		UserID:           uuid.MustParse(testUserSub),
		CentralSessionID: ptrUUID(testCentralSession),
		Reason:           "sso_logout",
		OccurredAt:       time.Now().UTC(),
	}
	body, _ := json.Marshal(event)
	resp := postEvent(t, srv.URL+"/internal/logout", body, app.Config.InternalAuthToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session revoked event expected 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	if n := activeSessions(t, app, testUserSub); n != 1 {
		t.Fatalf("expected 1 surviving session, got %d", n)
	}
	got, err := app.Store.FindSessionByTokenHash(t.Context(), sessB.SessionTokenHash)
	if err != nil || got == nil || !app.Store.IsSessionActive(got, time.Now()) {
		t.Fatal("unrelated central session must survive SessionRevoked")
	}
}

// TestInternalLogoutRejectsUnsupportedEvent verifies that an unknown event type
// is rejected (400) and NOT recorded, so a later retry is not silently acked.
func TestInternalLogoutRejectsUnsupportedEvent(t *testing.T) {
	app := newTestApp(t)
	srv := httptest.NewServer(newTestMux(app))
	defer srv.Close()

	event := revocationEvent{
		EventID:    uuid.New(),
		EventType:  "BogusEvent",
		UserID:     uuid.MustParse(testUserSub),
		OccurredAt: time.Now().UTC(),
	}
	body, _ := json.Marshal(event)
	resp := postEvent(t, srv.URL+"/internal/logout", body, app.Config.InternalAuthToken)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unsupported event expected 400, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	done, _ := app.Store.EventProcessed(t.Context(), event.EventID)
	if done {
		t.Fatal("unsupported event must not be recorded as processed")
	}
}

// TestInternalLogoutRejectsSessionRevokedWithoutCentralSession verifies that a
// SessionRevoked event missing centralSessionId is rejected rather than
// over-revoking every user session.
func TestInternalLogoutRejectsSessionRevokedWithoutCentralSession(t *testing.T) {
	app := newTestApp(t)
	srv := httptest.NewServer(newTestMux(app))
	defer srv.Close()
	client := newClient(t, srv)

	state := doLogin(t, client, srv.URL)
	cb := srv.URL + "/auth/callback?code=good&state=" + url.QueryEscape(state)
	if _, err := client.Get(cb); err != nil {
		t.Fatalf("callback: %v", err)
	}

	event := revocationEvent{
		EventID:    uuid.New(),
		EventType:  "SessionRevoked",
		UserID:     uuid.MustParse(testUserSub),
		Reason:     "sso_logout",
		OccurredAt: time.Now().UTC(),
	}
	body, _ := json.Marshal(event)
	resp := postEvent(t, srv.URL+"/internal/logout", body, app.Config.InternalAuthToken)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed SessionRevoked expected 400, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if n := activeSessions(t, app, testUserSub); n != 1 {
		t.Fatalf("session must survive malformed event, got %d active", n)
	}
	done, _ := app.Store.EventProcessed(t.Context(), event.EventID)
	if done {
		t.Fatal("rejected event must not be recorded as processed")
	}
}

// TestInternalLogoutRejectsWrongApplicationPolicyEvent verifies that an
// AccessPolicyChanged event for a different application is rejected and does
// not revoke this application's sessions.
func TestInternalLogoutRejectsWrongApplicationPolicyEvent(t *testing.T) {
	app := newTestApp(t)
	srv := httptest.NewServer(newTestMux(app))
	defer srv.Close()
	client := newClient(t, srv)

	state := doLogin(t, client, srv.URL)
	cb := srv.URL + "/auth/callback?code=good&state=" + url.QueryEscape(state)
	if _, err := client.Get(cb); err != nil {
		t.Fatalf("callback: %v", err)
	}

	event := revocationEvent{
		EventID:       uuid.New(),
		EventType:     "AccessPolicyChanged",
		UserID:        uuid.MustParse(testUserSub),
		ApplicationID: ptrUUID("99999999-9999-9999-9999-999999999999"),
		Reason:        "policy_lost",
		OccurredAt:    time.Now().UTC(),
	}
	body, _ := json.Marshal(event)
	resp := postEvent(t, srv.URL+"/internal/logout", body, app.Config.InternalAuthToken)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("misrouted policy event expected 400, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if n := activeSessions(t, app, testUserSub); n != 1 {
		t.Fatalf("session must survive misrouted event, got %d active", n)
	}
}

// ---- helpers ----

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	buf := make([]byte, 1<<16)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n])
}

func activeSessions(t *testing.T, app *App, externalUserID string) int {
	t.Helper()
	sessions, err := app.Store.ListActiveByUser(t.Context(), externalUserID)
	if err != nil {
		t.Fatalf("list active sessions: %v", err)
	}
	return len(sessions)
}
