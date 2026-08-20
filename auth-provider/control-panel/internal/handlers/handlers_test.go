package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/SomeonesDads/seleksilabpro-2/shared/logging"
)

// fakeAuthProvider records every call it receives and enforces the
// sso_session cookie, proving the control panel talks to the Auth Provider
// over HTTP and never touches a database.
type fakeAuthProvider struct {
	mu           sync.Mutex
	calls        []string
	secret       string
	logoutStatus int
}

func (f *fakeAuthProvider) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		f.mu.Unlock()

		// Logout is handled before the generic auth gate so we can simulate a
		// provider rejection (e.g. 500) for the failure-path test.
		if r.URL.Path == "/logout" {
			status := f.logoutStatus
			if status == 0 {
				status = http.StatusOK
			}
			w.WriteHeader(status)
			return
		}

		if c, err := r.Cookie("sso_session"); err != nil || c.Value != "valid" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "UNAUTHORIZED", "message": "authentication required"}})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/users":
			_ = json.NewEncoder(w).Encode(map[string]any{"users": []map[string]any{{"id": "u1", "name": "Ada", "email": "ada@example.com", "status": "active"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/groups":
			_ = json.NewEncoder(w).Encode(map[string]any{"groups": []map[string]any{{"id": "g1", "name": "administrators"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/applications":
			_ = json.NewEncoder(w).Encode(map[string]any{"applications": []map[string]any{{"id": "a1", "name": "App A", "client_id": "cid", "status": "active"}}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/admin/overview/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user":         map[string]any{"name": "Ada", "email": "ada@example.com", "status": "active"},
				"groups":       []map[string]any{{"name": "administrators"}},
				"applications": []map[string]any{{"id": "a1", "name": "App A"}},
				"policies":     map[string]any{"a1": []map[string]any{}},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/admin/users":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "u2", "name": "New", "email": "new@example.com", "status": "active"})
		case r.URL.Path == "/admin/users/u1/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "u1", "status": "inactive"})
		case r.URL.Path == "/admin/groups" && r.Method == http.MethodPost:
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "g2", "name": "eng"})
		case strings.HasSuffix(r.URL.Path, "/members") && r.Method == http.MethodPost:
			_ = json.NewEncoder(w).Encode(map[string]any{"group_id": "g1", "user_id": "u1"})
		case strings.Contains(r.URL.Path, "/members/") && r.Method == http.MethodDelete:
			_ = json.NewEncoder(w).Encode(map[string]any{"removed": true})
		case r.URL.Path == "/admin/applications" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "a2", "name": "App B", "client_id": "cid2", "client_secret": f.secret, "redirect_uri": "https://app-b/cb"})
		case strings.HasSuffix(r.URL.Path, "/redirect-uris") && r.Method == http.MethodPost:
			_ = json.NewEncoder(w).Encode(map[string]any{"application_id": "a1", "redirect_uri": "https://app/cb"})
		case strings.HasSuffix(r.URL.Path, "/policies") && r.Method == http.MethodPost:
			_ = json.NewEncoder(w).Encode(map[string]any{"application_id": "a1", "group_id": "g1", "effect": "allow"})
		case strings.HasSuffix(r.URL.Path, "/policies") && r.Method == http.MethodDelete:
			_ = json.NewEncoder(w).Encode(map[string]any{"deleted": true})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	return mux
}

func newTestPanel(t *testing.T, fake *fakeAuthProvider) (*httptest.Server, *fakeAuthProvider) {
	t.Helper()
	ts := httptest.NewServer(fake.handler())
	t.Cleanup(ts.Close)
	return ts, fake
}

func testMux(fakeURL string) *http.ServeMux {
	h := NewPanelHandler(fakeURL, "sso_session", logging.NewLogger("test"))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", h.LoginPage)
	mux.HandleFunc("POST /login", h.Login)
	mux.HandleFunc("POST /login/mfa", h.LoginMFA)
	mux.HandleFunc("GET /logout", h.Logout)
	mux.HandleFunc("POST /logout", h.Logout)
	mux.HandleFunc("GET /", h.Dashboard)
	mux.HandleFunc("GET /users", h.Users)
	mux.HandleFunc("GET /users/{id}", h.UserOverview)
	mux.HandleFunc("GET /groups", h.Groups)
	mux.HandleFunc("GET /applications", h.Applications)
	mux.HandleFunc("POST /users", h.CreateUser)
	mux.HandleFunc("POST /users/status", h.SetUserStatus)
	mux.HandleFunc("POST /groups", h.CreateGroup)
	mux.HandleFunc("POST /groups/members", h.AddGroupMember)
	mux.HandleFunc("POST /groups/members/delete", h.RemoveGroupMember)
	mux.HandleFunc("POST /applications", h.CreateApplication)
	mux.HandleFunc("POST /applications/redirect", h.AddRedirectURI)
	mux.HandleFunc("POST /applications/policies", h.AddApplicationPolicy)
	mux.HandleFunc("POST /applications/policies/delete", h.DeleteApplicationPolicy)
	return mux
}

func doReq(t *testing.T, mux *http.ServeMux, method, target, session, form string) *http.Response {
	t.Helper()
	var body io.Reader
	if form != "" {
		body = strings.NewReader(form)
	}
	req := httptest.NewRequest(method, target, body)
	if form != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if session != "" {
		req.AddCookie(&http.Cookie{Name: "sso_session", Value: session})
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Result()
}

func TestDashboardWithoutSessionIsRejected(t *testing.T) {
	ts, fake := newTestPanel(t, &fakeAuthProvider{})
	mux := testMux(ts.URL)
	resp := doReq(t, mux, http.MethodGet, "/", "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without session, got %d", resp.StatusCode)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("expected no Auth Provider calls without a session, got %v", fake.calls)
	}
}

func TestMutationWithoutSessionIsRejected(t *testing.T) {
	ts, fake := newTestPanel(t, &fakeAuthProvider{})
	mux := testMux(ts.URL)
	resp := doReq(t, mux, http.MethodPost, "/users", "", "name=Ada&email=a@b.c&password=x")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for mutation without session, got %d", resp.StatusCode)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("expected no Auth Provider calls, got %v", fake.calls)
	}
}

func TestDashboardRendersAndCallsProvider(t *testing.T) {
	ts, fake := newTestPanel(t, &fakeAuthProvider{})
	mux := testMux(ts.URL)
	resp := doReq(t, mux, http.MethodGet, "/", "valid", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Dashboard") {
		t.Fatalf("dashboard body missing title: %s", body)
	}
	want := []string{"GET /admin/users", "GET /admin/groups", "GET /admin/applications"}
	for _, w := range want {
		if !containsCall(fake.calls, w) {
			t.Fatalf("expected Auth Provider call %q, got %v", w, fake.calls)
		}
	}
}

func TestUserCRUDAndStatus(t *testing.T) {
	ts, fake := newTestPanel(t, &fakeAuthProvider{})
	mux := testMux(ts.URL)
	if resp := doReq(t, mux, http.MethodPost, "/users", "valid", "name=New&email=new@example.com&password=secret"); resp.StatusCode != http.StatusOK {
		t.Fatalf("create user: expected 200, got %d", resp.StatusCode)
	}
	if resp := doReq(t, mux, http.MethodPost, "/users/status", "valid", "id=u1&status=inactive"); resp.StatusCode != http.StatusOK {
		t.Fatalf("set status: expected 200, got %d", resp.StatusCode)
	}
	if resp := doReq(t, mux, http.MethodGet, "/users", "valid", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("list users: expected 200, got %d", resp.StatusCode)
	}
	if !containsCall(fake.calls, "POST /admin/users") || !containsCall(fake.calls, "PATCH /admin/users/u1/status") {
		t.Fatalf("expected user admin calls, got %v", fake.calls)
	}
}

func TestGroupMembership(t *testing.T) {
	ts, fake := newTestPanel(t, &fakeAuthProvider{})
	mux := testMux(ts.URL)
	if resp := doReq(t, mux, http.MethodPost, "/groups", "valid", "name=eng"); resp.StatusCode != http.StatusOK {
		t.Fatalf("create group: expected 200, got %d", resp.StatusCode)
	}
	if resp := doReq(t, mux, http.MethodPost, "/groups/members", "valid", "id=g1&userId=u1"); resp.StatusCode != http.StatusOK {
		t.Fatalf("add member: expected 200, got %d", resp.StatusCode)
	}
	if resp := doReq(t, mux, http.MethodPost, "/groups/members/delete", "valid", "id=g1&userId=u1"); resp.StatusCode != http.StatusOK {
		t.Fatalf("remove member: expected 200, got %d", resp.StatusCode)
	}
	if !containsCall(fake.calls, "POST /admin/groups") ||
		!containsCall(fake.calls, "POST /admin/groups/g1/members") ||
		!containsCall(fake.calls, "DELETE /admin/groups/g1/members/u1") {
		t.Fatalf("expected group admin calls, got %v", fake.calls)
	}
}

func TestApplicationRegistrationShowsSecretOnce(t *testing.T) {
	ts, _ := newTestPanel(t, &fakeAuthProvider{secret: "TOPSECRET"})
	mux := testMux(ts.URL)
	resp := doReq(t, mux, http.MethodPost, "/applications", "valid", "name=App+B&redirect_uri=https://app-b/cb&logout_notification_url=https://app-b/logout")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register app: expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "TOPSECRET") {
		t.Fatalf("expected one-time secret in provisioning response")
	}
	// The secret must not appear when listing applications later.
	listResp := doReq(t, mux, http.MethodGet, "/applications", "valid", "")
	listBody, _ := io.ReadAll(listResp.Body)
	if strings.Contains(string(listBody), "TOPSECRET") {
		t.Fatalf("client secret leaked into the applications list page")
	}
}

func TestApplicationRedirectAndPolicy(t *testing.T) {
	ts, fake := newTestPanel(t, &fakeAuthProvider{})
	mux := testMux(ts.URL)
	if resp := doReq(t, mux, http.MethodPost, "/applications/redirect", "valid", "id=a1&redirect_uri=https://app/cb"); resp.StatusCode != http.StatusOK {
		t.Fatalf("add redirect uri: expected 200, got %d", resp.StatusCode)
	}
	if resp := doReq(t, mux, http.MethodPost, "/applications/policies", "valid", "id=a1&group_id=g1"); resp.StatusCode != http.StatusOK {
		t.Fatalf("add policy: expected 200, got %d", resp.StatusCode)
	}
	if resp := doReq(t, mux, http.MethodPost, "/applications/policies/delete", "valid", "id=a1&group_id=g1"); resp.StatusCode != http.StatusOK {
		t.Fatalf("delete policy: expected 200, got %d", resp.StatusCode)
	}
	if !containsCall(fake.calls, "POST /admin/applications/a1/redirect-uris") ||
		!containsCall(fake.calls, "POST /admin/applications/a1/policies") ||
		!containsCall(fake.calls, "DELETE /admin/applications/a1/policies") {
		t.Fatalf("expected application admin calls, got %v", fake.calls)
	}
}

func TestLogoutRevokesCentralSession(t *testing.T) {
	ts, fake := newTestPanel(t, &fakeAuthProvider{})
	mux := testMux(ts.URL)
	resp := doReq(t, mux, http.MethodGet, "/logout", "valid", "")
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected redirect after logout, got %d", resp.StatusCode)
	}
	// The panel must have asked the Auth Provider to end the central session.
	if !containsCall(fake.calls, "POST /logout") {
		t.Fatalf("expected Auth Provider /logout call, got %v", fake.calls)
	}
	// The local cookie must be cleared.
	var cleared bool
	for _, c := range resp.Cookies() {
		if c.Name == "sso_session" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("local admin session cookie was not cleared")
	}
}

func TestLogoutProviderFailureIsSurfaced(t *testing.T) {
	ts, fake := newTestPanel(t, &fakeAuthProvider{logoutStatus: http.StatusInternalServerError})
	mux := testMux(ts.URL)
	resp := doReq(t, mux, http.MethodGet, "/logout", "valid", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected error page (200) on logout failure, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Sign out incomplete") {
		t.Fatalf("expected logout-failure page, got %s", body)
	}
	if !containsCall(fake.calls, "POST /logout") {
		t.Fatalf("expected Auth Provider /logout call, got %v", fake.calls)
	}
	// The local cookie must NOT be cleared while the central session is still
	// active, so the user can retry.
	for _, c := range resp.Cookies() {
		if c.Name == "sso_session" && c.MaxAge < 0 {
			t.Fatalf("local session cookie was cleared despite logout failure")
		}
	}
}

func TestLogoutWithoutLocalCookieIsIdempotent(t *testing.T) {
	ts, fake := newTestPanel(t, &fakeAuthProvider{})
	mux := testMux(ts.URL)
	// No session cookie: logout must succeed (redirect to /login) without
	// contacting the Auth Provider or rendering a failure page.
	resp := doReq(t, mux, http.MethodGet, "/logout", "", "")
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected redirect on idempotent logout, got %d", resp.StatusCode)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("expected no Auth Provider calls without a local session, got %v", fake.calls)
	}
}

func TestSafeErrorMessageHidesInternals(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("panic: driver: broken connection at pgx.(*Conn)"))
	}))
	t.Cleanup(ts.Close)
	mux := testMux(ts.URL)
	resp := doReq(t, mux, http.MethodGet, "/users", "valid", "")
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "pgx") || strings.Contains(string(body), "panic") {
		t.Fatalf("internal DB detail leaked to admin UI: %s", body)
	}
}

func containsCall(calls []string, want string) bool {
	for _, c := range calls {
		if c == want {
			return true
		}
	}
	return false
}
