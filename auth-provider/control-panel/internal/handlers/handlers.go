// The Control Panel is deliberately "dumb": it renders HTML and forwards
// admin actions to the Auth Provider Server's /admin/* API rather than
// touching the primary database itself. This keeps the DB credential
// surface small (only the server needs write access) and matches the
// component boundary in the spec's architecture diagram (Admin Console ->
// Auth Provider Server).
//
// The control panel never opens a database connection. It only issues
// HTTP requests to the Auth Provider and forwards the administrator's
// central-session cookie (the agreed admin-session mechanism) on every
// admin call.
package handlers

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/shared/logging"
)

const defaultSessionCookie = "sso_session"

type PanelHandler struct {
	AuthServerURL    string
	Client           *http.Client
	SessionCookieName string
	Logger           *slog.Logger
}

func NewPanelHandler(authServerURL, sessionCookieName string, logger *slog.Logger) *PanelHandler {
	if sessionCookieName == "" {
		sessionCookieName = defaultSessionCookie
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &PanelHandler{
		AuthServerURL:     authServerURL,
		Client:            &http.Client{Timeout: 15 * time.Second},
		SessionCookieName: sessionCookieName,
		Logger:            logger,
	}
}

// sessionValue returns the forwarded admin session cookie value, if any.
func (h *PanelHandler) sessionValue(r *http.Request) (string, bool) {
	c, err := r.Cookie(h.SessionCookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}

// adminRequest performs an HTTP call to the Auth Provider, forwarding the
// administrator's session cookie and correlation id. It never touches a
// database.
func (h *PanelHandler) adminRequest(r *http.Request, method, path string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(r.Context(), method, strings.TrimRight(h.AuthServerURL, "/")+path, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if v, ok := h.sessionValue(r); ok {
		req.Header.Set("Cookie", h.SessionCookieName+"="+v)
	}
	if rid := logging.RequestID(r.Context()); rid != "" {
		req.Header.Set("X-Request-Id", rid)
	}
	return h.Client.Do(req)
}

// formJSON builds a JSON body from selected form fields.
func formJSON(form url.Values, fields ...string) ([]byte, error) {
	m := make(map[string]any, len(fields))
	for _, f := range fields {
		if v := strings.TrimSpace(form.Get(f)); v != "" {
			m[f] = v
		}
	}
	return json.Marshal(m)
}

// safeErrorMessage extracts a user-safe message from a server error
// response, hiding status codes, hashes, stack traces, and request ids.
func safeErrorMessage(resp *http.Response) string {
	if resp == nil {
		return "The administration service is unavailable."
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return "Your session is invalid or has expired. Please sign in again."
	case resp.StatusCode >= 500:
		return "The administration service is temporarily unavailable. Try again later."
	}
	var env struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16)); err == nil {
		_ = json.Unmarshal(b, &env)
	}
	if msg := strings.TrimSpace(env.Error.Message); msg != "" {
		return msg
	}
	return "The request could not be completed."
}

// requireAuth ensures an admin session cookie is present. Returns false and
// renders a sign-in prompt if not.
func (h *PanelHandler) requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if _, ok := h.sessionValue(r); !ok {
		h.renderSignInRequired(w)
		return false
	}
	return true
}

// proxyDo performs an admin request and handles auth/error outcomes. If the
// call is unauthorized it renders the sign-in prompt; on other errors it
// renders a safe error page. ok is false when the caller should stop.
func (h *PanelHandler) proxyDo(w http.ResponseWriter, r *http.Request, method, path string, body io.Reader, contentType string) (*http.Response, bool) {
	if !h.requireAuth(w, r) {
		return nil, false
	}
	resp, err := h.adminRequest(r, method, path, body, contentType)
	if err != nil {
		h.Logger.Error("admin request failed", slog.Any("err", err), slog.String("path", path))
		h.renderError(w, "The administration service is unreachable.")
		return nil, false
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		h.renderSignInRequired(w)
		return nil, false
	}
	if resp.StatusCode >= 400 {
		h.renderError(w, safeErrorMessage(resp))
		return nil, false
	}
	return resp, true
}

func (h *PanelHandler) renderSignInRequired(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprint(w, `<!doctype html><html><body><h1>Sign in required</h1>
<p>Your administrator session is missing or expired.</p>
<p><a href="/login">Sign in to the control panel</a></p>
</body></html>`)
}

func (h *PanelHandler) renderError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<!doctype html><html><body><h1>Could not complete action</h1>
<p>%s</p>
<p><a href="/">Back to dashboard</a></p>
</body></html>`, html.EscapeString(message))
}

func (h *PanelHandler) renderMessage(w http.ResponseWriter, title, message, back string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><body><h1>%s</h1>
<p>%s</p>
<p><a href="%s">Continue</a></p>
</body></html>`, html.EscapeString(title), html.EscapeString(message), html.EscapeString(back))
}

func (h *PanelHandler) renderShell(w http.ResponseWriter, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><head><title>%s</title></head><body>
<h1>%s</h1>
<nav><a href="/">Dashboard</a> | <a href="/users">Users</a> | <a href="/groups">Groups</a> | <a href="/applications">Applications</a> | <a href="/logout">Sign out</a></nav>
<hr>
%s
</body></html>`, html.EscapeString(title), html.EscapeString(title), body)
}
