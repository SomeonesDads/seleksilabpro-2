package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/shared/logging"
)

// GET /login — render the control-panel sign-in form.
func (h *PanelHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.sessionValue(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`<!doctype html><html><body><h1>Control Panel sign in</h1>
<form method="post" action="/login">
<label>Email <input name="email" type="email" required></label>
<label>Password <input name="password" type="password" required></label>
<button type="submit">Sign in</button>
</form></body></html>`))
}

// POST /login — authenticate against the Auth Provider and forward the
// resulting central-session cookie to the administrator's browser.
func (h *PanelHandler) Login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderError(w, "Invalid form submission.")
		return
	}
	email := strings.TrimSpace(r.PostForm.Get("email"))
	password := r.PostForm.Get("password")
	if email == "" || password == "" {
		h.renderError(w, "Email and password are required.")
		return
	}
	payload, _ := json.Marshal(map[string]any{"email": email, "password": password})
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, strings.TrimRight(h.AuthServerURL, "/")+"/login", strings.NewReader(string(payload)))
	if err != nil {
		h.renderError(w, "The administration service is unreachable.")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if rid := requestID(r); rid != "" {
		req.Header.Set("X-Request-Id", rid)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		h.Logger.Error("login proxy failed", "err", err)
		h.renderError(w, "The administration service is unreachable.")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var env struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&env)
		msg := env.Error.Message
		if msg == "" {
			msg = "Sign in failed. Check your credentials."
		}
		h.renderError(w, msg)
		return
	}

	var result struct {
		MFARequired bool `json:"mfa_required"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)

	// Forward whichever session cookie the Auth Provider issued, preserving the
	// server-issued Secure flag and expiry so the central session is never sent
	// over plain HTTP.
	forwarded := false
	for _, c := range resp.Cookies() {
		if c.Name == h.SessionCookieName || c.Name == "mfa_pending" {
			http.SetCookie(w, &http.Cookie{
				Name:     c.Name,
				Value:    c.Value,
				Path:     c.Path,
				Domain:   c.Domain,
				Secure:   c.Secure,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				Expires:  c.Expires,
				MaxAge:   int(c.MaxAge),
			})
			forwarded = true
		}
	}

	if result.MFARequired {
		h.renderMFAForm(w)
		return
	}
	if !forwarded {
		h.renderError(w, "Sign in failed. No session was issued.")
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// POST /login/mfa — complete an MFA challenge against the Auth Provider.
func (h *PanelHandler) LoginMFA(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderError(w, "Invalid form submission.")
		return
	}
	code := strings.TrimSpace(r.PostForm.Get("code"))
	if code == "" {
		h.renderError(w, "An MFA code is required.")
		return
	}
	payload, _ := json.Marshal(map[string]any{"code": code})
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, strings.TrimRight(h.AuthServerURL, "/")+"/login/mfa", strings.NewReader(string(payload)))
	if err != nil {
		h.renderError(w, "The administration service is unreachable.")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if c, err := r.Cookie("mfa_pending"); err == nil {
		req.Header.Set("Cookie", "mfa_pending="+c.Value)
	}
	if rid := requestID(r); rid != "" {
		req.Header.Set("X-Request-Id", rid)
	}
	resp, err := h.Client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		h.renderError(w, "MFA verification failed. Try signing in again.")
		if resp != nil {
			resp.Body.Close()
		}
		return
	}
	defer resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == h.SessionCookieName {
			http.SetCookie(w, &http.Cookie{Name: c.Name, Value: c.Value, Path: c.Path, Domain: c.Domain, Secure: c.Secure, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: c.Expires, MaxAge: int(c.MaxAge)})
		}
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// GET /logout and POST /logout — revoke the central session at the Auth
// Provider (so the SSO session is terminated everywhere). The local admin
// session cookie is only cleared after the Auth Provider confirms the revocation.
// If the provider rejects or is unreachable, the failure is surfaced with a
// retry path rather than reporting a successful logout while the central
// session stays active.
func (h *PanelHandler) Logout(w http.ResponseWriter, r *http.Request) {
	v, ok := h.sessionValue(r)
	if !ok {
		// No local session: logout is already satisfied. Idempotent success.
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	revoked := false
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, strings.TrimRight(h.AuthServerURL, "/")+"/logout", nil)
	if err == nil {
		req.Header.Set("Cookie", h.SessionCookieName+"="+v)
		if rid := requestID(r); rid != "" {
			req.Header.Set("X-Request-Id", rid)
		}
		resp, derr := h.Client.Do(req)
		if derr != nil {
			h.Logger.Error("auth provider logout failed", "err", derr)
		} else {
			defer resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				revoked = true
			} else {
				h.Logger.Error("auth provider logout rejected", "status", resp.StatusCode)
			}
		}
	}
	if !revoked {
		// Central session may still be active: do not claim success. Keep the
		// local cookie so the user can retry the revocation.
		h.renderLogoutFailure(w)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     h.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *PanelHandler) renderMFAForm(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`<!doctype html><html><body><h1>Multi-factor authentication</h1>
<form method="post" action="/login/mfa">
<label>Code <input name="code" required></label>
<button type="submit">Verify</button>
</form></body></html>`))
}

func (h *PanelHandler) renderLogoutFailure(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`<!doctype html><html><body><h1>Sign out incomplete</h1>
<p>The authentication server did not confirm the sign-out. Your session may still be active on other applications.</p>
<form method="post" action="/logout"><button type="submit">Try again</button></form>
<p><a href="/">Return to the dashboard</a></p>
</body></html>`))
}

func requestID(r *http.Request) string {
	return logging.RequestID(r.Context())
}
