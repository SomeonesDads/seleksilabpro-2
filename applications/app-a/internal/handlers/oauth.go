package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/applications/app-a/internal/store"
	"github.com/SomeonesDads/seleksilabpro-2/shared/idgen"
	"github.com/google/uuid"
)

// Login starts the OAuth authorization-code + PKCE flow. It stores the PKCE
// verifier server-side bound to a one-time state, then redirects the browser
// to the Auth Provider's /authorize endpoint.
func (a *App) Login(w http.ResponseWriter, r *http.Request) {
	state, err := idgen.RandomToken(24)
	if err != nil {
		a.log().Error("state generation failed", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "login unavailable")
		return
	}
	verifier, err := idgen.RandomToken(48)
	if err != nil {
		a.log().Error("verifier generation failed", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "login unavailable")
		return
	}
	a.States.put(state, verifier)
	reqID := correlationID(r)
	_ = a.Store.AddActivity(r.Context(), "login_redirect", "Redirecting browser to Auth Provider /authorize", reqID, nil)

	http.Redirect(w, r, a.Provider.AuthorizeURL(state, pkceChallenge(verifier), a.Config.RedirectURI), http.StatusFound)
}

// Callback handles the Auth Provider redirect back with ?code&state. It
// validates the state, exchanges the code server-to-server, fetches the user
// profile, and creates an independent local session.
func (a *App) Callback(w http.ResponseWriter, r *http.Request) {
	reqID := correlationID(r)
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		_ = a.Store.AddActivity(r.Context(), "callback_error", "Callback missing code or state", reqID, nil)
		a.writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "authorization response invalid")
		return
	}
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		_ = a.Store.AddActivity(r.Context(), "callback_error", "Auth Provider denied authorization: "+errParam, reqID, nil)
		a.writeError(w, r, http.StatusBadRequest, "ACCESS_DENIED", "authorization was denied")
		return
	}

	verifier, ok := a.States.consume(state)
	if !ok {
		_ = a.Store.AddActivity(r.Context(), "callback_error", "State validation failed (missing, expired, or replayed)", reqID, nil)
		a.writeError(w, r, http.StatusBadRequest, "INVALID_STATE", "login state is invalid or already used")
		return
	}

	accessToken, err := a.Provider.ExchangeCode(r.Context(), code, a.Config.RedirectURI, verifier)
	if err != nil {
		a.log().Error("code exchange failed", "err", err)
		_ = a.Store.AddActivity(r.Context(), "callback_error", "Token exchange failed", reqID, nil)
		a.writeError(w, r, http.StatusBadRequest, "INVALID_GRANT", "could not complete sign in")
		return
	}

	profile, err := a.Provider.FetchProfile(r.Context(), accessToken)
	if err != nil {
		a.log().Error("userinfo fetch failed", "err", err)
		_ = a.Store.AddActivity(r.Context(), "callback_error", "Profile fetch failed", reqID, nil)
		a.writeError(w, r, http.StatusBadRequest, "PROFILE_UNAVAILABLE", "could not load profile")
		return
	}

	if err := a.Store.UpsertProfile(r.Context(), &store.ProfileCache{
		ExternalUserID: profile.Sub,
		Name:           profile.Name,
		Email:          profile.Email,
		Groups:         encodeGroups(profile.Groups),
	}); err != nil {
		a.log().Error("profile cache failed", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "could not save profile")
		return
	}

	rawToken, err := idgen.RandomToken(32)
	if err != nil {
		a.log().Error("session token generation failed", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "could not start session")
		return
	}
	sess := &store.LocalSession{
		ID:               uuid.New(),
		SessionTokenHash: idgen.HashToken(rawToken),
		ExternalUserID:   profile.Sub,
		CentralSessionID: profile.CentralSessionID,
		ApplicationID:    a.Config.AppID,
		Status:           "active",
		ExpiresAt:        time.Now().Add(a.Config.SessionTTL),
	}
	if err := a.Store.CreateSession(r.Context(), sess); err != nil {
		a.log().Error("session creation failed", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "could not start session")
		return
	}

	setSessionCookie(w, rawToken, a.Config.SessionTTL, a.CookieSecure)
	_ = a.Store.AddActivity(r.Context(), "session_created", "Local session created for "+profile.Email, reqID, &sess.ID)
	_ = a.Store.AddActivity(r.Context(), "userinfo_fetched", "Profile received for "+profile.Email, reqID, &sess.ID)

	http.Redirect(w, r, "/", http.StatusFound)
}

// Logout performs a LOCAL logout only: it revokes the App A local session bound
// to the browser cookie. It never touches the central session or other apps.
func (a *App) Logout(w http.ResponseWriter, r *http.Request) {
	reqID := correlationID(r)
	sess, err := a.loadSession(r)
	if err != nil {
		a.log().Error("session load failed", "err", err)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	clearSessionCookie(w)
	if sess != nil {
		if err := a.Store.RevokeSession(r.Context(), sess.ID, "local_logout", time.Now().UTC()); err != nil {
			a.log().Error("local logout failed", "err", err)
		}
		_ = a.Store.AddActivity(r.Context(), "local_logout", "Local session ended", reqID, &sess.ID)
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

var errNoSession = errors.New("no active session")
