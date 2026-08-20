package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/applications/app-a/internal/auth"
	"github.com/SomeonesDads/seleksilabpro-2/applications/app-a/internal/config"
	"github.com/SomeonesDads/seleksilabpro-2/applications/app-a/internal/store"
	"github.com/SomeonesDads/seleksilabpro-2/shared/idgen"
	"github.com/google/uuid"
)

const cookieName = "appa_session"

// stateStore keeps the PKCE verifier bound to the OAuth state value between the
// redirect and the callback. Entries expire; a consumed state is deleted so a
// replayed state cannot create a session.
type stateStore struct {
	mu      sync.Mutex
	entries map[string]stateEntry
	ttl     time.Duration
}

type stateEntry struct {
	verifier  string
	expiresAt time.Time
}

func newStateStore(ttl time.Duration) *stateStore {
	return &stateStore{entries: make(map[string]stateEntry), ttl: ttl}
}

func (s *stateStore) put(state, verifier string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[state] = stateEntry{verifier: verifier, expiresAt: time.Now().Add(s.ttl)}
}

// consume returns the verifier for a state and deletes it. A missing or expired
// state yields ("", false).
func (s *stateStore) consume(state string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[state]
	if !ok {
		return "", false
	}
	delete(s.entries, state)
	if time.Now().After(entry.expiresAt) {
		return "", false
	}
	return entry.verifier, true
}

// App wires the HTTP handlers and their dependencies.
type App struct {
	Config   config.Config
	Store    *store.Store
	Provider auth.Provider
	States   *stateStore
	Logger   *slog.Logger
	CookieSecure bool
}

func NewApp(cfg config.Config, st *store.Store, provider auth.Provider) *App {
	secure := cfg.CookieSecure
	return &App{
		Config:      cfg,
		Store:       st,
		Provider:    provider,
		States:      newStateStore(10 * time.Minute),
		Logger:      slog.Default(),
		CookieSecure: secure,
	}
}

func (a *App) log() *slog.Logger {
	if a.Logger != nil {
		return a.Logger
	}
	return slog.Default()
}

// correlationID returns a stable id for the request, creating one if absent.
func correlationID(r *http.Request) string {
	if v := r.Header.Get("X-Correlation-ID"); v != "" {
		return v
	}
	return uuid.NewString()
}

// loadSession resolves the local session bound to the cookie, regardless of
// its active status, or nil when no session exists. Callers decide whether an
// inactive (expired/revoked) session still authorizes an action.
func (a *App) loadSession(r *http.Request) (*store.LocalSession, error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil || cookie.Value == "" {
		return nil, nil
	}
	hash := idgen.HashToken(cookie.Value)
	sess, err := a.Store.FindSessionByTokenHash(r.Context(), hash)
	if err != nil {
		return nil, err
	}
	if sess == nil {
		return nil, nil
	}
	return sess, nil
}

func setSessionCookie(w http.ResponseWriter, raw string, ttl time.Duration, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    raw,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// pkceChallenge derives the S256 challenge for a verifier.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// writeError renders the standard safe error envelope. UI callers receive HTML;
// API callers receive JSON. No secrets, hashes, or stack traces are exposed.
func (a *App) writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	reqID := correlationID(r)
	w.Header().Set("X-Request-ID", reqID)
	if acceptsHTML(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		renderError(w, status, message, reqID)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":      code,
			"message":   message,
			"requestId": reqID,
		},
	})
}

func acceptsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}
