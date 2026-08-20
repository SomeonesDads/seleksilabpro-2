package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/applications/app-b/internal/store"
)

// Home renders the APP B dashboard: user identity, local-session status,
// activity log, and processed revocation events. Without a valid local session
// it shows the login entry point.
func (a *App) Home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		a.writeError(w, r, http.StatusNotFound, "NOT_FOUND", "page not found")
		return
	}
	sess, err := a.loadSession(r)
	if err != nil {
		a.log().Error("session load failed", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "service unavailable")
		return
	}
	if sess == nil {
		renderLanding(w)
		return
	}
	active := a.Store.IsSessionActive(sess, time.Now())
	if active {
		_ = a.Store.TouchSession(r.Context(), sess.ID)
	}

	profile, err := a.Store.GetProfile(r.Context(), sess.ExternalUserID)
	if err != nil {
		a.log().Error("profile load failed", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "service unavailable")
		return
	}
	events, err := a.Store.ListProcessedEvents(r.Context(), 50)
	if err != nil {
		a.log().Error("event load failed", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "service unavailable")
		return
	}
	logs, err := a.Store.ListActivity(r.Context(), 50)
	if err != nil {
		a.log().Error("activity load failed", "err", err)
		a.writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "service unavailable")
		return
	}

	renderDashboard(w, dashboardData{
		AppName:         "APP B",
		Profile:         profile,
		Session:         sess,
		SessionActive:   active,
		ProcessedEvents: events,
		Activity:        logs,
		Now:             time.Now().UTC(),
	})
}

func encodeGroups(groups []string) string {
	if len(groups) == 0 {
		return "[]"
	}
	b, err := json.Marshal(groups)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func decodeGroups(raw string) []string {
	if raw == "" {
		return nil
	}
	var groups []string
	if err := json.Unmarshal([]byte(raw), &groups); err != nil {
		return nil
	}
	return groups
}

var _ = strings.TrimSpace
var _ = store.LocalSession{}
