package handlers

import (
	"bytes"
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/applications/app-a/internal/store"
)

type dashboardData struct {
	AppName         string
	Profile         *store.ProfileCache
	Session         *store.LocalSession
	SessionActive   bool
	ProcessedEvents []store.ProcessedEvent
	Activity        []store.ActivityLog
	Now             time.Time
}

func renderLanding(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><html><head><meta charset="utf-8"><title>App A</title></head>
<body>
<h1>APP A</h1>
<p>You are not signed in to App A.</p>
<form method="get" action="/login"><button type="submit">Sign in with Auth Provider</button></form>
</body></html>`)
}

func renderDashboard(w http.ResponseWriter, d dashboardData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var buf bytes.Buffer
	buf.WriteString(`<!doctype html><html><head><meta charset="utf-8"><title>` + html.EscapeString(d.AppName) + `</title></head><body>`)
	buf.WriteString("<h1>" + html.EscapeString(d.AppName) + "</h1>")

	buf.WriteString("<section><h2>Identity</h2>")
	if d.Profile != nil {
		buf.WriteString("<p>Hello, " + html.EscapeString(d.Profile.Name) + "</p>")
		buf.WriteString("<ul>")
		buf.WriteString("<li>Email: " + html.EscapeString(d.Profile.Email) + "</li>")
		buf.WriteString("<li>External user id: " + html.EscapeString(d.Profile.ExternalUserID) + "</li>")
		buf.WriteString("<li>Groups: " + html.EscapeString(formatGroups(d.Profile.Groups)) + "</li>")
		buf.WriteString("</ul>")
	} else {
		buf.WriteString("<p>Profile cache unavailable.</p>")
	}
	buf.WriteString("</section>")

	buf.WriteString("<section><h2>Local Session</h2>")
	if d.Session != nil && !d.SessionActive {
		buf.WriteString("<p><strong>Warning:</strong> this local session is " + html.EscapeString(d.Session.Status) + ". Please sign in again.</p>")
	}
	buf.WriteString("<ul>")
	if d.Session != nil {
		buf.WriteString("<li>Status: " + html.EscapeString(d.Session.Status) + "</li>")
		buf.WriteString("<li>Created: " + html.EscapeString(d.Session.CreatedAt.Format(time.RFC3339)) + "</li>")
		buf.WriteString("<li>Expires: " + html.EscapeString(d.Session.ExpiresAt.Format(time.RFC3339)) + "</li>")
	}
	buf.WriteString("</ul>")
	buf.WriteString(`<form method="post" action="/logout"><button type="submit">Local logout</button></form>`)
	buf.WriteString("</section>")

	buf.WriteString("<section><h2>Activity Log</h2><table border=\"1\"><tr><th>Time</th><th>Kind</th><th>Message</th></tr>")
	for _, l := range d.Activity {
		buf.WriteString("<tr><td>" + html.EscapeString(l.CreatedAt.Format(time.RFC3339)) + "</td>")
		buf.WriteString("<td>" + html.EscapeString(l.Kind) + "</td>")
		buf.WriteString("<td>" + html.EscapeString(l.Message) + "</td></tr>")
	}
	buf.WriteString("</table></section>")

	buf.WriteString("<section><h2>Processed Events</h2><table border=\"1\"><tr><th>Event ID</th><th>Type</th><th>Processed</th><th>Result</th></tr>")
	for _, e := range d.ProcessedEvents {
		buf.WriteString("<tr><td>" + html.EscapeString(e.EventID.String()) + "</td>")
		buf.WriteString("<td>" + html.EscapeString(e.EventType) + "</td>")
		buf.WriteString("<td>" + html.EscapeString(e.ProcessedAt.Format(time.RFC3339)) + "</td>")
		buf.WriteString("<td>" + html.EscapeString(e.Result) + "</td></tr>")
	}
	buf.WriteString("</table></section>")

	buf.WriteString("</body></html>")
	_, _ = w.Write(buf.Bytes())
}

func renderError(w http.ResponseWriter, status int, message, reqID string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>App A — Error</title></head>
<body><h1>APP A</h1><h2>Something went wrong</h2>
<p>%s</p>
<p>If this keeps happening, contact your administrator. Reference: %s</p>
<p><a href="/">Return to App A</a></p>
</body></html>`, html.EscapeString(message), html.EscapeString(reqID))
}

func formatGroups(raw string) string {
	groups := decodeGroups(raw)
	if len(groups) == 0 {
		return "(none)"
	}
	return strings.Join(groups, ", ")
}

var _ = http.StatusOK
