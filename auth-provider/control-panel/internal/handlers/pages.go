package handlers

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"
)

// GET / — dashboard: users, groups, applications, policy overview.
func (h *PanelHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	resp, ok := h.proxyDo(w, r, http.MethodGet, "/admin/users", nil, "")
	if !ok {
		return
	}
	defer resp.Body.Close()
	users := decodeList(resp, "users")
	resp2, ok2 := h.proxyDo(w, r, http.MethodGet, "/admin/groups", nil, "")
	if !ok2 {
		return
	}
	defer resp2.Body.Close()
	groups := decodeList(resp2, "groups")
	resp3, ok3 := h.proxyDo(w, r, http.MethodGet, "/admin/applications", nil, "")
	if !ok3 {
		return
	}
	defer resp3.Body.Close()
	apps := decodeList(resp3, "applications")

	var b strings.Builder
	fmt.Fprintf(&b, "<p>Users: <b>%d</b> | Groups: <b>%d</b> | Applications: <b>%d</b></p>", len(users), len(groups), len(apps))
	b.WriteString("<h2>Users</h2><ul>")
	for _, u := range users {
		b.WriteString(fmt.Sprintf("<li>%s (%s) — %s</li>", html.EscapeString(strField(u, "name")), html.EscapeString(strField(u, "email")), html.EscapeString(strField(u, "status"))))
	}
	b.WriteString("</ul><p><a href=\"/users\">Manage users</a></p>")
	b.WriteString("<h2>Groups</h2><ul>")
	for _, g := range groups {
		b.WriteString(fmt.Sprintf("<li>%s</li>", html.EscapeString(strField(g, "name"))))
	}
	b.WriteString("</ul><p><a href=\"/groups\">Manage groups</a></p>")
	b.WriteString("<h2>Applications</h2><ul>")
	for _, a := range apps {
		b.WriteString(fmt.Sprintf("<li>%s — %s</li>", html.EscapeString(strField(a, "name")), html.EscapeString(strField(a, "status"))))
	}
	b.WriteString("</ul><p><a href=\"/applications\">Manage applications</a></p>")

	h.renderShell(w, "Control Panel — Dashboard", b.String())
}

// GET /users — list users with create/status forms.
func (h *PanelHandler) Users(w http.ResponseWriter, r *http.Request) {
	resp, ok := h.proxyDo(w, r, http.MethodGet, "/admin/users", nil, "")
	if !ok {
		return
	}
	defer resp.Body.Close()
	users := decodeList(resp, "users")

	var b strings.Builder
	b.WriteString(`<h2>Create user</h2>
<form method="post" action="/users">
<label>Name <input name="name" required></label>
<label>Email <input name="email" type="email" required></label>
<label>Password <input name="password" type="password" required></label>
<label>Status <select name="status"><option value="active">active</option><option value="inactive">inactive</option></select></label>
<button type="submit">Create</button>
</form>
<h2>Users</h2><table border="1"><tr><th>Name</th><th>Email</th><th>Status</th><th>Actions</th></tr>`)
	for _, u := range users {
		id := strField(u, "id")
		b.WriteString("<tr>")
		b.WriteString(fmt.Sprintf("<td>%s</td><td>%s</td><td>%s</td>", html.EscapeString(strField(u, "name")), html.EscapeString(strField(u, "email")), html.EscapeString(strField(u, "status"))))
		b.WriteString("<td>")
		b.WriteString(fmt.Sprintf("<form method=\"post\" action=\"/users/status\" style=\"display:inline\">"+
			"<input type=\"hidden\" name=\"id\" value=\"%s\"><input type=\"hidden\" name=\"status\" value=\"%s\">"+
			"<button type=\"submit\">%s</button></form> ",
			html.EscapeString(id),
			func() string {
				if strField(u, "status") == "active" {
					return "inactive"
				}
				return "active"
			}(),
			func() string {
				if strField(u, "status") == "active" {
					return "Deactivate"
				}
				return "Activate"
			}()))
		b.WriteString(fmt.Sprintf("<a href=\"/users/%s\">Overview</a></td>", html.EscapeString(id)))
		b.WriteString("</tr>")
	}
	b.WriteString("</table>")

	h.renderShell(w, "Control Panel — Users", b.String())
}

// GET /users/{id} — per-user overview (groups, applications, policies).
func (h *PanelHandler) UserOverview(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	resp, ok := h.proxyDo(w, r, http.MethodGet, "/admin/overview/"+id, nil, "")
	if !ok {
		return
	}
	defer resp.Body.Close()
	var data map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&data)

	var b strings.Builder
	b.WriteString("<p><a href=\"/users\">Back</a></p>")
	user, _ := data["user"].(map[string]any)
	b.WriteString(fmt.Sprintf("<h2>%s</h2><p>%s — %s</p>", html.EscapeString(strField(user, "name")), html.EscapeString(strField(user, "email")), html.EscapeString(strField(user, "status"))))

	b.WriteString("<h3>Groups</h3><ul>")
	for _, g := range listField(data, "groups") {
		b.WriteString(fmt.Sprintf("<li>%s</li>", html.EscapeString(strField(g, "name"))))
	}
	b.WriteString("</ul>")

	b.WriteString("<h3>Application policies</h3><ul>")
	for _, a := range listField(data, "applications") {
		aid := strField(a, "id")
		b.WriteString(fmt.Sprintf("<li>%s", html.EscapeString(strField(a, "name"))))
		if pol, ok := data["policies"].(map[string]any); ok {
			if items, ok := pol[aid].([]any); ok && len(items) > 0 {
				b.WriteString(" — allowed groups: ")
				for i, it := range items {
					if m, ok := it.(map[string]any); ok {
						if i > 0 {
							b.WriteString(", ")
						}
						b.WriteString(html.EscapeString(strField(m, "group_id")))
					}
				}
			}
		}
		b.WriteString("</li>")
	}
	b.WriteString("</ul>")

	h.renderShell(w, "Control Panel — User Overview", b.String())
}

// GET /groups — list groups with create/membership forms.
func (h *PanelHandler) Groups(w http.ResponseWriter, r *http.Request) {
	resp, ok := h.proxyDo(w, r, http.MethodGet, "/admin/groups", nil, "")
	if !ok {
		return
	}
	defer resp.Body.Close()
	groups := decodeList(resp, "groups")

	var b strings.Builder
	b.WriteString(`<h2>Create group</h2>
<form method="post" action="/groups">
<label>Name <input name="name" required></label>
<label>Description <input name="description"></label>
<button type="submit">Create</button>
</form>
<h2>Groups</h2><ul>`)
	for _, g := range groups {
		id := strField(g, "id")
		b.WriteString("<li>")
		b.WriteString(fmt.Sprintf("%s ", html.EscapeString(strField(g, "name"))))
		b.WriteString(fmt.Sprintf("<form method=\"post\" action=\"/groups/members\" style=\"display:inline\">"+
			"<input type=\"hidden\" name=\"id\" value=\"%s\"><input name=\"userId\" placeholder=\"user id\" required><button type=\"submit\">Add member</button></form> ",
			html.EscapeString(id)))
		b.WriteString(fmt.Sprintf("<form method=\"post\" action=\"/groups/members/delete\" style=\"display:inline\">"+
			"<input type=\"hidden\" name=\"id\" value=\"%s\"><input name=\"userId\" placeholder=\"user id\" required><button type=\"submit\">Remove member</button></form>",
			html.EscapeString(id)))
		b.WriteString("</li>")
	}
	b.WriteString("</ul>")

	h.renderShell(w, "Control Panel — Groups", b.String())
}

// GET /applications — list applications with registration forms.
func (h *PanelHandler) Applications(w http.ResponseWriter, r *http.Request) {
	resp, ok := h.proxyDo(w, r, http.MethodGet, "/admin/applications", nil, "")
	if !ok {
		return
	}
	defer resp.Body.Close()
	apps := decodeList(resp, "applications")

	var b strings.Builder
	b.WriteString(`<h2>Register application</h2>
<form method="post" action="/applications">
<label>Name <input name="name" required></label>
<label>Redirect URI <input name="redirect_uri" required></label>
<label>Launch URL <input name="launch_url"></label>
<label>Logout Notification URL <input name="logout_notification_url" required></label>
<button type="submit">Register</button>
</form>
<h2>Applications</h2><table border="1"><tr><th>Name</th><th>Client ID</th><th>Status</th><th>Actions</th></tr>`)
	for _, a := range apps {
		id := strField(a, "id")
		b.WriteString("<tr>")
		b.WriteString(fmt.Sprintf("<td>%s</td><td>%s</td><td>%s</td>", html.EscapeString(strField(a, "name")), html.EscapeString(strField(a, "client_id")), html.EscapeString(strField(a, "status"))))
		b.WriteString("<td>")
		b.WriteString(fmt.Sprintf("<form method=\"post\" action=\"/applications/redirect\" style=\"display:inline\">"+
			"<input type=\"hidden\" name=\"id\" value=\"%s\"><input name=\"redirect_uri\" placeholder=\"redirect uri\" required><button type=\"submit\">Add URI</button></form> ",
			html.EscapeString(id)))
		b.WriteString(fmt.Sprintf("<form method=\"post\" action=\"/applications/policies\" style=\"display:inline\">"+
			"<input type=\"hidden\" name=\"id\" value=\"%s\"><input name=\"group_id\" placeholder=\"group id\" required><button type=\"submit\">Allow group</button></form> ",
			html.EscapeString(id)))
		b.WriteString(fmt.Sprintf("<form method=\"post\" action=\"/applications/policies/delete\" style=\"display:inline\">"+
			"<input type=\"hidden\" name=\"id\" value=\"%s\"><input name=\"group_id\" placeholder=\"group id\" required><button type=\"submit\">Remove policy</button></form>",
			html.EscapeString(id)))
		b.WriteString("</td></tr>")
	}
	b.WriteString("</table>")

	h.renderShell(w, "Control Panel — Applications", b.String())
}

// --- JSON decoding helpers ---

func decodeList(resp *http.Response, key string) []map[string]any {
	var data map[string]any
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&data)
	if data == nil {
		return nil
	}
	out, _ := data[key].([]any)
	result := make([]map[string]any, 0, len(out))
	for _, item := range out {
		if m, ok := item.(map[string]any); ok {
			result = append(result, m)
		}
	}
	return result
}

func listField(data map[string]any, key string) []map[string]any {
	out, _ := data[key].([]any)
	result := make([]map[string]any, 0, len(out))
	for _, item := range out {
		if m, ok := item.(map[string]any); ok {
			result = append(result, m)
		}
	}
	return result
}

func strField(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
