package handlers

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// POST /users — create a user.
func (h *PanelHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderError(w, "Invalid form submission.")
		return
	}
	body, err := formJSON(r.PostForm, "name", "email", "password", "status")
	if err != nil {
		h.renderError(w, "Invalid form submission.")
		return
	}
	resp, ok := h.proxyDo(w, r, http.MethodPost, "/admin/users", strings.NewReader(string(body)), "application/json")
	if !ok {
		return
	}
	resp.Body.Close()
	h.renderMessage(w, "User created", "The user was created successfully.", "/users")
}

// POST /users/status — activate or deactivate a user.
func (h *PanelHandler) SetUserStatus(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderError(w, "Invalid form submission.")
		return
	}
	id := strings.TrimSpace(r.PostForm.Get("id"))
	status := strings.TrimSpace(r.PostForm.Get("status"))
	if id == "" || (status != "active" && status != "inactive") {
		h.renderError(w, "A valid user id and status are required.")
		return
	}
	body, _ := formJSON(r.PostForm, "status")
	resp, ok := h.proxyDo(w, r, http.MethodPatch, "/admin/users/"+id+"/status", strings.NewReader(string(body)), "application/json")
	if !ok {
		return
	}
	resp.Body.Close()
	h.renderMessage(w, "User updated", "The user status was changed.", "/users")
}

// POST /groups — create a group.
func (h *PanelHandler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderError(w, "Invalid form submission.")
		return
	}
	body, err := formJSON(r.PostForm, "name", "description")
	if err != nil {
		h.renderError(w, "Invalid form submission.")
		return
	}
	resp, ok := h.proxyDo(w, r, http.MethodPost, "/admin/groups", strings.NewReader(string(body)), "application/json")
	if !ok {
		return
	}
	resp.Body.Close()
	h.renderMessage(w, "Group created", "The group was created successfully.", "/groups")
}

// POST /groups/members — add a user to a group.
func (h *PanelHandler) AddGroupMember(w http.ResponseWriter, r *http.Request) {
	id, userID, ok := h.parseGroupMemberForm(w, r)
	if !ok {
		return
	}
	resp, ok := h.proxyDo(w, r, http.MethodPost, "/admin/groups/"+id+"/members", strings.NewReader(mustJSON(map[string]any{"userId": userID})), "application/json")
	if !ok {
		return
	}
	resp.Body.Close()
	h.renderMessage(w, "Member added", "The user was added to the group.", "/groups")
}

// POST /groups/members/delete — remove a user from a group.
func (h *PanelHandler) RemoveGroupMember(w http.ResponseWriter, r *http.Request) {
	id, userID, ok := h.parseGroupMemberForm(w, r)
	if !ok {
		return
	}
	resp, ok := h.proxyDo(w, r, http.MethodDelete, "/admin/groups/"+id+"/members/"+userID, nil, "")
	if !ok {
		return
	}
	resp.Body.Close()
	h.renderMessage(w, "Member removed", "The user was removed from the group.", "/groups")
}

// POST /applications — register an application. The client secret is shown
// only in this provisioning response and is never stored or logged.
func (h *PanelHandler) CreateApplication(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderError(w, "Invalid form submission.")
		return
	}
	body, err := formJSON(r.PostForm, "name", "redirect_uri", "launch_url", "logout_notification_url")
	if err != nil {
		h.renderError(w, "Invalid form submission.")
		return
	}
	resp, ok := h.proxyDo(w, r, http.MethodPost, "/admin/applications", strings.NewReader(string(body)), "application/json")
	if !ok {
		return
	}
	defer resp.Body.Close()
	var data map[string]any
	_ = decodeJSON(resp.Body, &data)
	secret, _ := data["client_secret"].(string)

	var b strings.Builder
	b.WriteString("<p>The application was registered.</p>")
	if secret != "" {
		b.WriteString(fmt.Sprintf("<p><b>Client secret (shown once):</b> <code>%s</code></p>", html.EscapeString(secret)))
		b.WriteString("<p>Copy this secret now. It will not be shown again.</p>")
	}
	b.WriteString("<p><a href=\"/applications\">Continue</a></p>")
	h.renderShell(w, "Application registered", b.String())
}

// POST /applications/redirect — add a redirect URI to an application.
func (h *PanelHandler) AddRedirectURI(w http.ResponseWriter, r *http.Request) {
	id, uri, ok := h.parseApplicationChildForm(w, r, "redirect_uri")
	if !ok {
		return
	}
	resp, ok := h.proxyDo(w, r, http.MethodPost, "/admin/applications/"+id+"/redirect-uris", strings.NewReader(mustJSON(map[string]any{"redirect_uri": uri})), "application/json")
	if !ok {
		return
	}
	resp.Body.Close()
	h.renderMessage(w, "Redirect URI added", "The redirect URI was registered.", "/applications")
}

// POST /applications/policies — assign a group allow-policy.
func (h *PanelHandler) AddApplicationPolicy(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderError(w, "Invalid form submission.")
		return
	}
	id := strings.TrimSpace(r.PostForm.Get("id"))
	groupID := strings.TrimSpace(r.PostForm.Get("group_id"))
	if id == "" || groupID == "" {
		h.renderError(w, "An application id and group id are required.")
		return
	}
	payload := mustJSON(map[string]any{"group_id": groupID, "effect": "allow"})
	resp, ok := h.proxyDo(w, r, http.MethodPost, "/admin/applications/"+id+"/policies", strings.NewReader(payload), "application/json")
	if !ok {
		return
	}
	resp.Body.Close()
	h.renderMessage(w, "Policy assigned", "The group allow-policy was assigned.", "/applications")
}

// POST /applications/policies/delete — remove a group allow-policy.
func (h *PanelHandler) DeleteApplicationPolicy(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderError(w, "Invalid form submission.")
		return
	}
	id := strings.TrimSpace(r.PostForm.Get("id"))
	groupID := strings.TrimSpace(r.PostForm.Get("group_id"))
	if id == "" || groupID == "" {
		h.renderError(w, "An application id and group id are required.")
		return
	}
	path := "/admin/applications/" + id + "/policies?group_id=" + url.QueryEscape(groupID)
	resp, ok := h.proxyDo(w, r, http.MethodDelete, path, nil, "")
	if !ok {
		return
	}
	resp.Body.Close()
	h.renderMessage(w, "Policy removed", "The group allow-policy was removed.", "/applications")
}

// --- form helpers ---

func (h *PanelHandler) parseGroupMemberForm(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	if err := r.ParseForm(); err != nil {
		h.renderError(w, "Invalid form submission.")
		return "", "", false
	}
	id := strings.TrimSpace(r.PostForm.Get("id"))
	userID := strings.TrimSpace(r.PostForm.Get("userId"))
	if id == "" || userID == "" {
		h.renderError(w, "A group id and user id are required.")
		return "", "", false
	}
	return id, userID, true
}

func (h *PanelHandler) parseApplicationChildForm(w http.ResponseWriter, r *http.Request, field string) (string, string, bool) {
	if err := r.ParseForm(); err != nil {
		h.renderError(w, "Invalid form submission.")
		return "", "", false
	}
	id := strings.TrimSpace(r.PostForm.Get("id"))
	value := strings.TrimSpace(r.PostForm.Get(field))
	if id == "" || value == "" {
		h.renderError(w, "An application id and "+field+" are required.")
		return "", "", false
	}
	return id, value, true
}

func mustJSON(m map[string]any) string {
	b, _ := json.Marshal(m)
	return string(b)
}

func decodeJSON(src io.Reader, dst *map[string]any) error {
	return json.NewDecoder(src).Decode(dst)
}
