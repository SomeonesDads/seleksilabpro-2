// The Control Panel is deliberately "dumb": it renders HTML and forwards
// admin actions to the Auth Provider Server's /admin/* API rather than
// touching the primary database itself. This keeps the DB credential
// surface small (only the server needs write access) and matches the
// component boundary in the spec's architecture diagram (Admin Console ->
// Auth Provider Server).
package handlers

import (
	"net/http"
)

type PanelHandler struct {
	AuthServerURL string
	Client        *http.Client
}

func NewPanelHandler(authServerURL string) *PanelHandler {
	return &PanelHandler{
		AuthServerURL: authServerURL,
		Client:        &http.Client{},
	}
}

// GET / — dashboard: users, groups, applications, policy overview.
func (h *PanelHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	// TODO: fetch from AuthServerURL + "/admin/..." and render a template.
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

// GET /users, POST /users, etc. — proxy CRUD forms to the admin API.
// TODO: implement one handler per admin action listed in F02's Control
// Panel Admin requirements (create/view/update/activate/deactivate users;
// manage groups + membership; register applications + redirect URIs;
// assign group policies per application).
func (h *PanelHandler) Users(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func (h *PanelHandler) Groups(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func (h *PanelHandler) Applications(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
