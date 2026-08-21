package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/repository"
	sharederrors "github.com/SomeonesDads/seleksilabpro-2/shared/errors"
	"github.com/SomeonesDads/seleksilabpro-2/shared/idgen"
	"github.com/google/uuid"
)

type AdminHandler struct {
	Repos  AdminRepositories
	Logger *slog.Logger
}

func NewAdminHandler(repos AdminRepositories, logger *slog.Logger) *AdminHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &AdminHandler{Repos: repos, Logger: logger}
}

func (h *AdminHandler) audit(r *http.Request, eventType, result string, userID, applicationID *uuid.UUID) {
	if h.Repos.Audit == nil {
		return
	}
	if err := h.Repos.Audit.WriteAuditLog(r.Context(), &models.AuditLog{
		EventType:     eventType,
		UserID:        userID,
		ApplicationID: applicationID,
		Result:        result,
		IPAddress:     stringPtr(r.RemoteAddr),
	}); err != nil {
		h.Logger.Error("admin audit write failed", slog.Any("err", err), slog.String("eventType", eventType))
	}
}

func adminUser(user *models.User) map[string]any {
	return map[string]any{"id": user.ID, "name": user.Name, "email": user.Email, "status": user.Status, "created_at": user.CreatedAt, "updated_at": user.UpdatedAt}
}

func adminGroup(group *models.Group) map[string]any {
	m := map[string]any{"id": group.ID, "name": group.Name}
	if group.Description != nil {
		m["description"] = *group.Description
	}
	return m
}

func adminApplication(application *models.Application) map[string]any {
	return map[string]any{"id": application.ID, "name": application.Name, "client_id": application.ClientID, "status": application.Status, "launch_url": application.LaunchURL, "logout_notification_url": application.LogoutNotificationURL, "created_at": application.CreatedAt, "updated_at": application.UpdatedAt}
}

func adminID(r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue(name))
	return id, err == nil
}

func adminRequired(value string) bool { return strings.TrimSpace(value) != "" }

func adminRepositoryError(w http.ResponseWriter, r *http.Request, err error, resource string) {
	if errors.Is(err, repository.ErrGroupMembershipNotFound) {
		writeError(w, r, http.StatusNotFound, sharederrors.CodeNotFound, "group membership not found")
		return
	}
	if repository.IsConflict(err) {
		// Keep uniqueness details generic. In particular, do not reveal whether
		// an email address is already registered through the admin API.
		writeError(w, r, http.StatusConflict, sharederrors.CodeConflict, "request conflicts with an existing resource")
		return
	}
	if repository.IsForeignKeyViolation(err) {
		writeError(w, r, http.StatusNotFound, sharederrors.CodeNotFound, "referenced resource not found")
		return
	}
	writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, resource+" unavailable")
}

func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	if h.Repos.Users == nil {
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "users unavailable")
		return
	}
	if h.Repos.Users == nil || h.Repos.Groups == nil {
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "users unavailable")
		return
	}
	users, err := h.Repos.Users.List(r.Context())
	if err != nil {
		h.Logger.Error("list users failed", slog.Any("err", err))
		adminRepositoryError(w, r, err, "users")
		return
	}
	result := make([]map[string]any, 0, len(users))
	for i := range users {
		row := adminUser(&users[i])
		groups, gerr := h.Repos.Groups.FindByUserID(r.Context(), users[i].ID)
		if gerr != nil {
			adminRepositoryError(w, r, gerr, "users")
			return
		}
		groupViews := make([]map[string]any, 0, len(groups))
		for j := range groups {
			groupViews = append(groupViews, map[string]any{"id": groups[j].ID, "name": groups[j].Name})
		}
		row["groups"] = groupViews
		result = append(result, row)
	}
	_ = writeJSON(w, http.StatusOK, map[string]any{"users": result})
}

func (h *AdminHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	if h.Repos.Users == nil {
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "users unavailable")
		return
	}
	var input struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Status   string `json:"status"`
	}
	if err := decodeJSONBody(r, &input); err != nil || !adminRequired(input.Name) || !adminRequired(input.Email) || !adminRequired(input.Password) {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "name, email, and password are required")
		return
	}
	if input.Status == "" {
		input.Status = "active"
	}
	if input.Status != "active" && input.Status != "inactive" {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "invalid user status")
		return
	}
	user, err := h.Repos.Users.CreateUser(r.Context(), strings.TrimSpace(input.Name), strings.TrimSpace(input.Email), input.Password, input.Status)
	if err != nil {
		h.Logger.Error("create user failed", slog.Any("err", err))
		adminRepositoryError(w, r, err, "user")
		return
	}
	h.audit(r, "UserChanged", "success", &user.ID, nil)
	_ = writeJSON(w, http.StatusCreated, adminUser(user))
}

func (h *AdminHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	if h.Repos.Users == nil {
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "users unavailable")
		return
	}
	id, ok := adminID(r, "id")
	if !ok {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "invalid user id")
		return
	}
	user, err := h.Repos.Users.FindByID(r.Context(), id)
	if errors.Is(err, repository.ErrUserNotFound) {
		writeError(w, r, http.StatusNotFound, sharederrors.CodeNotFound, "user not found")
		return
	}
	if err != nil {
		adminRepositoryError(w, r, err, "user")
		return
	}
	_ = writeJSON(w, http.StatusOK, adminUser(user))
}

func (h *AdminHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	if h.Repos.Users == nil {
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "users unavailable")
		return
	}
	id, ok := adminID(r, "id")
	if !ok {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "invalid user id")
		return
	}
	var input struct {
		Name     *string `json:"name"`
		Email    *string `json:"email"`
		Password *string `json:"password"`
	}
	if err := decodeJSONBody(r, &input); err != nil || (input.Name == nil && input.Email == nil && input.Password == nil) {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "user update is empty or invalid")
		return
	}
	if input.Password != nil && !adminRequired(*input.Password) {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "password cannot be empty")
		return
	}
	user, err := h.Repos.Users.UpdateUserAndRevoke(r.Context(), id, input.Name, input.Email, input.Password)
	if errors.Is(err, repository.ErrUserNotFound) {
		writeError(w, r, http.StatusNotFound, sharederrors.CodeNotFound, "user not found")
		return
	}
	if err != nil {
		adminRepositoryError(w, r, err, "user")
		return
	}
	eventType := "UserChanged"
	if input.Password != nil {
		eventType = "PasswordChanged"
	}
	h.audit(r, eventType, "success", &user.ID, nil)
	_ = writeJSON(w, http.StatusOK, adminUser(user))
}

func (h *AdminHandler) SetUserStatus(w http.ResponseWriter, r *http.Request) {
	if h.Repos.Users == nil {
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "users unavailable")
		return
	}
	id, ok := adminID(r, "id")
	if !ok {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "invalid user id")
		return
	}
	var input struct {
		Status string `json:"status"`
	}
	if err := decodeJSONBody(r, &input); err != nil || (input.Status != "active" && input.Status != "inactive") {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "status must be active or inactive")
		return
	}
	if h.Repos.Sessions == nil {
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "user status unavailable")
		return
	}
	if err := h.Repos.Sessions.SetUserStatusAndRevoke(r.Context(), id, input.Status, "user_inactive"); err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			writeError(w, r, http.StatusNotFound, sharederrors.CodeNotFound, "user not found")
			return
		}
		adminRepositoryError(w, r, err, "user")
		return
	}
	h.audit(r, "UserChanged", "success", &id, nil)
	_ = writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": input.Status})
}

func (h *AdminHandler) ListGroups(w http.ResponseWriter, r *http.Request) {
	if h.Repos.Groups == nil {
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "groups unavailable")
		return
	}
	groups, err := h.Repos.Groups.List(r.Context())
	if err != nil {
		adminRepositoryError(w, r, err, "groups")
		return
	}
	views := make([]map[string]any, 0, len(groups))
	for i := range groups {
		views = append(views, adminGroup(&groups[i]))
	}
	_ = writeJSON(w, http.StatusOK, map[string]any{"groups": views})
}

func (h *AdminHandler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	if h.Repos.Groups == nil {
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "groups unavailable")
		return
	}
	var input struct {
		Name        string  `json:"name"`
		Description *string `json:"description"`
	}
	if err := decodeJSONBody(r, &input); err != nil || !adminRequired(input.Name) {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "group name is required")
		return
	}
	group := &models.Group{Name: strings.TrimSpace(input.Name), Description: input.Description}
	if err := h.Repos.Groups.Create(r.Context(), group); err != nil {
		adminRepositoryError(w, r, err, "group")
		return
	}
	h.audit(r, "GroupChanged", "success", nil, nil)
	_ = writeJSON(w, http.StatusCreated, adminGroup(group))
}

func (h *AdminHandler) AddUserToGroup(w http.ResponseWriter, r *http.Request) {
	if h.Repos.Groups == nil {
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "groups unavailable")
		return
	}
	groupID, groupOK := adminID(r, "id")
	if !groupOK {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "invalid group or user id")
		return
	}
	var input struct {
		UserID string `json:"userId"`
	}
	if err := decodeJSONBody(r, &input); err != nil || strings.TrimSpace(input.UserID) == "" {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "invalid group or user id")
		return
	}
	userID, userErr := uuid.Parse(strings.TrimSpace(input.UserID))
	if userErr != nil {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "invalid group or user id")
		return
	}
	if err := h.Repos.Groups.AddUser(r.Context(), groupID, userID); err != nil {
		adminRepositoryError(w, r, err, "group membership")
		return
	}
	h.audit(r, "GroupChanged", "success", &userID, nil)
	_ = writeJSON(w, http.StatusOK, map[string]any{"group_id": groupID, "user_id": userID})
}

func (h *AdminHandler) RemoveUserFromGroup(w http.ResponseWriter, r *http.Request) {
	if h.Repos.Groups == nil {
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "groups unavailable")
		return
	}
	groupID, groupOK := adminID(r, "id")
	userID, userErr := uuid.Parse(r.PathValue("userId"))
	if !groupOK || userErr != nil {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "invalid group or user id")
		return
	}
	if err := h.Repos.Groups.RemoveUser(r.Context(), groupID, userID); err != nil {
		adminRepositoryError(w, r, err, "group membership")
		return
	}
	h.audit(r, "GroupChanged", "success", &userID, nil)
	_ = writeJSON(w, http.StatusOK, map[string]any{"removed": true})
}

func (h *AdminHandler) ListApplications(w http.ResponseWriter, r *http.Request) {
	if h.Repos.Applications == nil {
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "applications unavailable")
		return
	}
	applications, err := h.Repos.Applications.List(r.Context())
	if err != nil {
		adminRepositoryError(w, r, err, "applications")
		return
	}
	result := make([]map[string]any, 0, len(applications))
	for i := range applications {
		result = append(result, adminApplication(&applications[i]))
	}
	_ = writeJSON(w, http.StatusOK, map[string]any{"applications": result})
}

func (h *AdminHandler) CreateApplication(w http.ResponseWriter, r *http.Request) {
	if h.Repos.Applications == nil {
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "applications unavailable")
		return
	}
	var input struct {
		Name                  string  `json:"name"`
		ClientID              string  `json:"client_id"`
		RedirectURI           string  `json:"redirect_uri"`
		LaunchURL             *string `json:"launch_url"`
		LogoutNotificationURL string  `json:"logout_notification_url"`
	}
	if err := decodeJSONBody(r, &input); err != nil || !adminRequired(input.Name) || !adminRequired(input.RedirectURI) || !adminRequired(input.LogoutNotificationURL) {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "name, redirect_uri, and logout_notification_url are required")
		return
	}
	clientID := strings.TrimSpace(input.ClientID)
	if clientID == "" {
		var err error
		clientID, err = idgen.RandomToken(18)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "application unavailable")
			return
		}
	}
	clientSecret, err := idgen.RandomToken(32)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "application unavailable")
		return
	}
	application := &models.Application{Name: strings.TrimSpace(input.Name), ClientID: clientID, Status: "active", LaunchURL: input.LaunchURL, LogoutNotificationURL: strings.TrimSpace(input.LogoutNotificationURL)}
	if err := h.Repos.Applications.CreateWithSecretAndRedirect(r.Context(), application, clientSecret, input.RedirectURI); err != nil {
		adminRepositoryError(w, r, err, "application")
		return
	}
	h.audit(r, "ApplicationChanged", "success", nil, &application.ID)
	response := adminApplication(application)
	response["client_secret"] = clientSecret
	response["redirect_uri"] = input.RedirectURI
	_ = writeJSON(w, http.StatusCreated, response)
}

func (h *AdminHandler) AddRedirectURI(w http.ResponseWriter, r *http.Request) {
	if h.Repos.Applications == nil {
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "applications unavailable")
		return
	}
	applicationID, ok := adminID(r, "id")
	if !ok {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "invalid application id")
		return
	}
	var input struct {
		RedirectURI string `json:"redirect_uri"`
	}
	if err := decodeJSONBody(r, &input); err != nil || !adminRequired(input.RedirectURI) {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "redirect_uri is required")
		return
	}
	if err := h.Repos.Applications.AddRedirectURI(r.Context(), &models.ApplicationRedirectURI{ApplicationID: applicationID, RedirectURI: input.RedirectURI}); err != nil {
		adminRepositoryError(w, r, err, "redirect URI")
		return
	}
	h.audit(r, "ApplicationChanged", "success", nil, &applicationID)
	_ = writeJSON(w, http.StatusCreated, map[string]any{"application_id": applicationID, "redirect_uri": input.RedirectURI})
}

func (h *AdminHandler) SetApplicationGroupPolicy(w http.ResponseWriter, r *http.Request) {
	if h.Repos.Policies == nil {
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "policies unavailable")
		return
	}
	applicationID, ok := adminID(r, "id")
	if !ok {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "invalid application id")
		return
	}
	var input struct {
		GroupID uuid.UUID `json:"group_id"`
		Effect  string    `json:"effect"`
	}
	if err := decodeJSONBody(r, &input); err != nil || input.GroupID == uuid.Nil || (input.Effect != "" && input.Effect != "allow") {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "group_id and allow effect are required")
		return
	}
	if input.Effect == "" {
		input.Effect = "allow"
	}
	policy := &models.ApplicationGroupPolicy{ApplicationID: applicationID, GroupID: input.GroupID, Effect: input.Effect}
	if err := h.Repos.Policies.Set(r.Context(), policy); err != nil {
		adminRepositoryError(w, r, err, "policy")
		return
	}
	h.audit(r, "PolicyChanged", "success", nil, &applicationID)
	_ = writeJSON(w, http.StatusOK, policy)
}

// DeleteApplicationGroupPolicy removes an allow policy binding a group to an
// application. Per DECISIONS.md Decision 016, this revokes only the affected
// application's access-token metadata (not central SSO sessions or unrelated
// apps) and emits an AccessPolicyChanged outbox event per affected user.
func (h *AdminHandler) DeleteApplicationGroupPolicy(w http.ResponseWriter, r *http.Request) {
	if h.Repos.Policies == nil {
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "policies unavailable")
		return
	}
	applicationID, ok := adminID(r, "id")
	if !ok {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "invalid application id")
		return
	}
	groupID, err := uuid.Parse(r.URL.Query().Get("group_id"))
	if err != nil || groupID == uuid.Nil {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "group_id is required")
		return
	}
	if err := h.Repos.Policies.Delete(r.Context(), applicationID, groupID); err != nil {
		if errors.Is(err, repository.ErrPolicyNotFound) {
			writeError(w, r, http.StatusNotFound, sharederrors.CodeNotFound, "policy not found")
			return
		}
		adminRepositoryError(w, r, err, "policy")
		return
	}
	h.audit(r, "PolicyChanged", "success", nil, &applicationID)
	_ = writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "application_id": applicationID, "group_id": groupID})
}

func (h *AdminHandler) GetUserStatusOverview(w http.ResponseWriter, r *http.Request) {
	if h.Repos.Users == nil || h.Repos.Groups == nil || h.Repos.Applications == nil || h.Repos.Policies == nil {
		writeError(w, r, http.StatusInternalServerError, sharederrors.CodeInternal, "overview unavailable")
		return
	}
	id, ok := adminID(r, "userId")
	if !ok {
		writeError(w, r, http.StatusBadRequest, sharederrors.CodeInvalidRequest, "invalid user id")
		return
	}
	user, err := h.Repos.Users.FindByID(r.Context(), id)
	if errors.Is(err, repository.ErrUserNotFound) {
		writeError(w, r, http.StatusNotFound, sharederrors.CodeNotFound, "user not found")
		return
	}
	if err != nil {
		adminRepositoryError(w, r, err, "overview")
		return
	}
	groups, err := h.Repos.Groups.FindByUserID(r.Context(), id)
	if err != nil {
		adminRepositoryError(w, r, err, "overview")
		return
	}
	groupViews := make([]map[string]any, 0, len(groups))
	for i := range groups {
		groupViews = append(groupViews, adminGroup(&groups[i]))
	}
	applications, err := h.Repos.Applications.List(r.Context())
	if err != nil {
		adminRepositoryError(w, r, err, "overview")
		return
	}
	policies := make(map[string][]models.ApplicationGroupPolicy, len(applications))
	applicationViews := make([]map[string]any, 0, len(applications))
	for i := range applications {
		applicationViews = append(applicationViews, adminApplication(&applications[i]))
		items, err := h.Repos.Policies.ListByApplication(r.Context(), applications[i].ID)
		if err != nil {
			adminRepositoryError(w, r, err, "overview")
			return
		}
		policies[applications[i].ID.String()] = items
	}
	_ = writeJSON(w, http.StatusOK, map[string]any{"user": adminUser(user), "groups": groupViews, "applications": applicationViews, "policies": policies})
}
