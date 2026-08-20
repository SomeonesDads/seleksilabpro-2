package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type adminUsersFake struct {
	user    models.User
	created bool
	err     error
}

func (s *adminUsersFake) List(context.Context) ([]models.User, error) {
	return []models.User{s.user}, nil
}
func (s *adminUsersFake) FindByID(context.Context, uuid.UUID) (*models.User, error) {
	return &s.user, nil
}
func (s *adminUsersFake) CreateUser(_ context.Context, name, email, password, status string) (*models.User, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.created = true
	s.user = models.User{ID: uuid.New(), Name: name, Email: email, PasswordHash: password, Status: status}
	return &s.user, nil
}

func TestAdminDuplicateUserDoesNotRevealEmailExistence(t *testing.T) {
	users := &adminUsersFake{err: gorm.ErrDuplicatedKey}
	handler := NewAdminHandler(AdminRepositories{Users: users}, nil)
	request := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(`{"name":"Ada","email":"ada@example.com","password":"secret"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.CreateUser(response, request)

	if response.Code != http.StatusConflict {
		t.Fatalf("expected conflict status, got %d: %s", response.Code, response.Body.String())
	}
	if strings.Contains(strings.ToLower(response.Body.String()), "ada@example.com") || strings.Contains(strings.ToLower(response.Body.String()), "already exists") {
		t.Fatalf("duplicate response leaks uniqueness details: %s", response.Body.String())
	}
}
func (s *adminUsersFake) UpdateUser(context.Context, uuid.UUID, *string, *string, *string) (*models.User, error) {
	return &s.user, nil
}
func (s *adminUsersFake) UpdateUserAndRevoke(context.Context, uuid.UUID, *string, *string, *string) (*models.User, error) {
	return &s.user, nil
}
func (s *adminUsersFake) SetStatus(context.Context, uuid.UUID, string) error { return nil }

type adminGroupsFake struct{}

func (adminGroupsFake) List(context.Context) ([]models.Group, error) { return nil, nil }
func (adminGroupsFake) FindByUserID(context.Context, uuid.UUID) ([]models.Group, error) {
	return nil, nil
}
func (adminGroupsFake) Create(context.Context, *models.Group) error            { return nil }
func (adminGroupsFake) AddUser(context.Context, uuid.UUID, uuid.UUID) error    { return nil }
func (adminGroupsFake) RemoveUser(context.Context, uuid.UUID, uuid.UUID) error { return nil }

type adminApplicationsFake struct {
	application models.Application
	secretHash  string
}

func (s *adminApplicationsFake) List(context.Context) ([]models.Application, error) {
	return []models.Application{s.application}, nil
}
func (s *adminApplicationsFake) CreateWithSecret(_ context.Context, application *models.Application, secret string) error {
	s.application = *application
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	s.secretHash = string(hash)
	return err
}
func (s *adminApplicationsFake) CreateWithSecretAndRedirect(ctx context.Context, application *models.Application, secret, _ string) error {
	return s.CreateWithSecret(ctx, application, secret)
}
func (s *adminApplicationsFake) AddRedirectURI(context.Context, *models.ApplicationRedirectURI) error {
	return nil
}

type adminPoliciesFake struct{}

func (adminPoliciesFake) Set(context.Context, *models.ApplicationGroupPolicy) error { return nil }
func (adminPoliciesFake) ListByApplication(context.Context, uuid.UUID) ([]models.ApplicationGroupPolicy, error) {
	return nil, nil
}
func (adminPoliciesFake) Delete(context.Context, uuid.UUID, uuid.UUID) error { return nil }

type adminSessionsFake struct {
	called bool
}

func (s *adminSessionsFake) RevokeAllForUser(context.Context, uuid.UUID, string) error { return nil }
func (s *adminSessionsFake) SetUserStatusAndRevoke(context.Context, uuid.UUID, string, string) error {
	s.called = true
	return nil
}

func TestAdminCreateUserDoesNotReturnPasswordHash(t *testing.T) {
	users := &adminUsersFake{}
	handler := NewAdminHandler(AdminRepositories{Users: users}, nil)
	request := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(`{"name":"Ada","email":"ada@example.com","password":"secret"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.CreateUser(response, request)
	if response.Code != http.StatusCreated || !users.created {
		t.Fatalf("user creation failed: status=%d body=%s", response.Code, response.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["password_hash"]; ok {
		t.Fatalf("password hash leaked in admin response: %v", body)
	}
}

func TestAdminCreateApplicationHashesSecretAndListOmitsIt(t *testing.T) {
	applications := &adminApplicationsFake{}
	handler := NewAdminHandler(AdminRepositories{Applications: applications}, nil)
	request := httptest.NewRequest(http.MethodPost, "/admin/applications", strings.NewReader(`{"name":"App","client_id":"app-client","redirect_uri":"https://app.example/callback","logout_notification_url":"https://app.example/internal/logout"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.CreateApplication(response, request)
	if response.Code != http.StatusCreated || applications.secretHash == "" {
		t.Fatalf("application creation failed: status=%d body=%s", response.Code, response.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	secret, ok := body["client_secret"].(string)
	if !ok || secret == "" || bcrypt.CompareHashAndPassword([]byte(applications.secretHash), []byte(secret)) != nil {
		t.Fatalf("client secret was not returned once or was not hash-compatible: %v", body)
	}
	listResponse := httptest.NewRecorder()
	handler.ListApplications(listResponse, httptest.NewRequest(http.MethodGet, "/admin/applications", nil))
	if strings.Contains(listResponse.Body.String(), "client_secret_hash") {
		t.Fatalf("client secret hash leaked in application list: %s", listResponse.Body.String())
	}
}

func TestAdminDeactivationUsesTransactionalSessionOperation(t *testing.T) {
	userID := uuid.New()
	sessions := &adminSessionsFake{}
	handler := NewAdminHandler(AdminRepositories{Users: &adminUsersFake{user: models.User{ID: userID}}, Sessions: sessions}, nil)
	request := httptest.NewRequest(http.MethodPatch, "/admin/users/"+userID.String()+"/status", strings.NewReader(`{"status":"inactive"}`))
	request.Header.Set("Content-Type", "application/json")
	request.SetPathValue("id", userID.String())
	response := httptest.NewRecorder()
	handler.SetUserStatus(response, request)
	if response.Code != http.StatusOK || !sessions.called {
		t.Fatalf("deactivation did not use transactional session operation: status=%d called=%v body=%s", response.Code, sessions.called, response.Body.String())
	}
}
