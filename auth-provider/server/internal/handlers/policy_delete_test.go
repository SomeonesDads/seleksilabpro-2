package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/repository"
	"github.com/google/uuid"
)

// fakePolicyStore records the Delete call so the P2 handler path can be
// exercised without PostgreSQL. The transactional revocation + outbox logic
// itself lives in PolicyRepository.Delete and is covered by
// TestPostgresPolicyDeletionRevokesAppTokensAndEmitsEvent (skipped without
// Docker); this fake guards the handler wiring in every environment.
type fakePolicyStore struct {
	lastApp   uuid.UUID
	lastGroup uuid.UUID
	delErr    error
	deleted   bool
}

func (s *fakePolicyStore) Set(_ context.Context, _ *models.ApplicationGroupPolicy) error {
	return nil
}

func (s *fakePolicyStore) ListByApplication(_ context.Context, _ uuid.UUID) ([]models.ApplicationGroupPolicy, error) {
	return nil, nil
}

func (s *fakePolicyStore) Delete(_ context.Context, applicationID, groupID uuid.UUID) error {
	s.lastApp = applicationID
	s.lastGroup = groupID
	s.deleted = true
	return s.delErr
}

type recorderAudit struct {
	events []models.AuditLog
}

func (a *recorderAudit) WriteAuditLog(_ context.Context, entry *models.AuditLog) error {
	a.events = append(a.events, *entry)
	return nil
}

func TestDeleteApplicationGroupPolicyRequiresGroupID(t *testing.T) {
	policies := &fakePolicyStore{}
	handler := NewAdminHandler(AdminRepositories{Policies: policies, Audit: &recorderAudit{}}, nil)

	appID := uuid.New()
	request := httptest.NewRequest(http.MethodDelete, "/admin/applications/"+appID.String()+"/policies", nil)
	request.SetPathValue("id", appID.String())
	response := httptest.NewRecorder()
	handler.DeleteApplicationGroupPolicy(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing group_id, got %d", response.Code)
	}
	if policies.deleted {
		t.Fatalf("Delete must not be called when group_id is missing")
	}
}

func TestDeleteApplicationGroupPolicyReturns404WhenPolicyMissing(t *testing.T) {
	policies := &fakePolicyStore{delErr: repository.ErrPolicyNotFound}
	handler := NewAdminHandler(AdminRepositories{Policies: policies, Audit: &recorderAudit{}}, nil)

	appID, groupID := uuid.New(), uuid.New()
	request := httptest.NewRequest(http.MethodDelete, "/admin/applications/"+appID.String()+"/policies?group_id="+groupID.String(), nil)
	request.SetPathValue("id", appID.String())
	response := httptest.NewRecorder()
	handler.DeleteApplicationGroupPolicy(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when policy missing, got %d: %s", response.Code, response.Body.String())
	}
}

func TestDeleteApplicationGroupPolicyDeletesAndAudits(t *testing.T) {
	policies := &fakePolicyStore{}
	audit := &recorderAudit{}
	handler := NewAdminHandler(AdminRepositories{Policies: policies, Audit: audit}, nil)

	appID, groupID := uuid.New(), uuid.New()
	request := httptest.NewRequest(http.MethodDelete, "/admin/applications/"+appID.String()+"/policies?group_id="+groupID.String(), nil)
	request.SetPathValue("id", appID.String())
	response := httptest.NewRecorder()
	handler.DeleteApplicationGroupPolicy(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200 on success, got %d: %s", response.Code, response.Body.String())
	}
	if policies.lastApp != appID || policies.lastGroup != groupID {
		t.Fatalf("Delete called with wrong ids: app=%s group=%s", policies.lastApp, policies.lastGroup)
	}

	var policyChanged bool
	for _, e := range audit.events {
		if e.EventType == "PolicyChanged" && e.Result == "success" {
			policyChanged = true
		}
	}
	if !policyChanged {
		t.Fatalf("expected PolicyChanged success audit, got %+v", audit.events)
	}
}
