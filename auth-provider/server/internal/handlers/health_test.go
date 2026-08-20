package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeBrokerConn struct{ closed bool }

func (f *fakeBrokerConn) Close() error { f.closed = true; return nil }

func newTestHealth() *HealthHandler {
	return &HealthHandler{
		BrokerURL:  "amqp://example",
		brokerDial: func(url string) (brokerConn, error) { return &fakeBrokerConn{}, nil },
		dbPing:     func(ctx context.Context) error { return nil },
	}
}

func TestLiveAlwaysOK(t *testing.T) {
	h := newTestHealth()
	rec := httptest.NewRecorder()
	h.Live(rec, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("live status = %d, want 200", rec.Code)
	}
}

func TestReadyAllUp(t *testing.T) {
	h := newTestHealth()
	rec := httptest.NewRecorder()
	h.Ready(rec, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("ready status = %d, want 200", rec.Code)
	}
	var body struct {
		Ready      bool              `json:"ready"`
		Components map[string]string `json:"components"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.Ready {
		t.Fatalf("ready = false, want true")
	}
	if body.Components["database"] != "up" || body.Components["broker"] != "up" {
		t.Fatalf("components = %v, want both up", body.Components)
	}
}

func TestReadyBrokerDown(t *testing.T) {
	h := newTestHealth()
	h.brokerDial = func(url string) (brokerConn, error) { return nil, context.DeadlineExceeded }
	rec := httptest.NewRecorder()
	h.Ready(rec, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready status = %d, want 503", rec.Code)
	}
	var body struct {
		Ready      bool              `json:"ready"`
		Components map[string]string `json:"components"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Ready {
		t.Fatalf("ready = true, want false")
	}
	if body.Components["broker"] != "down" {
		t.Fatalf("broker component = %q, want down", body.Components["broker"])
	}
	if body.Components["database"] != "up" {
		t.Fatalf("database component = %q, want up", body.Components["database"])
	}
}

func TestReadyDatabaseDown(t *testing.T) {
	h := newTestHealth()
	h.dbPing = func(ctx context.Context) error { return context.DeadlineExceeded }
	rec := httptest.NewRecorder()
	h.Ready(rec, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready status = %d, want 503", rec.Code)
	}
	var body struct {
		Components map[string]string `json:"components"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Components["database"] != "down" {
		t.Fatalf("database component = %q, want down", body.Components["database"])
	}
	if body.Components["broker"] != "up" {
		t.Fatalf("broker component = %q, want up", body.Components["broker"])
	}
}

func TestReadyNoBrokerConfiguredSkipsBroker(t *testing.T) {
	h := newTestHealth()
	h.BrokerURL = ""
	rec := httptest.NewRecorder()
	h.Ready(rec, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("ready status = %d, want 200", rec.Code)
	}
	var body struct {
		Components map[string]string `json:"components"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body.Components["broker"]; ok {
		t.Fatalf("broker should be omitted when unconfigured, got %v", body.Components)
	}
}
