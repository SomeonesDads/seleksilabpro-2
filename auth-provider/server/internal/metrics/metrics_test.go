package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestMiddlewareCountsRequests(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/boom" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(m.Middleware(next))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/login")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	resp, err = http.Get(srv.URL + "/boom")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}

	// /metrics must return valid exposition text.
	metricsSrv := httptest.NewServer(promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	defer metricsSrv.Close()
	mresp, err := http.Get(metricsSrv.URL)
	if err != nil {
		t.Fatalf("metrics request failed: %v", err)
	}
	if mresp.StatusCode != http.StatusOK {
		t.Fatalf("metrics expected 200, got %d", mresp.StatusCode)
	}
	buf := make([]byte, 4096)
	n, _ := mresp.Body.Read(buf)
	body := string(buf[:n])
	mresp.Body.Close()
	if !strings.Contains(body, "auth_http_requests_total") {
		t.Fatalf("expected request counter in exposition, got:\n%s", body)
	}
}

func TestAuthFailureAndOutboxDepth(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	m.RecordAuthFailure("login")
	m.RecordAuthFailure("login")
	m.RecordAuthzDenied()
	m.SetOutboxDepth(7)

	metricsSrv := httptest.NewServer(promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	defer metricsSrv.Close()
	resp, err := http.Get(metricsSrv.URL)
	if err != nil {
		t.Fatalf("metrics request failed: %v", err)
	}
	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	resp.Body.Close()

	for _, want := range []string{
		`auth_authentication_failures_total{kind="login"} 2`,
		"auth_authorization_denied_total 1",
		"auth_outbox_depth 7",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("exposition missing %q, got:\n%s", want, body)
		}
	}
}

func TestWorkerDeliveryMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	m.WorkerDeliveryAttempt("app-a", "success")
	m.WorkerDeliverySuccess()
	m.WorkerDeliveryRetry()
	m.WorkerDeliveryPermanentFailure()
	m.WorkerDLQEvent("app-b")

	metricsSrv := httptest.NewServer(promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	defer metricsSrv.Close()
	resp, err := http.Get(metricsSrv.URL)
	if err != nil {
		t.Fatalf("metrics request failed: %v", err)
	}
	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	resp.Body.Close()

	for _, want := range []string{
		`auth_worker_delivery_attempts_total{application="app-a",status="success"} 1`,
		"auth_worker_delivery_successes_total 1",
		"auth_worker_delivery_retries_total 1",
		"auth_worker_delivery_permanent_failures_total 1",
		`auth_worker_dlq_total{application="app-b"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("exposition missing %q, got:\n%s", want, body)
		}
	}
}
