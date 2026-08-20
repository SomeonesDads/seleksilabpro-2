// Package metrics holds the Prometheus collectors for the Auth Provider web
// application and the Sync Worker. Each process registers its own collectors
// on the default registry and exposes them at /metrics.
package metrics

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// defaultMetrics caches the singleton registered on the default registry so
// that repeated constructions (e.g. many test handlers) never double-register
// collectors and panic.
var (
	defaultMetricsOnce sync.Once
	defaultMetrics     *Metrics
)

// Metrics groups every collector the Auth Provider server exposes.
type Metrics struct {
	Registry prometheus.Registerer

	httpRequests     *prometheus.CounterVec
	httpDuration     *prometheus.HistogramVec
	authFailures     *prometheus.CounterVec
	authzDenied      prometheus.Counter
	outboxDepth      prometheus.Gauge
	dbUp             prometheus.Gauge
	workerAttempts   *prometheus.CounterVec
	workerSuccesses  prometheus.Counter
	workerRetries    prometheus.Counter
	workerFailures   prometheus.Counter
	workerDLQ        *prometheus.CounterVec
}

// New registers all server collectors on the supplied registry (or the default
// registry when reg is nil) and returns the handle.
func New(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		defaultMetricsOnce.Do(func() {
			defaultMetrics = build(prometheus.DefaultRegisterer)
		})
		return defaultMetrics
	}
	return build(reg)
}

func build(reg prometheus.Registerer) *Metrics {
	f := promauto.With(reg)
	return &Metrics{
		Registry: reg,
		httpRequests: f.NewCounterVec(prometheus.CounterOpts{
			Name: "auth_http_requests_total",
			Help: "Total HTTP requests handled, by method and status code.",
		}, []string{"method", "code"}),
		httpDuration: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "auth_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds, by method and status code.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		}, []string{"method", "code"}),
		authFailures: f.NewCounterVec(prometheus.CounterOpts{
			Name: "auth_authentication_failures_total",
			Help: "Authentication failures, by kind (login, mfa, authorize).",
		}, []string{"kind"}),
		authzDenied: f.NewCounter(prometheus.CounterOpts{
			Name: "auth_authorization_denied_total",
			Help: "Total authorization denials (policy/redirect/parameter failures).",
		}),
		outboxDepth: f.NewGauge(prometheus.GaugeOpts{
			Name: "auth_outbox_depth",
			Help: "Number of unpublished outbox events awaiting delivery.",
		}),
		dbUp: f.NewGauge(prometheus.GaugeOpts{
			Name: "auth_dependency_up",
			Help: "Health state of a required dependency, 1 = up, 0 = down. Labeled by component.",
		}),
		workerAttempts: f.NewCounterVec(prometheus.CounterOpts{
			Name: "auth_worker_delivery_attempts_total",
			Help: "Sync Worker delivery attempts, by application and outcome.",
		}, []string{"application", "status"}),
		workerSuccesses: f.NewCounter(prometheus.CounterOpts{
			Name: "auth_worker_delivery_successes_total",
			Help: "Sync Worker deliveries completed successfully.",
		}),
		workerRetries: f.NewCounter(prometheus.CounterOpts{
			Name: "auth_worker_delivery_retries_total",
			Help: "Sync Worker deliveries that hit a transient failure and were retried.",
		}),
		workerFailures: f.NewCounter(prometheus.CounterOpts{
			Name: "auth_worker_delivery_permanent_failures_total",
			Help: "Sync Worker deliveries that exhausted retries and failed permanently.",
		}),
		workerDLQ: f.NewCounterVec(prometheus.CounterOpts{
			Name: "auth_worker_dlq_total",
			Help: "Events routed to the dead-letter queue, by application.",
		}, []string{"application"}),
	}
}

// Middleware instruments every HTTP request for rate, error count, and duration.
func (m *Metrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		code := strconv.Itoa(sw.status)
		elapsed := time.Since(start).Seconds()
		m.httpRequests.WithLabelValues(r.Method, code).Inc()
		m.httpDuration.WithLabelValues(r.Method, code).Observe(elapsed)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	return s.ResponseWriter.Write(b)
}

// RecordAuthFailure increments the authentication-failure counter for a kind.
func (m *Metrics) RecordAuthFailure(kind string) {
	m.authFailures.WithLabelValues(kind).Inc()
}

// RecordAuthzDenied increments the authorization-denial counter.
func (m *Metrics) RecordAuthzDenied() {
	m.authzDenied.Inc()
}

// SetOutboxDepth records the current unpublished-event count.
func (m *Metrics) SetOutboxDepth(n int64) {
	m.outboxDepth.Set(float64(n))
}

// SetDBHealth reports the database dependency state.
func (m *Metrics) SetDBHealth(up bool) {
	if up {
		m.dbUp.Set(1)
	} else {
		m.dbUp.Set(0)
	}
}

// WorkerDeliveryAttempt records one worker delivery attempt for an application.
func (m *Metrics) WorkerDeliveryAttempt(application, status string) {
	m.workerAttempts.WithLabelValues(application, status).Inc()
}

// WorkerDeliverySuccess records a successful worker delivery.
func (m *Metrics) WorkerDeliverySuccess() {
	m.workerSuccesses.Inc()
}

// WorkerDeliveryRetry records a transient failure that was retried.
func (m *Metrics) WorkerDeliveryRetry() {
	m.workerRetries.Inc()
}

// WorkerDeliveryPermanentFailure records an exhausted-retry failure.
func (m *Metrics) WorkerDeliveryPermanentFailure() {
	m.workerFailures.Inc()
}

// WorkerDLQ records an event routed to the dead-letter queue for an application.
func (m *Metrics) WorkerDLQEvent(application string) {
	m.workerDLQ.WithLabelValues(application).Inc()
}
