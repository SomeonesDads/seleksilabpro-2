// Package metrics holds the Prometheus collectors for the Sync Worker. The
// worker exposes them at /metrics from its own HTTP server.
package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics groups every collector the Sync Worker exposes.
type Metrics struct {
	Registry prometheus.Registerer

	attempts      *prometheus.CounterVec
	successes     prometheus.Counter
	retries       prometheus.Counter
	permanentFail prometheus.Counter
	dlq           *prometheus.CounterVec
	brokerUp      prometheus.Gauge
	dbUp          prometheus.Gauge
}

var (
	defaultOnce sync.Once
	defaultM    *Metrics
)

// New registers all worker collectors on the supplied registry (or the default
// registry when reg is nil) and returns the handle. Repeated constructions on
// the default registry return the same singleton.
func New(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		defaultOnce.Do(func() { defaultM = build(prometheus.DefaultRegisterer) })
		return defaultM
	}
	return build(reg)
}

func build(reg prometheus.Registerer) *Metrics {
	f := promauto.With(reg)
	return &Metrics{
		Registry: reg,
		attempts: f.NewCounterVec(prometheus.CounterOpts{
			Name: "worker_delivery_attempts_total",
			Help: "Delivery attempts, by application and outcome.",
		}, []string{"application", "status"}),
		successes: f.NewCounter(prometheus.CounterOpts{
			Name: "worker_delivery_successes_total",
			Help: "Deliveries completed successfully.",
		}),
		retries: f.NewCounter(prometheus.CounterOpts{
			Name: "worker_delivery_retries_total",
			Help: "Deliveries that hit a transient failure and were retried.",
		}),
		permanentFail: f.NewCounter(prometheus.CounterOpts{
			Name: "worker_delivery_permanent_failures_total",
			Help: "Deliveries that exhausted retries and failed permanently.",
		}),
		dlq: f.NewCounterVec(prometheus.CounterOpts{
			Name: "worker_dlq_total",
			Help: "Events routed to the dead-letter queue, by application.",
		}, []string{"application"}),
		brokerUp: f.NewGauge(prometheus.GaugeOpts{
			Name: "worker_broker_up",
			Help: "RabbitMQ broker health state, 1 = up, 0 = down.",
		}),
		dbUp: f.NewGauge(prometheus.GaugeOpts{
			Name: "worker_db_up",
			Help: "PostgreSQL health state, 1 = up, 0 = down.",
		}),
	}
}

// DeliveryAttempt records one delivery attempt for an application.
func (m *Metrics) DeliveryAttempt(application, status string) {
	m.attempts.WithLabelValues(application, status).Inc()
}

// DeliverySuccess records a successful delivery.
func (m *Metrics) DeliverySuccess() { m.successes.Inc() }

// DeliveryRetry records a transient failure that was retried.
func (m *Metrics) DeliveryRetry() { m.retries.Inc() }

// DeliveryPermanentFailure records an exhausted-retry failure.
func (m *Metrics) DeliveryPermanentFailure() { m.permanentFail.Inc() }

// DLQEvent records an event routed to the dead-letter queue for an application.
func (m *Metrics) DLQEvent(application string) { m.dlq.WithLabelValues(application).Inc() }

// SetBrokerHealth reports the broker dependency state.
func (m *Metrics) SetBrokerHealth(up bool) {
	if up {
		m.brokerUp.Set(1)
	} else {
		m.brokerUp.Set(0)
	}
}

// SetDBHealth reports the database dependency state.
func (m *Metrics) SetDBHealth(up bool) {
	if up {
		m.dbUp.Set(1)
	} else {
		m.dbUp.Set(0)
	}
}

// Exported collectors, used by tests to assert counter values.
func (m *Metrics) Attempts() *prometheus.CounterVec    { return m.attempts }
func (m *Metrics) DLQ() *prometheus.CounterVec         { return m.dlq }
func (m *Metrics) Successes() prometheus.Counter       { return m.successes }
func (m *Metrics) Retries() prometheus.Counter         { return m.retries }
func (m *Metrics) PermanentFailures() prometheus.Counter { return m.permanentFail }
