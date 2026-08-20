// Health endpoints for F01 and bonus B03. /health/live is always 200 while the
// process is responsive; /health/ready checks PostgreSQL and RabbitMQ and
// returns 503 with per-component status when a dependency is unavailable.
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/metrics"
	"github.com/jackc/pgx/v5/pgxpool"
	amqp "github.com/rabbitmq/amqp091-go"
)

type HealthHandler struct {
	DB         *pgxpool.Pool
	Metrics    *metrics.Metrics
	BrokerURL  string
	brokerDial func(url string) (brokerConn, error)
	// dbPing overrides DB.Ping when set, used to inject dependency state in tests.
	dbPing func(ctx context.Context) error
}

// brokerConn is the minimal AMQP surface the readiness probe needs.
type brokerConn interface {
	Close() error
}

func NewHealthHandler(db *pgxpool.Pool) *HealthHandler {
	h := &HealthHandler{DB: db}
	h.brokerDial = h.dialBroker
	return h
}

func (h *HealthHandler) dialBroker(url string) (brokerConn, error) {
	conn, err := amqp.DialConfig(url, amqp.Config{
		Dial: amqp.DefaultDial(time.Second * 3),
	})
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// ping reports database connectivity, using an injected override when present.
func (h *HealthHandler) ping(ctx context.Context) error {
	if h.dbPing != nil {
		return h.dbPing(ctx)
	}
	return h.DB.Ping(ctx)
}

// GET /health — simple combined check for the base (non-bonus) requirement.
func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	if err := h.ping(r.Context()); err != nil {
		if h.Metrics != nil {
			h.Metrics.SetDBHealth(false)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "unhealthy",
			"db":     "unreachable",
		})
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "healthy"})
	if h.Metrics != nil {
		h.Metrics.SetDBHealth(true)
	}
}

// GET /health/live — [B03] proves the process is up; must NOT depend on
// dependencies. Always 200 unless the event loop is genuinely wedged.
func (h *HealthHandler) Live(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "alive"})
}

// GET /health/ready — [B03] checks every dependency required to actually
// serve traffic correctly, including PostgreSQL and RabbitMQ.
func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	components := map[string]string{}
	ready := true

	if err := h.ping(r.Context()); err != nil {
		components["database"] = "down"
		ready = false
		if h.Metrics != nil {
			h.Metrics.SetDBHealth(false)
		}
	} else {
		components["database"] = "up"
		if h.Metrics != nil {
			h.Metrics.SetDBHealth(true)
		}
	}

	if dial := h.brokerDial; dial != nil && h.BrokerURL != "" {
		if conn, err := dial(h.BrokerURL); err != nil {
			components["broker"] = "down"
			ready = false
		} else {
			_ = conn.Close()
			components["broker"] = "up"
		}
	}

	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ready":      ready,
		"components": components,
	})
}
