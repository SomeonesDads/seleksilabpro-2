// Basic /health for F01. If you implement B03 (separate liveness/readiness
// probes), split this into HealthLive (always 200 if the process is up)
// and HealthReady (checks DB + broker connectivity, returns 503 with
// per-component detail if something's down).
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/metrics"
	"github.com/jackc/pgx/v5/pgxpool"
)

type HealthHandler struct {
	DB      *pgxpool.Pool
	Metrics *metrics.Metrics
	// TODO [B03]: add a broker connection/checker here too.
}

func NewHealthHandler(db *pgxpool.Pool) *HealthHandler {
	return &HealthHandler{DB: db}
}

// GET /health — simple combined check for the base (non-bonus) requirement.
func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	if err := h.DB.Ping(r.Context()); err != nil {
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
// serve traffic correctly. TODO: add broker ping alongside DB ping.
func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	components := map[string]string{}
	ready := true

	if err := h.DB.Ping(r.Context()); err != nil {
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

	// TODO: components["broker"] = ... via an amqp connection check.

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
