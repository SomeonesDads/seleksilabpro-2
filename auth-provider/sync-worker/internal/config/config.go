package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

type AppTarget struct {
	Name              string `json:"name"`
	ApplicationID     string `json:"applicationId"`
	LogoutNotifyURL   string `json:"logoutNotifyURL"`
	InternalAuthToken string `json:"internalAuthToken"`
}

type Config struct {
	DatabaseURL string // read access to primary DB (events / event_deliveries) — or call the server's internal API instead, your choice
	BrokerURL   string

	MaxRetries      int
	BaseBackoff     time.Duration // exponential backoff base
	MaxBackoff      time.Duration
	OutboxInterval  time.Duration
	ShutdownTimeout time.Duration
	Targets         []AppTarget
}

func Load() (*Config, error) {
	cfg := &Config{
		DatabaseURL:     os.Getenv("DATABASE_URL"),
		BrokerURL:       os.Getenv("BROKER_URL"),
		MaxRetries:      intEnv("MAX_RETRIES", 5),
		BaseBackoff:     durEnv("BASE_BACKOFF", 2*time.Second),
		MaxBackoff:      durEnv("MAX_BACKOFF", 2*time.Minute),
		OutboxInterval:  durEnv("OUTBOX_INTERVAL", 500*time.Millisecond),
		ShutdownTimeout: durEnv("SHUTDOWN_TIMEOUT", 10*time.Second),
	}
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("config: DATABASE_URL is required")
	}
	if cfg.BrokerURL == "" {
		return nil, fmt.Errorf("config: BROKER_URL is required")
	}
	targets, err := parseTargets(os.Getenv("APP_TARGETS_JSON"))
	if err != nil {
		return nil, err
	}
	cfg.Targets = targets
	return cfg, nil
}

func parseTargets(raw string) ([]AppTarget, error) {
	if raw == "" {
		return nil, fmt.Errorf("config: APP_TARGETS_JSON is required; configure every relying application")
	}
	var targets []AppTarget
	if err := json.Unmarshal([]byte(raw), &targets); err != nil {
		return nil, fmt.Errorf("config: invalid APP_TARGETS_JSON: %w", err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("config: APP_TARGETS_JSON must contain at least one application")
	}
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if _, err := uuid.Parse(target.ApplicationID); err != nil {
			return nil, fmt.Errorf("config: invalid applicationId in APP_TARGETS_JSON")
		}
		if _, ok := seen[target.ApplicationID]; ok {
			return nil, fmt.Errorf("config: duplicate applicationId in APP_TARGETS_JSON")
		}
		seen[target.ApplicationID] = struct{}{}
		if strings.TrimSpace(target.LogoutNotifyURL) == "" {
			return nil, fmt.Errorf("config: empty logoutNotifyURL in APP_TARGETS_JSON")
		}
		if strings.TrimSpace(target.InternalAuthToken) == "" {
			return nil, fmt.Errorf("config: empty internalAuthToken in APP_TARGETS_JSON")
		}
	}
	return targets, nil
}

func intEnv(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return fallback
	}
	return n
}

func durEnv(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
