package config

import (
	"fmt"
	"os"
	"time"
)

type AppTarget struct {
	Name              string
	ApplicationID     string // UUID as string; resolved from applications table, or hardcode via env for simplicity
	LogoutNotifyURL   string // POST target for /internal/logout
	InternalAuthToken string // shared secret for service-to-service auth — see README "Keputusan teknis"
}

type Config struct {
	DatabaseURL string // read access to primary DB (events / event_deliveries) — or call the server's internal API instead, your choice
	BrokerURL   string

	MaxRetries      int
	BaseBackoff     time.Duration // exponential backoff base
	MaxBackoff      time.Duration
	ShutdownTimeout time.Duration
}

func Load() (*Config, error) {
	cfg := &Config{
		DatabaseURL:     os.Getenv("DATABASE_URL"),
		BrokerURL:       os.Getenv("BROKER_URL"),
		MaxRetries:      intEnv("MAX_RETRIES", 5),
		BaseBackoff:     durEnv("BASE_BACKOFF", 2*time.Second),
		MaxBackoff:      durEnv("MAX_BACKOFF", 2*time.Minute),
		ShutdownTimeout: durEnv("SHUTDOWN_TIMEOUT", 10*time.Second),
	}
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("config: DATABASE_URL is required")
	}
	if cfg.BrokerURL == "" {
		return nil, fmt.Errorf("config: BROKER_URL is required")
	}
	return cfg, nil
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
