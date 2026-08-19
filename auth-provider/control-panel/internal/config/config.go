package config

import (
	"fmt"
	"os"
)

type Config struct {
	Port          string
	AuthServerURL string // base URL of auth-provider/server's /admin/* API, e.g. http://auth-server:5001
	// TODO: whatever admin-auth mechanism you land on (session secret,
	// static admin credentials for the seeded admin, etc.) goes here too.
}

func Load() (*Config, error) {
	cfg := &Config{
		Port:          getEnv("PORT", "5002"),
		AuthServerURL: os.Getenv("AUTH_SERVER_URL"),
	}
	if cfg.AuthServerURL == "" {
		return nil, fmt.Errorf("config: AUTH_SERVER_URL is required")
	}
	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
