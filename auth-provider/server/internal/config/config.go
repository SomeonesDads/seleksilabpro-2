// Package config loads Auth Provider Server configuration from the
// environment. Nothing sensitive (DB password, signing key, broker creds)
// is ever hardcoded — see auth-provider/server/.env.example for the full
// list of variables docker-compose expects to find in .env.
package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	// HTTP
	Port string // e.g. "5001"

	// Primary database (Postgres)
	DatabaseURL string // postgres://user:pass@host:5432/dbname?sslmode=disable

	// Message broker (RabbitMQ)
	BrokerURL string // amqp://user:pass@host:5672/

	// Token strategy: "opaque" or "jwt". Document your choice + tradeoffs
	// in the README per the deliverables checklist.
	TokenStrategy string

	// Only relevant if TokenStrategy == "jwt": symmetric signing key.
	// MUST be injected via env/secret store, never committed.
	JWTSigningKey    string
	JWTIssuer        string
	MFAEncryptionKey []byte

	// TTLs — spec suggests auth codes live 2-5 minutes.
	AuthCodeTTL    time.Duration
	AccessTokenTTL time.Duration
	SSOSessionTTL  time.Duration

	// Graceful shutdown timeout (B04 bonus, but harmless to wire up now).
	ShutdownTimeout time.Duration

	// SecureCookies controls the Secure attribute on session cookies.
	// Set false only when the server is served over plain HTTP.
	SecureCookies bool
}

func Load() (*Config, error) {
	cfg := &Config{
		Port:            getEnv("PORT", "5001"),
		DatabaseURL:     os.Getenv("DATABASE_URL"),
		BrokerURL:       os.Getenv("BROKER_URL"),
		TokenStrategy:   getEnv("TOKEN_STRATEGY", "jwt"),
		JWTSigningKey:   os.Getenv("JWT_SIGNING_KEY"),
		JWTIssuer:       getEnv("JWT_ISSUER", "auth-provider"),
		AuthCodeTTL:     durEnv("AUTH_CODE_TTL", 3*time.Minute),
		AccessTokenTTL:  durEnv("ACCESS_TOKEN_TTL", 15*time.Minute),
		SSOSessionTTL:   durEnv("SSO_SESSION_TTL", 12*time.Hour),
		ShutdownTimeout: durEnv("SHUTDOWN_TIMEOUT", 10*time.Second),
		SecureCookies:   boolEnv("SECURE_COOKIES", true),
	}
	keyText := os.Getenv("MFA_ENCRYPTION_KEY")
	if keyText == "" {
		return nil, fmt.Errorf("config: MFA_ENCRYPTION_KEY is required")
	}
	key, err := base64.StdEncoding.DecodeString(keyText)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("config: MFA_ENCRYPTION_KEY must be base64-encoded 32 bytes")
	}
	cfg.MFAEncryptionKey = key

	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("config: DATABASE_URL is required")
	}
	if cfg.BrokerURL == "" {
		return nil, fmt.Errorf("config: BROKER_URL is required")
	}
	if cfg.TokenStrategy == "jwt" && cfg.JWTSigningKey == "" {
		return nil, fmt.Errorf("config: JWT_SIGNING_KEY is required when TOKEN_STRATEGY=jwt")
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
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

func boolEnv(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}
