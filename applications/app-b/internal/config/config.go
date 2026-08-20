package config

import (
	"os"
	"time"
)

// Config holds the runtime configuration for App B. All values come from the
// environment; nothing sensitive is ever compiled into the binary.
type Config struct {
	Port                string
	DatabaseURL         string
	AuthProviderBaseURL string
	ClientID            string
	ClientSecret        string
	RedirectURI         string
	InternalAuthToken   string
	SessionTTL          time.Duration
	CookieSecure        bool
	AppID               string
}

func Get() Config {
	return Config{
		Port:                getenv("APP_PORT", "5020"),
		DatabaseURL:         os.Getenv("DATABASE_URL"),
		AuthProviderBaseURL: getenv("AUTH_PROVIDER_BASE_URL", "http://auth-server:5001"),
		ClientID:            os.Getenv("APP_CLIENT_ID"),
		ClientSecret:        os.Getenv("APP_CLIENT_SECRET"),
		RedirectURI:         getenv("APP_REDIRECT_URI", "http://localhost:5020/auth/callback"),
		InternalAuthToken:   os.Getenv("INTERNAL_AUTH_TOKEN"),
		SessionTTL:          getenvDuration("APP_SESSION_TTL", 12*time.Hour),
		CookieSecure:        os.Getenv("COOKIE_SECURE") == "true",
		AppID:               os.Getenv("APP_ID"),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
