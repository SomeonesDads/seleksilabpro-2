package main

import (
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/applications/app-a/internal/auth"
	"github.com/SomeonesDads/seleksilabpro-2/applications/app-a/internal/config"
	"github.com/SomeonesDads/seleksilabpro-2/applications/app-a/internal/db"
	"github.com/SomeonesDads/seleksilabpro-2/applications/app-a/internal/handlers"
	"github.com/SomeonesDads/seleksilabpro-2/applications/app-a/internal/store"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func main() {
	cfg := config.Get()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if cfg.DatabaseURL == "" {
		logger.Error("DATABASE_URL is required")
		os.Exit(1)
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		logger.Error("APP_CLIENT_ID and APP_CLIENT_SECRET are required")
		os.Exit(1)
	}
	if cfg.AppID == "" {
		logger.Error("APP_ID is required (the application's UUID at the Auth Provider)")
		os.Exit(1)
	}
	if _, err := uuid.Parse(cfg.AppID); err != nil {
		logger.Error("APP_ID must be a valid UUID", "err", err)
		os.Exit(1)
	}

	gormDB, err := openDB(cfg.DatabaseURL)
	if err != nil {
		logger.Error("database connection failed", "err", err)
		os.Exit(1)
	}
	st := store.New(gormDB)
	if err := st.AutoMigrate(); err != nil {
		logger.Error("migration failed", "err", err)
		os.Exit(1)
	}

	provider := auth.NewClient(cfg.AuthProviderBaseURL, cfg.ClientID, cfg.ClientSecret)
	app := handlers.NewApp(cfg, st, provider)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", app.Home)
	mux.HandleFunc("GET /login", app.Login)
	mux.HandleFunc("GET /auth/callback", app.Callback)
	mux.HandleFunc("POST /logout", app.Logout)
	mux.HandleFunc("POST /internal/logout", app.InternalLogout)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	logger.Info("app-a listening", "port", cfg.Port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func openDB(dsn string) (*gorm.DB, error) {
	return db.Open(dsn, nil)
}



