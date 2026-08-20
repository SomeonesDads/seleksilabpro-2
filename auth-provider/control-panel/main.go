package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/control-panel/internal/config"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/control-panel/internal/handlers"
	"github.com/SomeonesDads/seleksilabpro-2/shared/logging"
)

func main() {
	logger := logging.NewLogger("control-panel")

	cfg, err := config.Load()
	if err != nil {
		logger.Error("config load failed", slog.Any("err", err))
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	h := handlers.NewPanelHandler(cfg.AuthServerURL, cfg.SessionCookieName, logger)

	mux := http.NewServeMux()
	// Auth (control-panel session bootstrap, forwards central-session cookie).
	mux.HandleFunc("GET /login", h.LoginPage)
	mux.HandleFunc("POST /login", h.Login)
	mux.HandleFunc("POST /login/mfa", h.LoginMFA)
	mux.HandleFunc("GET /logout", h.Logout)
	mux.HandleFunc("POST /logout", h.Logout)
	// Dashboard + resource pages.
	mux.HandleFunc("GET /", h.Dashboard)
	mux.HandleFunc("GET /users", h.Users)
	mux.HandleFunc("GET /users/{id}", h.UserOverview)
	mux.HandleFunc("GET /groups", h.Groups)
	mux.HandleFunc("GET /applications", h.Applications)
	// Mutations (proxy to Auth Provider /admin/* API).
	mux.HandleFunc("POST /users", h.CreateUser)
	mux.HandleFunc("POST /users/status", h.SetUserStatus)
	mux.HandleFunc("POST /groups", h.CreateGroup)
	mux.HandleFunc("POST /groups/members", h.AddGroupMember)
	mux.HandleFunc("POST /groups/members/delete", h.RemoveGroupMember)
	mux.HandleFunc("POST /applications", h.CreateApplication)
	mux.HandleFunc("POST /applications/redirect", h.AddRedirectURI)
	mux.HandleFunc("POST /applications/policies", h.AddApplicationPolicy)
	mux.HandleFunc("POST /applications/policies/delete", h.DeleteApplicationPolicy)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	var handler http.Handler = mux
	handler = logging.WithRequestID(handler)

	srv := &http.Server{Addr: ":" + cfg.Port, Handler: handler}

	go func() {
		logger.Info("listening", slog.String("addr", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", slog.Any("err", err))
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	logger.Info("shutdown complete")
}
