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

	h := handlers.NewPanelHandler(cfg.AuthServerURL)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", h.Dashboard)
	mux.HandleFunc("GET /users", h.Users)
	mux.HandleFunc("GET /groups", h.Groups)
	mux.HandleFunc("GET /applications", h.Applications)
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
