package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/config"
	appdb "github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/db"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/handlers"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/mfa"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/middleware"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/repository"
	"github.com/SomeonesDads/seleksilabpro-2/shared/logging"
)

func main() {
	logger := logging.NewLogger("auth-provider-server")

	cfg, err := config.Load()
	if err != nil {
		logger.Error("config load failed", slog.Any("err", err))
		os.Exit(1)
	}

	// Graceful shutdown (Defer harusny udh memenuhin)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	pool, err := appdb.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("db connect failed", slog.Any("err", err))
		os.Exit(1)
	}
	defer pool.Close()

	if err := appdb.RunMigrations(ctx, cfg.DatabaseURL, "migrations"); err != nil {
		logger.Error("migrations failed", slog.Any("err", err))
		os.Exit(1)
	}
	logger.Info("migrations applied")

	gormDB, err := appdb.ConnectGORM(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("gorm connect failed", slog.Any("err", err))
		os.Exit(1)
	}
	sqlDB, err := gormDB.DB()
	if err != nil {
		logger.Error("gorm sql db failed", slog.Any("err", err))
		os.Exit(1)
	}
	defer sqlDB.Close()

	userRepo := repository.NewUserRepository(gormDB)
	mfaRepo := repository.NewMFARepository(gormDB)
	totpRepo := repository.NewTOTPRepository(gormDB)
	applicationRepo := repository.NewApplicationRepository(gormDB)
	policyRepo := repository.NewPolicyRepository(gormDB)
	sessionRepo := repository.NewSessionRepository(gormDB)
	authorizationCodeRepo := repository.NewAuthorizationCodeRepository(gormDB)
	auditRepo := repository.NewAuditRepository(gormDB)
	accessTokenRepo := repository.NewAccessTokenRepository(gormDB)
	groupRepo := repository.NewGroupRepository(gormDB)

	authH := handlers.NewAuthHandlerWithDependencies(handlers.AuthRepositories{
		Users:             userRepo,
		UserProfiles:      userRepo,
		MFA:               mfaRepo,
		TOTP:              totpRepo,
		Applications:      applicationRepo,
		Policies:          policyRepo,
		Sessions:          sessionRepo,
		SessionLookup:     sessionRepo,
		SessionRevocation: sessionRepo,
		AuthorizationCode: authorizationCodeRepo,
		TokenRedemption:   authorizationCodeRepo,
		Audit:             auditRepo,
		AccessTokens:      accessTokenRepo,
		Groups:            groupRepo,
	}, handlers.AuthHandlerConfig{
		AuthCodeTTL:    cfg.AuthCodeTTL,
		AccessTokenTTL: cfg.AccessTokenTTL,
		SessionTTL:     cfg.SSOSessionTTL,
		JWTIssuer:      cfg.JWTIssuer,
		JWTSigningKey:  []byte(cfg.JWTSigningKey),
		TokenStrategy:  cfg.TokenStrategy,
	}, logger)
	authH.VerifyMFA = mfa.NewTOTPVerifier(totpRepo, cfg.MFAEncryptionKey).Verify
	adminH := handlers.NewAdminHandler(handlers.AdminRepositories{
		Users:        userRepo,
		Groups:       groupRepo,
		Applications: applicationRepo,
		Policies:     policyRepo,
		Sessions:     sessionRepo,
		Audit:        auditRepo,
	}, logger)
	healthH := handlers.NewHealthHandler(pool)

	mux := http.NewServeMux()

	// --- Synchronous OAuth2 / central session flow ---
	mux.HandleFunc("GET /login", authH.LoginPage)
	mux.HandleFunc("POST /login", authH.Login)
	mux.HandleFunc("POST /login/mfa", authH.LoginMFA)
	mux.HandleFunc("GET /authorize", authH.Authorize)
	mux.HandleFunc("POST /token", authH.Token)
	mux.HandleFunc("GET /userinfo", authH.UserInfo)
	mux.HandleFunc("POST /logout", authH.Logout)

	// --- Admin API (consumed by the control-panel service) ---
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("GET /admin/users", adminH.ListUsers)
	adminMux.HandleFunc("POST /admin/users", adminH.CreateUser)
	adminMux.HandleFunc("GET /admin/users/{id}", adminH.GetUser)
	adminMux.HandleFunc("PATCH /admin/users/{id}", adminH.UpdateUser)
	adminMux.HandleFunc("PATCH /admin/users/{id}/status", adminH.SetUserStatus)
	adminMux.HandleFunc("GET /admin/groups", adminH.ListGroups)
	adminMux.HandleFunc("POST /admin/groups", adminH.CreateGroup)
	adminMux.HandleFunc("POST /admin/groups/{id}/members", adminH.AddUserToGroup)
	adminMux.HandleFunc("DELETE /admin/groups/{id}/members/{userId}", adminH.RemoveUserFromGroup)
	adminMux.HandleFunc("GET /admin/applications", adminH.ListApplications)
	adminMux.HandleFunc("POST /admin/applications", adminH.CreateApplication)
	adminMux.HandleFunc("POST /admin/applications/{id}/redirect-uris", adminH.AddRedirectURI)
	adminMux.HandleFunc("POST /admin/applications/{id}/policies", adminH.SetApplicationGroupPolicy)
	adminMux.HandleFunc("GET /admin/overview/{userId}", adminH.GetUserStatusOverview)
	mux.Handle("/admin/", middleware.RequireAdminWithAuthenticator(sessionRepo, adminMux))

	// --- Health ---
	mux.HandleFunc("GET /health", healthH.Health)
	mux.HandleFunc("GET /health/live", healthH.Live)
	mux.HandleFunc("GET /health/ready", healthH.Ready)

	// TODO [B02]: mount promhttp.Handler() at GET /metrics once you wire up
	// prometheus/client_golang counters/histograms in the handlers above.

	var handler http.Handler = mux
	handler = middleware.RequestLogger(logger)(handler)
	handler = logging.WithRequestID(handler)

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: handler,
	}

	go func() {
		logger.Info("listening", slog.String("addr", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", slog.Any("err", err))
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	logger.Info("shutdown signal received, draining in-flight requests")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", slog.Any("err", err))
	}
	// TODO [B04]: also stop consuming from the broker here and close the
	// AMQP connection cleanly before the process exits.
	logger.Info("shutdown complete")
}
