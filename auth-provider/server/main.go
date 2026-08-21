package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/config"
	appdb "github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/db"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/handlers"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/metrics"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/mfa"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/middleware"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/repository"
	"github.com/SomeonesDads/seleksilabpro-2/shared/logging"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gorm.io/gorm"
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
		AuthCodeTTL:      cfg.AuthCodeTTL,
		AccessTokenTTL:   cfg.AccessTokenTTL,
		SessionTTL:       cfg.SSOSessionTTL,
		JWTIssuer:        cfg.JWTIssuer,
		JWTSigningKey:    []byte(cfg.JWTSigningKey),
		TokenStrategy:    cfg.TokenStrategy,
		MFAEncryptionKey: cfg.MFAEncryptionKey,
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
	healthH.BrokerURL = cfg.BrokerURL

	metricsInstance := metrics.New(nil)
	authH.Metrics = metricsInstance
	healthH.Metrics = metricsInstance

	// Refresh dependency-health and outbox-depth gauges once at startup and
	// then periodically so the metrics endpoint reflects real runtime state
	// immediately rather than only after the first tick.
	updateRuntimeMetrics(ctx, logger, gormDB, pool, metricsInstance)
	runtimeMetricsDone := make(chan struct{})
	go func() {
		defer close(runtimeMetricsDone)
		refreshRuntimeMetrics(ctx, logger, gormDB, pool, metricsInstance)
	}()

	mux := http.NewServeMux()

	// --- Synchronous OAuth2 / central session flow ---
	mux.HandleFunc("GET /login", authH.LoginPage)
	mux.HandleFunc("POST /login", authH.Login)
	mux.HandleFunc("POST /login/mfa", authH.LoginMFA)
	mux.HandleFunc("POST /mfa/enroll", authH.EnrollMFA)
	mux.HandleFunc("GET /mfa/enroll", authH.MFASettingsPage)
	mux.HandleFunc("POST /mfa/enroll/confirm", authH.ConfirmMFAEnrollment)
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
	adminMux.HandleFunc("DELETE /admin/applications/{id}/policies", adminH.DeleteApplicationGroupPolicy)
	adminMux.HandleFunc("GET /admin/overview/{userId}", adminH.GetUserStatusOverview)
	mux.Handle("/admin/", middleware.RequireAdminWithAuthenticator(sessionRepo, adminMux))

	// --- Health ---
	mux.HandleFunc("GET /health", healthH.Health)
	mux.HandleFunc("GET /health/live", healthH.Live)
	mux.HandleFunc("GET /health/ready", healthH.Ready)

	// --- Metrics (B02) ---
	mux.Handle("GET /metrics", promhttp.Handler())

	var handler http.Handler = mux
	handler = metricsInstance.Middleware(handler)
	handler = middleware.RequestLogger(logger)(handler)
	handler = logging.WithRequestID(handler)

	gs := newGracefulServer(":"+cfg.Port, handler)
	gs.metricsDone = runtimeMetricsDone
	gs.run(logger)
	drained, err := gs.shutdown(ctx, cfg.ShutdownTimeout, logger)
	if err != nil {
		logger.Error("graceful drain failed", slog.Any("err", err))
	}

	// The server runs no broker consumer or publisher of its own: the
	// transactional-outbox publisher and event consumer live in the
	// sync-worker process (DECISIONS 017/020). After every in-flight request
	// has finished (or been cancelled and joined) we close the database
	// connections. If a handler ignored cancellation past the deadline we do
	// NOT close the pool underneath it; we let the process exit and the OS
	// reclaim the connections instead.
	if drained {
		if err := sqlDB.Close(); err != nil {
			logger.Error("gorm db close failed", slog.Any("err", err))
		}
		pool.Close()
		logger.Info("shutdown complete")
	} else {
		logger.Error("shutdown incomplete: database connections left open for the OS to reclaim")
	}
}

// gracefulServer wraps http.Server with in-flight request tracking and a
// cancelable base context. http.Server.Shutdown stops accepting new
// connections but does NOT cancel active request contexts, so after the drain
// timeout handlers can still be running against the database. gracefulServer
// forces those requests to cancel (via the base context) and waits for them to
// return before the caller tears down shared resources such as the connection
// pool.
type gracefulServer struct {
	srv         *http.Server
	wg          sync.WaitGroup
	baseCtx     context.Context
	cancel      context.CancelFunc
	metricsDone <-chan struct{}
}

func newGracefulServer(addr string, handler http.Handler) *gracefulServer {
	baseCtx, cancel := context.WithCancel(context.Background())
	gs := &gracefulServer{baseCtx: baseCtx, cancel: cancel}
	gs.srv = &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gs.wg.Add(1)
			defer gs.wg.Done()
			ctx, c := context.WithCancel(baseCtx)
			defer c()
			handler.ServeHTTP(w, r.WithContext(ctx))
		}),
	}
	return gs
}

func (gs *gracefulServer) run(logger *slog.Logger) {
	go func() {
		logger.Info("listening", slog.String("addr", gs.srv.Addr))
		if err := gs.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", slog.Any("err", err))
			os.Exit(1)
		}
	}()
}

// shutdown blocks until a shutdown signal, then drains in-flight requests
// within a hard wall-clock deadline (signal time + shutdownTimeout). A small
// finalization reserve is carved inside that deadline: the graceful drain gets
// the remaining time, then the base context is cancelled and handlers are
// joined within the reserve. It returns whether all handlers finished; if a
// handler ignores cancellation past the deadline the caller must NOT close the
// database underneath it.
func (gs *gracefulServer) shutdown(signalCtx context.Context, shutdownTimeout time.Duration, logger *slog.Logger) (bool, error) {
	<-signalCtx.Done()
	logger.Info("shutdown signal received, draining in-flight requests")

	// Hard deadline for the whole shutdown.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	// Reserve a small finalization window; the graceful drain uses the rest.
	reserve := finalizationReserve(shutdownTimeout)
	drainDeadline := time.Now().Add(shutdownTimeout - reserve)
	drainCtx, drainCancel := context.WithDeadline(shutdownCtx, drainDeadline)
	err := gs.srv.Shutdown(drainCtx)
	drainCancel()
	if err != nil {
		logger.Error("graceful drain timed out, forcing in-flight requests to cancel", slog.Any("err", err))
	}

	// Cancel any request still running so its database work stops before the
	// connection pool is closed.
	gs.cancel()

	// Join the now-cancelled handlers inside the finalization reserve (the
	// remaining hard deadline); a handler mid-DB-call is not raced by teardown.
	done := make(chan struct{})
	go func() {
		gs.wg.Wait()
		if gs.metricsDone != nil {
			<-gs.metricsDone
		}
		close(done)
	}()
	select {
	case <-done:
		logger.Info("all in-flight requests finished")
		return true, err
	case <-shutdownCtx.Done():
		logger.Error("forced in-flight wait exceeded budget; skipping DB close to avoid racing in-flight requests")
		return false, err
	}
}

// finalizationReserve returns the small slice of the shutdown budget reserved
// for joining cancelled handlers, capped so it stays a small finalization
// window rather than eating the graceful-drain time.
func finalizationReserve(timeout time.Duration) time.Duration {
	r := timeout / 4
	if r > 2*time.Second {
		r = 2 * time.Second
	}
	if r <= 0 {
		r = timeout
	}
	return r
}

// refreshRuntimeMetrics periodically updates the database-health and
// outbox-depth gauges so /metrics reflects live state without coupling the
// metrics package to the database.
func refreshRuntimeMetrics(ctx context.Context, logger *slog.Logger, db *gorm.DB, pool *pgxpool.Pool, m *metrics.Metrics) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			updateRuntimeMetrics(ctx, logger, db, pool, m)
		}
	}
}

// updateRuntimeMetrics performs one refresh of the dependency-health and
// outbox-depth gauges. Exposed so startup can populate them immediately.
func updateRuntimeMetrics(ctx context.Context, logger *slog.Logger, db *gorm.DB, pool *pgxpool.Pool, m *metrics.Metrics) {
	up := pool.Ping(ctx) == nil
	m.SetDBHealth(up)
	if !up {
		return
	}
	var depth int64
	if err := db.WithContext(ctx).Table("events").Where("published_at IS NULL").Count(&depth).Error; err != nil {
		logger.Debug("outbox depth refresh failed", slog.Any("err", err))
		return
	}
	m.SetOutboxDepth(depth)
}
