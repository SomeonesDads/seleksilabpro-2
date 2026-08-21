package handlers

import (
	"context"
	"log/slog"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/metrics"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/google/uuid"
)

type UserStore interface {
	FindByEmail(context.Context, string) (*models.User, error)
	VerifyPassword(context.Context, string, string) (*models.User, bool, error)
}

type UserProfileStore interface {
	FindByID(context.Context, uuid.UUID) (*models.User, error)
}

type MFAStore interface {
	Create(context.Context, *models.MFALoginChallenge) error
	FindActiveByToken(context.Context, string, int) (*models.MFALoginChallenge, error)
	ClaimAttempt(context.Context, uuid.UUID, int) (bool, error)
	ConsumeAndCreateSession(context.Context, uuid.UUID, *models.SSOSession, int) error
}

type TOTPStore interface {
	FindByUserID(context.Context, uuid.UUID) (*models.UserTOTP, error)
	EnrollPending(context.Context, uuid.UUID, []byte) error
	Confirm(context.Context, uuid.UUID) error
	ClaimEnrollAttempt(context.Context, uuid.UUID, int, time.Duration) (bool, error)
	RecordEnrollFailure(context.Context, uuid.UUID, int, time.Duration) (bool, error)
	ResetEnrollAttempts(context.Context, uuid.UUID) error
}

type ApplicationStore interface {
	FindByClientID(context.Context, string) (*models.Application, error)
	HasExactRedirectURI(context.Context, uuid.UUID, string) (bool, error)
	VerifyClientSecret(context.Context, string, string) (bool, error)
}

type PolicyStore interface {
	UserHasApplicationAccess(context.Context, uuid.UUID, uuid.UUID) (bool, error)
	GroupsAllowedForApplication(context.Context, uuid.UUID, uuid.UUID) ([]string, error)
}

type SessionStore interface {
	Create(context.Context, *models.SSOSession) error
}

type SessionLookupStore interface {
	FindActiveByTokenHash(context.Context, string) (*models.SSOSession, error)
	FindActiveByID(context.Context, uuid.UUID) (*models.SSOSession, error)
}

type SessionRevocationStore interface {
	RevokeAndCreateEvent(context.Context, uuid.UUID, string) error
}

type AuthorizationCodeStore interface {
	Create(context.Context, *models.AuthorizationCode) error
	FindByHash(context.Context, string) (*models.AuthorizationCode, error)
	ConsumeAtomically(context.Context, uuid.UUID) error
}

type AuthorizationCodeRedemptionStore interface {
	Redeem(context.Context, uuid.UUID, *models.AccessToken) error
}

type AuditStore interface {
	WriteAuditLog(context.Context, *models.AuditLog) error
}

type AccessTokenStore interface {
	Create(context.Context, *models.AccessToken) error
	FindActiveByJTI(context.Context, uuid.UUID) (*models.AccessToken, error)
}

type GroupStore interface {
	FindByUserID(context.Context, uuid.UUID) ([]models.Group, error)
}

type AdminUserStore interface {
	List(context.Context) ([]models.User, error)
	FindByID(context.Context, uuid.UUID) (*models.User, error)
	CreateUser(context.Context, string, string, string, string) (*models.User, error)
	UpdateUser(context.Context, uuid.UUID, *string, *string, *string) (*models.User, error)
	UpdateUserAndRevoke(context.Context, uuid.UUID, *string, *string, *string) (*models.User, error)
	SetStatus(context.Context, uuid.UUID, string) error
}

type AdminGroupStore interface {
	List(context.Context) ([]models.Group, error)
	FindByUserID(context.Context, uuid.UUID) ([]models.Group, error)
	Create(context.Context, *models.Group) error
	AddUser(context.Context, uuid.UUID, uuid.UUID) error
	RemoveUser(context.Context, uuid.UUID, uuid.UUID) error
}

type AdminApplicationStore interface {
	List(context.Context) ([]models.Application, error)
	CreateWithSecret(context.Context, *models.Application, string) error
	CreateWithSecretAndRedirect(context.Context, *models.Application, string, string) error
	AddRedirectURI(context.Context, *models.ApplicationRedirectURI) error
}

type AdminPolicyStore interface {
	Set(context.Context, *models.ApplicationGroupPolicy) error
	ListByApplication(context.Context, uuid.UUID) ([]models.ApplicationGroupPolicy, error)
	Delete(context.Context, uuid.UUID, uuid.UUID) error
}

type AdminSessionStore interface {
	RevokeAllForUser(context.Context, uuid.UUID, string) error
	SetUserStatusAndRevoke(context.Context, uuid.UUID, string, string) error
}

// AuthRepositories is the synchronous server dependency boundary. Handlers
// coordinate these stores; SQL and security-critical predicates stay inside
// repository implementations.
type AuthRepositories struct {
	Users             UserStore
	UserProfiles      UserProfileStore
	MFA               MFAStore
	TOTP              TOTPStore
	Applications      ApplicationStore
	Policies          PolicyStore
	Sessions          SessionStore
	SessionLookup     SessionLookupStore
	SessionRevocation SessionRevocationStore
	AuthorizationCode AuthorizationCodeStore
	TokenRedemption   AuthorizationCodeRedemptionStore
	Audit             AuditStore
	AccessTokens      AccessTokenStore
	Groups            GroupStore
}

type AdminRepositories struct {
	Users        AdminUserStore
	Groups       AdminGroupStore
	Applications AdminApplicationStore
	Policies     AdminPolicyStore
	Sessions     AdminSessionStore
	Audit        AuditStore
}

type AuthHandlerConfig struct {
	AuthCodeTTL      time.Duration
	AccessTokenTTL   time.Duration
	SessionTTL       time.Duration
	JWTIssuer        string
	JWTSigningKey    []byte
	TokenStrategy    string
	MFAEncryptionKey []byte
	SecureCookies    *bool
}

const (
	defaultAuthCodeTTL    = 3 * time.Minute
	defaultAccessTokenTTL = 15 * time.Minute
	defaultSessionTTL     = 12 * time.Hour
	defaultJWTIssuer      = "auth-provider"
	defaultTokenStrategy  = "jwt"
)

func (c AuthHandlerConfig) withDefaults() AuthHandlerConfig {
	if c.AuthCodeTTL <= 0 {
		c.AuthCodeTTL = defaultAuthCodeTTL
	}
	if c.AccessTokenTTL <= 0 {
		c.AccessTokenTTL = defaultAccessTokenTTL
	}
	if c.SessionTTL <= 0 {
		c.SessionTTL = defaultSessionTTL
	}
	if c.JWTIssuer == "" {
		c.JWTIssuer = defaultJWTIssuer
	}
	if c.TokenStrategy == "" {
		c.TokenStrategy = defaultTokenStrategy
	}
	if c.SecureCookies == nil {
		secure := true
		c.SecureCookies = &secure
	}
	c.JWTSigningKey = append([]byte(nil), c.JWTSigningKey...)
	return c
}

func NewAuthHandlerWithDependencies(repos AuthRepositories, cfg AuthHandlerConfig, logger *slog.Logger) *AuthHandler {
	cfg = cfg.withDefaults()
	if logger == nil {
		logger = slog.Default()
	}
	tokenRedemption := repos.TokenRedemption
	if tokenRedemption == nil {
		tokenRedemption = authorizationCodeRedemption(repos.AuthorizationCode)
	}
	return &AuthHandler{
		Users:              repos.Users,
		UserProfiles:       repos.UserProfiles,
		MFA:                repos.MFA,
		TOTP:               repos.TOTP,
		Applications:       repos.Applications,
		Policies:           repos.Policies,
		Sessions:           repos.Sessions,
		SessionLookup:      repos.SessionLookup,
		SessionRevocation:  repos.SessionRevocation,
		AuthorizationCodes: repos.AuthorizationCode,
		TokenRedemption:    tokenRedemption,
		Audit:              repos.Audit,
		AccessTokens:       repos.AccessTokens,
		Groups:             repos.Groups,
		Logger:             logger,
		AuthCodeTTL:        cfg.AuthCodeTTL,
		AccessTokenTTL:     cfg.AccessTokenTTL,
		SessionTTL:         cfg.SessionTTL,
		JWTIssuer:          cfg.JWTIssuer,
		JWTSigningKey:      cfg.JWTSigningKey,
		TokenStrategy:      cfg.TokenStrategy,
		MFAEncryptionKey:   append([]byte(nil), cfg.MFAEncryptionKey...),
		SecureCookies:      *cfg.SecureCookies,
		Metrics:            metrics.New(nil),
	}
}

func authorizationCodeRedemption(store AuthorizationCodeStore) AuthorizationCodeRedemptionStore {
	redeemer, _ := store.(AuthorizationCodeRedemptionStore)
	return redeemer
}
