package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID           uuid.UUID `gorm:"column:id;type:uuid;default:gen_random_uuid();primaryKey"`
	Name         string    `gorm:"column:name;type:varchar(255);not null"`
	Email        string    `gorm:"column:email;type:varchar(320);not null;uniqueIndex"`
	PasswordHash string    `gorm:"column:password_hash;type:varchar(255);not null"`
	Status       string    `gorm:"column:status;type:varchar(20);not null;default:active"`
	CreatedAt    time.Time `gorm:"column:created_at;not null"`
	UpdatedAt    time.Time `gorm:"column:updated_at;not null"`
}

func (User) TableName() string { return "users" }
func (u User) IsActive() bool  { return u.Status == "active" }

type Group struct {
	ID          uuid.UUID `gorm:"column:id;type:uuid;default:gen_random_uuid();primaryKey"`
	Name        string    `gorm:"column:name;type:varchar(255);not null;uniqueIndex"`
	Description *string   `gorm:"column:description;type:text"`
	CreatedAt   time.Time `gorm:"column:created_at;not null"`
	UpdatedAt   time.Time `gorm:"column:updated_at;not null"`
}

func (Group) TableName() string { return "groups" }

type UserGroup struct {
	ID        uuid.UUID `gorm:"column:id;type:uuid;default:gen_random_uuid();primaryKey"`
	UserID    uuid.UUID `gorm:"column:user_id;type:uuid;not null"`
	GroupID   uuid.UUID `gorm:"column:group_id;type:uuid;not null"`
	CreatedAt time.Time `gorm:"column:created_at;not null"`
}

func (UserGroup) TableName() string { return "user_groups" }

type Application struct {
	ID                    uuid.UUID `gorm:"column:id;type:uuid;default:gen_random_uuid();primaryKey"`
	Name                  string    `gorm:"column:name;type:varchar(255);not null"`
	ClientID              string    `gorm:"column:client_id;type:varchar(255);not null;uniqueIndex"`
	ClientSecretHash      *string   `gorm:"column:client_secret_hash;type:varchar(255)"`
	Status                string    `gorm:"column:status;type:varchar(20);not null;default:active"`
	LaunchURL             *string   `gorm:"column:launch_url;type:text"`
	LogoutNotificationURL string    `gorm:"column:logout_notification_url;type:text;not null"`
	CreatedAt             time.Time `gorm:"column:created_at;not null"`
	UpdatedAt             time.Time `gorm:"column:updated_at;not null"`
}

func (Application) TableName() string { return "applications" }
func (a Application) IsActive() bool  { return a.Status == "active" }

type ApplicationRedirectURI struct {
	ID            uuid.UUID `gorm:"column:id;type:uuid;default:gen_random_uuid();primaryKey"`
	ApplicationID uuid.UUID `gorm:"column:application_id;type:uuid;not null"`
	RedirectURI   string    `gorm:"column:redirect_uri;type:text;not null"`
	CreatedAt     time.Time `gorm:"column:created_at;not null"`
}

func (ApplicationRedirectURI) TableName() string { return "application_redirect_uris" }

type ApplicationGroupPolicy struct {
	ID            uuid.UUID `gorm:"column:id;type:uuid;default:gen_random_uuid();primaryKey"`
	ApplicationID uuid.UUID `gorm:"column:application_id;type:uuid;not null"`
	GroupID       uuid.UUID `gorm:"column:group_id;type:uuid;not null"`
	Effect        string    `gorm:"column:effect;type:varchar(20);not null;default:allow"`
	CreatedAt     time.Time `gorm:"column:created_at;not null"`
}

func (ApplicationGroupPolicy) TableName() string { return "application_group_policies" }

type SSOSession struct {
	ID               uuid.UUID  `gorm:"column:id;type:uuid;default:gen_random_uuid();primaryKey"`
	UserID           uuid.UUID  `gorm:"column:user_id;type:uuid;not null"`
	SessionTokenHash string     `gorm:"column:session_token_hash;type:varchar(255);not null;uniqueIndex"`
	Status           string     `gorm:"column:status;type:varchar(20);not null;default:active"`
	CreatedAt        time.Time  `gorm:"column:created_at;not null"`
	ExpiresAt        time.Time  `gorm:"column:expires_at;not null"`
	LastActivityAt   *time.Time `gorm:"column:last_activity_at"`
	RevokedAt        *time.Time `gorm:"column:revoked_at"`
	RevokeReason     *string    `gorm:"column:revoke_reason;type:varchar(100)"`
	IPAddress        *string    `gorm:"column:ip_address;type:varchar(64)"`
	UserAgent        *string    `gorm:"column:user_agent;type:text"`
}

func (SSOSession) TableName() string { return "sso_sessions" }

func (s SSOSession) IsValid(now time.Time) bool {
	return s.Status == "active" && now.Before(s.ExpiresAt) && s.RevokedAt == nil
}

type MFALoginChallenge struct {
	ID        uuid.UUID  `gorm:"column:id;type:uuid;default:gen_random_uuid();primaryKey"`
	UserID    uuid.UUID  `gorm:"column:user_id;type:uuid;not null"`
	TokenHash string     `gorm:"column:token_hash;type:varchar(255);not null;uniqueIndex"`
	ExpiresAt time.Time  `gorm:"column:expires_at;not null"`
	Attempts  int        `gorm:"column:attempts;not null;default:0"`
	UsedAt    *time.Time `gorm:"column:used_at"`
	CreatedAt time.Time  `gorm:"column:created_at;not null"`
}

func (MFALoginChallenge) TableName() string { return "mfa_login_challenges" }

type UserTOTP struct {
	ID              uuid.UUID `gorm:"column:id;type:uuid;default:gen_random_uuid();primaryKey"`
	UserID          uuid.UUID `gorm:"column:user_id;type:uuid;not null;uniqueIndex"`
	EncryptedSecret []byte    `gorm:"column:encrypted_secret;type:bytea;not null"`
	Confirmed       bool      `gorm:"column:confirmed;not null;default:false"`
	CreatedAt       time.Time `gorm:"column:created_at;not null"`
	UpdatedAt       time.Time `gorm:"column:updated_at;not null"`
}

func (UserTOTP) TableName() string { return "user_totp_credentials" }

type AuthorizationCode struct {
	ID                  uuid.UUID  `gorm:"column:id;type:uuid;default:gen_random_uuid();primaryKey"`
	CodeHash            string     `gorm:"column:code_hash;type:varchar(255);not null;uniqueIndex"`
	UserID              uuid.UUID  `gorm:"column:user_id;type:uuid;not null"`
	ApplicationID       uuid.UUID  `gorm:"column:application_id;type:uuid;not null"`
	SSOSessionID        uuid.UUID  `gorm:"column:sso_session_id;type:uuid;not null"`
	RedirectURI         string     `gorm:"column:redirect_uri;type:text;not null"`
	CodeChallenge       string     `gorm:"column:code_challenge;type:varchar(255);not null"`
	CodeChallengeMethod string     `gorm:"column:code_challenge_method;type:varchar(10);not null;default:S256"`
	CreatedAt           time.Time  `gorm:"column:created_at;not null"`
	ExpiresAt           time.Time  `gorm:"column:expires_at;not null"`
	UsedAt              *time.Time `gorm:"column:used_at"`
}

func (AuthorizationCode) TableName() string { return "authorization_codes" }

// AccessToken stores revocation metadata for a JWT without storing the signed
// token itself. The jti is the token's stable denylist key.
type AccessToken struct {
	ID            uuid.UUID  `gorm:"column:id;type:uuid;default:gen_random_uuid();primaryKey"`
	JTI           uuid.UUID  `gorm:"column:jti;type:uuid;not null;uniqueIndex"`
	UserID        uuid.UUID  `gorm:"column:user_id;type:uuid;not null"`
	ApplicationID uuid.UUID  `gorm:"column:application_id;type:uuid;not null"`
	SessionID     uuid.UUID  `gorm:"column:session_id;type:uuid;not null"`
	ExpiresAt     time.Time  `gorm:"column:expires_at;not null"`
	RevokedAt     *time.Time `gorm:"column:revoked_at"`
	RevokeReason  *string    `gorm:"column:revoke_reason;type:varchar(100)"`
	CreatedAt     time.Time  `gorm:"column:created_at;not null"`
}

func (AccessToken) TableName() string { return "access_tokens" }

type AuditLog struct {
	ID            uuid.UUID      `gorm:"column:id;type:uuid;default:gen_random_uuid();primaryKey"`
	EventType     string         `gorm:"column:event_type;type:varchar(100);not null"`
	ActorID       *uuid.UUID     `gorm:"column:actor_id;type:uuid"`
	UserID        *uuid.UUID     `gorm:"column:user_id;type:uuid"`
	ApplicationID *uuid.UUID     `gorm:"column:application_id;type:uuid"`
	SessionID     *uuid.UUID     `gorm:"column:session_id;type:uuid"`
	Result        string         `gorm:"column:result;type:varchar(20);not null"`
	Metadata      map[string]any `gorm:"column:metadata;type:jsonb;serializer:json"`
	IPAddress     *string        `gorm:"column:ip_address;type:varchar(64)"`
	CreatedAt     time.Time      `gorm:"column:created_at;not null"`
}

func (AuditLog) TableName() string { return "audit_logs" }

const (
	EventSessionRevoked      = "SessionRevoked"
	EventPasswordChanged     = "PasswordChanged"
	EventAccessPolicyChanged = "AccessPolicyChanged"
)

type Event struct {
	ID               uuid.UUID      `gorm:"column:id;type:uuid;default:gen_random_uuid();primaryKey"`
	EventType        string         `gorm:"column:event_type;type:varchar(100);not null"`
	UserID           uuid.UUID      `gorm:"column:user_id;type:uuid;not null"`
	CentralSessionID *uuid.UUID     `gorm:"column:central_session_id;type:uuid"`
	ApplicationID    *uuid.UUID     `gorm:"column:application_id;type:uuid"`
	Payload          map[string]any `gorm:"column:payload;type:jsonb;not null;serializer:json"`
	Status           string         `gorm:"column:status;type:varchar(20);not null;default:pending"`
	CreatedAt        time.Time      `gorm:"column:created_at;not null"`
	PublishedAt      *time.Time     `gorm:"column:published_at"`
}

func (Event) TableName() string { return "events" }

type EventDelivery struct {
	ID            uuid.UUID  `gorm:"column:id;type:uuid;default:gen_random_uuid();primaryKey"`
	EventID       uuid.UUID  `gorm:"column:event_id;type:uuid;not null"`
	ApplicationID uuid.UUID  `gorm:"column:application_id;type:uuid;not null"`
	Status        string     `gorm:"column:status;type:varchar(20);not null;default:pending"`
	AttemptCount  int        `gorm:"column:attempt_count;not null;default:0"`
	LastAttemptAt *time.Time `gorm:"column:last_attempt_at"`
	NextRetryAt   *time.Time `gorm:"column:next_retry_at"`
	ProcessedAt   *time.Time `gorm:"column:processed_at"`
	LastError     *string    `gorm:"column:last_error;type:text"`
}

func (EventDelivery) TableName() string { return "event_deliveries" }
