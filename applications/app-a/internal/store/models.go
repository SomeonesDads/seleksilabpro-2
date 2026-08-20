package store

import (
	"time"

	"github.com/google/uuid"
)

// LocalSession is App A's independent session. It stores ONLY a hash of the
// browser session token, the Auth Provider user reference, the originating
// central session id, the (constant) application id, and status/timestamps.
// It never stores passwords, password hashes, client secrets, the raw
// Auth Provider access token, the raw session token, or redeemed codes.
type LocalSession struct {
	ID                 uuid.UUID `gorm:"type:uuid;primaryKey"`
	SessionTokenHash   string    `gorm:"size:64;index"`
	ExternalUserID     string    `gorm:"size:64;index"`
	CentralSessionID   string    `gorm:"size:64;index"`
	ApplicationID      string    `gorm:"size:64;index"`
	Status             string    `gorm:"size:16"`
	CreatedAt          time.Time
	ExpiresAt          time.Time
	LastActivityAt     *time.Time
	RevokedAt          *time.Time
	RevokeReason       string `gorm:"size:32"`
}

func (LocalSession) TableName() string { return "local_sessions" }

// ProfileCache holds the identity App A received from Auth Provider /userinfo.
// It is a cache, not the source of truth, and holds no credentials.
type ProfileCache struct {
	ExternalUserID string   `gorm:"size:64;primaryKey"`
	Name           string   `gorm:"size:255"`
	Email          string   `gorm:"size:255"`
	Groups         string   `gorm:"type:text"`
	SyncedAt       time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (ProfileCache) TableName() string { return "profile_cache" }

// ProcessedEvent makes revocation events idempotent. A duplicate eventId is
// acknowledged without repeating the revocation work.
type ProcessedEvent struct {
	EventID    uuid.UUID `gorm:"type:uuid;primaryKey"`
	EventType  string    `gorm:"size:32"`
	ProcessedAt time.Time
	Result     string    `gorm:"size:64"`
}

func (ProcessedEvent) TableName() string { return "processed_events" }

// ActivityLog records the lifecycle events App A goes through for auditing and
// display. It never stores sensitive values.
type ActivityLog struct {
	ID            uuid.UUID  `gorm:"type:uuid;primaryKey"`
	LocalSessionID *uuid.UUID `gorm:"type:uuid"`
	Kind          string     `gorm:"size:32"`
	Message       string     `gorm:"size:512"`
	CorrelationID string     `gorm:"size:64"`
	CreatedAt     time.Time
}

func (ActivityLog) TableName() string { return "activity_logs" }
