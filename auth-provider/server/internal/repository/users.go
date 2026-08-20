package repository

import (
	"context"
	"errors"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var ErrUserNotFound = errors.New("user not found")
var ErrMFAChallengeNotFound = errors.New("MFA challenge not found")
var ErrTOTPNotFound = errors.New("TOTP credential not found")
var ErrTOTPAlreadyConfirmed = errors.New("TOTP credential already confirmed")

type UserRepository struct {
	db *gorm.DB
}

type MFARepository struct{ db *gorm.DB }

func NewMFARepository(db *gorm.DB) *MFARepository { return &MFARepository{db: db} }

func (r *MFARepository) Create(ctx context.Context, challenge *models.MFALoginChallenge) error {
	return r.db.WithContext(ctx).Create(challenge).Error
}

func (r *MFARepository) FindActiveByToken(ctx context.Context, tokenHash string, maxAttempts int) (*models.MFALoginChallenge, error) {
	var challenge models.MFALoginChallenge
	err := r.db.WithContext(ctx).
		Where("token_hash = ? AND used_at IS NULL AND expires_at > ? AND attempts < ?", tokenHash, time.Now(), maxAttempts).
		First(&challenge).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrMFAChallengeNotFound
	}
	if err != nil {
		return nil, err
	}
	return &challenge, nil
}

func (r *MFARepository) IncrementAttempts(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&models.MFALoginChallenge{}).
		Where("id = ? AND used_at IS NULL", id).
		UpdateColumn("attempts", gorm.Expr("attempts + 1")).Error
}

// ClaimAttempt atomically reserves one verification attempt. The caller must
// verify the MFA code after this succeeds; a failed code does not need a
// second increment.
func (r *MFARepository) ClaimAttempt(ctx context.Context, id uuid.UUID, maxAttempts int) (bool, error) {
	result := r.db.WithContext(ctx).Model(&models.MFALoginChallenge{}).
		Where("id = ? AND used_at IS NULL AND expires_at > ? AND attempts < ?", id, time.Now(), maxAttempts).
		UpdateColumn("attempts", gorm.Expr("attempts + 1"))
	if result.Error != nil {
		return false, result.Error
	}
	return result.RowsAffected == 1, nil
}

func (r *MFARepository) Consume(ctx context.Context, id uuid.UUID) error {
	result := r.db.WithContext(ctx).Model(&models.MFALoginChallenge{}).
		Where("id = ? AND used_at IS NULL AND expires_at > ?", id, time.Now()).
		Updates(map[string]any{"used_at": gorm.Expr("NOW()")})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrMFAChallengeNotFound
	}
	return nil
}

func (r *MFARepository) ConsumeAndCreateSession(ctx context.Context, id uuid.UUID, session *models.SSOSession, maxAttempts int) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&models.MFALoginChallenge{}).
			Where("id = ? AND used_at IS NULL AND expires_at > ? AND attempts <= ?", id, time.Now(), maxAttempts).
			Updates(map[string]any{"used_at": gorm.Expr("NOW()")})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrMFAChallengeNotFound
		}
		return tx.Create(session).Error
	})
}

type TOTPRepository struct{ db *gorm.DB }

func NewTOTPRepository(db *gorm.DB) *TOTPRepository { return &TOTPRepository{db: db} }

func (r *TOTPRepository) FindByUserID(ctx context.Context, userID uuid.UUID) (*models.UserTOTP, error) {
	var credential models.UserTOTP
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).First(&credential).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrTOTPNotFound
	}
	if err != nil {
		return nil, err
	}
	return &credential, nil
}

func (r *TOTPRepository) Upsert(ctx context.Context, credential *models.UserTOTP) error {
	var existing models.UserTOTP
	err := r.db.WithContext(ctx).Where("user_id = ?", credential.UserID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return r.db.WithContext(ctx).Create(credential).Error
	}
	if err != nil {
		return err
	}
	return r.db.WithContext(ctx).Model(&existing).Updates(map[string]any{
		"encrypted_secret": credential.EncryptedSecret,
	}).Error
}

// EnrollPending stores an unconfirmed TOTP credential. The encrypted secret is
// written but confirmed stays false until Confirm succeeds, so a pending
// enrollment never blocks login.
//
// A confirmed credential is never overwritten: visiting the enrollment page
// must not downgrade an active MFA to password-only. Callers that want to
// rotate a confirmed credential must first require current-MFA re-auth (not
// implemented here) and then start a fresh enrollment.
func (r *TOTPRepository) EnrollPending(ctx context.Context, userID uuid.UUID, encryptedSecret []byte) error {
	var existing models.UserTOTP
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return r.db.WithContext(ctx).Create(&models.UserTOTP{
			UserID:             userID,
			EncryptedSecret:    encryptedSecret,
			Confirmed:          false,
			EnrollAttempts:     0,
			EnrollLockedUntil:  nil,
		}).Error
	}
	if err != nil {
		return err
	}
	if existing.Confirmed {
		return ErrTOTPAlreadyConfirmed
	}
	return r.db.WithContext(ctx).Model(&existing).Updates(map[string]any{
		"encrypted_secret":    encryptedSecret,
		"confirmed":           false,
		"enroll_attempts":     0,
		"enroll_locked_until": nil,
	}).Error
}

// RecordEnrollFailure counts a failed MFA enrollment confirmation and locks
// further attempts once the bound is reached, mirroring the login-MFA attempt
// policy. locked reports whether the credential is now blocked until
// EnrollLockedUntil passes.
//
// The increment and lock assignment happen in a single conditional UPDATE so
// concurrent confirmations cannot read-then-overwrite the same attempt count
// (i.e. more than maxAttempts verifications can never succeed).
func (r *TOTPRepository) RecordEnrollFailure(ctx context.Context, userID uuid.UUID, maxAttempts int, lock time.Duration) (locked bool, err error) {
	now := time.Now()
	res := r.db.WithContext(ctx).Model(&models.UserTOTP{}).
		Where("user_id = ? AND (enroll_locked_until IS NULL OR enroll_locked_until < ?)", userID, now).
		Updates(map[string]any{
			"enroll_attempts": gorm.Expr("enroll_attempts + 1"),
			"enroll_locked_until": gorm.Expr(
				"CASE WHEN enroll_attempts + 1 >= ? THEN ? ELSE enroll_locked_until END",
				maxAttempts, now.Add(lock)),
		})
	if res.Error != nil {
		return false, res.Error
	}
	if res.RowsAffected == 0 {
		// No row updated: either the credential is missing or already locked.
		var exists int64
		if err := r.db.WithContext(ctx).Model(&models.UserTOTP{}).Where("user_id = ?", userID).Count(&exists).Error; err != nil {
			return false, err
		}
		if exists == 0 {
			return false, ErrTOTPNotFound
		}
		return true, nil
	}
	var totp models.UserTOTP
	if err := r.db.WithContext(ctx).Select("enroll_locked_until").Where("user_id = ?", userID).First(&totp).Error; err != nil {
		return false, err
	}
	return totp.EnrollLockedUntil != nil && totp.EnrollLockedUntil.After(time.Now()), nil
}

// ClaimEnrollAttempt atomically reserves one MFA enrollment-confirmation
// attempt before the TOTP code is verified, mirroring the login-MFA
// ClaimAttempt flow. The counter is incremented (and the lock set once the
// bound is reached) in a single conditional UPDATE, so concurrent
// confirmations cannot all pass a pre-check and verify before any reservation
// is recorded. allowed reports whether this attempt is permitted; when false
// the credential is locked and the caller must reject.
func (r *TOTPRepository) ClaimEnrollAttempt(ctx context.Context, userID uuid.UUID, maxAttempts int, lock time.Duration) (allowed bool, err error) {
	now := time.Now()
	res := r.db.WithContext(ctx).Model(&models.UserTOTP{}).
		Where("user_id = ? AND (enroll_locked_until IS NULL OR enroll_locked_until < ?)", userID, now).
		Updates(map[string]any{
			"enroll_attempts": gorm.Expr("enroll_attempts + 1"),
			"enroll_locked_until": gorm.Expr(
				"CASE WHEN enroll_attempts + 1 >= ? THEN ? ELSE enroll_locked_until END",
				maxAttempts, now.Add(lock)),
		})
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

// ResetEnrollAttempts clears the failure counter and lock after a successful
// enrollment confirmation.
func (r *TOTPRepository) ResetEnrollAttempts(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&models.UserTOTP{}).Where("user_id = ?", userID).
		Updates(map[string]any{"enroll_attempts": 0, "enroll_locked_until": nil}).Error
}

// Confirm marks the user's pending TOTP credential as active.
func (r *TOTPRepository) Confirm(ctx context.Context, userID uuid.UUID) error {
	res := r.db.WithContext(ctx).Model(&models.UserTOTP{}).
		Where("user_id = ?", userID).
		Updates(map[string]any{"confirmed": true})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrTOTPNotFound
	}
	return nil
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

// return 1 user dari emailny
func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).
		Where("email = ?", email).
		First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) List(ctx context.Context) ([]models.User, error) {
	var users []models.User
	err := r.db.WithContext(ctx).Order("created_at ASC").Find(&users).Error
	return users, err
}

func (r *UserRepository) CreateUser(ctx context.Context, name, email, password, status string) (*models.User, error) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	if status == "" {
		status = "active"
	}
	user := &models.User{Name: name, Email: email, PasswordHash: string(passwordHash), Status: status}
	if err := r.db.WithContext(ctx).Create(user).Error; err != nil {
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) UpdateUser(ctx context.Context, id uuid.UUID, name, email, password *string) (*models.User, error) {
	return r.updateUser(ctx, r.db.WithContext(ctx), id, name, email, password, false)
}

func (r *UserRepository) UpdateUserAndRevoke(ctx context.Context, id uuid.UUID, name, email, password *string) (*models.User, error) {
	var user *models.User
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		user, err = r.updateUser(ctx, tx, id, name, email, password, true)
		return err
	})
	if err != nil {
		return nil, err
	}
	return r.FindByID(ctx, user.ID)
}

func (r *UserRepository) updateUser(ctx context.Context, db *gorm.DB, id uuid.UUID, name, email, password *string, revokeSessions bool) (*models.User, error) {
	updates := make(map[string]any)
	if name != nil {
		updates["name"] = *name
	}
	if email != nil {
		updates["email"] = *email
	}
	if password != nil {
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(*password), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		updates["password_hash"] = string(passwordHash)
	}
	if len(updates) == 0 {
		return r.FindByID(ctx, id)
	}
	result := db.WithContext(ctx).Model(&models.User{}).Where("id = ?", id).Updates(updates)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected != 1 {
		return nil, ErrUserNotFound
	}
	if revokeSessions && password != nil {
		var sessions []models.SSOSession
		if err := db.WithContext(ctx).Where("user_id = ? AND status = ? AND revoked_at IS NULL", id, "active").Find(&sessions).Error; err != nil {
			return nil, err
		}
		for i := range sessions {
			if err := db.WithContext(ctx).Model(&models.SSOSession{}).
				Where("id = ? AND status = ? AND revoked_at IS NULL", sessions[i].ID, "active").
				Updates(map[string]any{"status": "revoked", "revoked_at": time.Now(), "revoke_reason": "password_changed"}).Error; err != nil {
				return nil, err
			}
			if err := createPasswordChangedEvent(db.WithContext(ctx), &sessions[i], "password_changed"); err != nil {
				return nil, err
			}
		}
	}
	var user models.User
	if err := db.WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) SetStatus(ctx context.Context, id uuid.UUID, status string) error {
	result := r.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ?", id).
		Update("status", status)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrUserNotFound
	}
	return nil
}
