package repository

import (
	"context"
	"errors"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

var ErrUserNotFound = errors.New("user not found")
var ErrMFAChallengeNotFound = errors.New("MFA challenge not found")
var ErrTOTPNotFound = errors.New("TOTP credential not found")

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
			Where("id = ? AND used_at IS NULL AND expires_at > ? AND attempts < ?", id, time.Now(), maxAttempts).
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
