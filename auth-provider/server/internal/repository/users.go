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
func (r *TOTPRepository) EnrollPending(ctx context.Context, userID uuid.UUID, encryptedSecret []byte) error {
	var existing models.UserTOTP
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return r.db.WithContext(ctx).Create(&models.UserTOTP{
			UserID:          userID,
			EncryptedSecret: encryptedSecret,
			Confirmed:       false,
		}).Error
	}
	if err != nil {
		return err
	}
	return r.db.WithContext(ctx).Model(&existing).Updates(map[string]any{
		"encrypted_secret": encryptedSecret,
		"confirmed":        false,
	}).Error
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
