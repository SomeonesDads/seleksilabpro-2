package repository

import (
	"context"
	"errors"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type PolicyRepository struct{ db *gorm.DB }

var ErrPolicyNotFound = errors.New("policy not found")

func NewPolicyRepository(db *gorm.DB) *PolicyRepository { return &PolicyRepository{db: db} }

func (r *PolicyRepository) UserHasApplicationAccess(ctx context.Context, userID, applicationID uuid.UUID) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Table("users u").
		Joins("JOIN user_groups ug ON ug.user_id = u.id").
		Joins("JOIN application_group_policies p ON p.group_id = ug.group_id").
		Where("u.id = ? AND u.status = ? AND p.application_id = ? AND p.effect = ?", userID, "active", applicationID, "allow").
		Count(&count).Error
	return count > 0, err
}

func (r *PolicyRepository) Set(ctx context.Context, policy *models.ApplicationGroupPolicy) error {
	var existing models.ApplicationGroupPolicy
	err := r.db.WithContext(ctx).
		Where("application_id = ? AND group_id = ? AND effect = ?", policy.ApplicationID, policy.GroupID, policy.Effect).
		First(&existing).Error
	if err == nil {
		policy.ID = existing.ID
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	return r.db.WithContext(ctx).Create(policy).Error
}

func (r *PolicyRepository) ListByApplication(ctx context.Context, applicationID uuid.UUID) ([]models.ApplicationGroupPolicy, error) {
	var policies []models.ApplicationGroupPolicy
	err := r.db.WithContext(ctx).
		Where("application_id = ?", applicationID).
		Order("created_at ASC").Find(&policies).Error
	return policies, err
}
