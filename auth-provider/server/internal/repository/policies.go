package repository

import (
	"context"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type PolicyRepository struct{ db *gorm.DB }

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
