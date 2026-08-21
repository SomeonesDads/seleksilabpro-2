package repository

import (
	"context"
	"errors"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type GroupRepository struct{ db *gorm.DB }

var ErrGroupNotFound = errors.New("group not found")
var ErrGroupMembershipNotFound = errors.New("group membership not found")

func NewGroupRepository(db *gorm.DB) *GroupRepository { return &GroupRepository{db: db} }

func (r *GroupRepository) FindByUserID(ctx context.Context, userID uuid.UUID) ([]models.Group, error) {
	var groups []models.Group
	err := r.db.WithContext(ctx).
		Model(&models.Group{}).
		Joins("JOIN user_groups ON user_groups.group_id = groups.id").
		Where("user_groups.user_id = ?", userID).
		Order("groups.name ASC").
		Find(&groups).Error
	return groups, err
}

func (r *GroupRepository) List(ctx context.Context) ([]models.Group, error) {
	var groups []models.Group
	err := r.db.WithContext(ctx).Order("created_at ASC").Find(&groups).Error
	return groups, err
}

func (r *GroupRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.Group, error) {
	var group models.Group
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&group).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrGroupNotFound
	}
	if err != nil {
		return nil, err
	}
	return &group, nil
}

func (r *GroupRepository) Create(ctx context.Context, group *models.Group) error {
	return r.db.WithContext(ctx).Create(group).Error
}

func (r *GroupRepository) AddUser(ctx context.Context, groupID, userID uuid.UUID) error {
	return r.db.WithContext(ctx).Create(&models.UserGroup{GroupID: groupID, UserID: userID}).Error
}

func (r *GroupRepository) RemoveUser(ctx context.Context, groupID, userID uuid.UUID) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var applicationIDs []uuid.UUID
		if err := tx.Raw(`
			SELECT DISTINCT p.application_id
			FROM application_group_policies p
			JOIN user_groups removed_membership
			  ON removed_membership.group_id = p.group_id
			 AND removed_membership.user_id = ?
			WHERE p.group_id = ?
			  AND p.effect = 'allow'
			  AND NOT EXISTS (
				  SELECT 1
				  FROM user_groups other_membership
				  JOIN application_group_policies other_policy
				    ON other_policy.group_id = other_membership.group_id
				   AND other_policy.application_id = p.application_id
				   AND other_policy.effect = 'allow'
				  WHERE other_membership.user_id = ?
				    AND other_membership.group_id <> ?
			  )`, userID, groupID, userID, groupID).Scan(&applicationIDs).Error; err != nil {
			return err
		}

		result := tx.Where("group_id = ? AND user_id = ?", groupID, userID).Delete(&models.UserGroup{})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrGroupMembershipNotFound
		}

		now := time.Now()
		for _, applicationID := range applicationIDs {
			if err := tx.Model(&models.AccessToken{}).
				Where("user_id = ? AND application_id = ? AND revoked_at IS NULL", userID, applicationID).
				Updates(map[string]any{"revoked_at": now, "revoke_reason": "access_policy_changed"}).Error; err != nil {
				return err
			}
			if err := createAccessPolicyChangedEvent(tx, userID, applicationID, "access_policy_changed"); err != nil {
				return err
			}
		}
		return nil
	})
}
