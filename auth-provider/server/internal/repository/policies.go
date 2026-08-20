package repository

import (
	"context"
	"errors"
	"time"

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

// GroupsAllowedForApplication returns the names of the groups that grant the
// user access to the given application via allow policies. The handler must
// not perform policy joins itself; this is the single source of truth.
func (r *PolicyRepository) GroupsAllowedForApplication(ctx context.Context, userID, applicationID uuid.UUID) ([]string, error) {
	var names []string
	err := r.db.WithContext(ctx).Table("users u").
		Joins("JOIN user_groups ug ON ug.user_id = u.id").
		Joins("JOIN application_group_policies p ON p.group_id = ug.group_id").
		Joins("JOIN groups g ON g.id = p.group_id").
		Where("u.id = ? AND u.status = ? AND p.application_id = ? AND p.effect = ?", userID, "active", applicationID, "allow").
		Distinct("g.name").
		Pluck("DISTINCT g.name", &names).Error
	return names, err
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

// Delete removes an allow policy binding a group to an application and, within
// the same transaction, revokes the affected application's access-token
// metadata for any user who loses their final allow path to that application.
// It does NOT revoke central SSO sessions or unrelated application access
// (DECISIONS.md Decision 016); one AccessPolicyChanged outbox event is emitted
// per affected user.
func (r *PolicyRepository) Delete(ctx context.Context, applicationID, groupID uuid.UUID) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Where("application_id = ? AND group_id = ? AND effect = ?", applicationID, groupID, "allow").
			Delete(&models.ApplicationGroupPolicy{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrPolicyNotFound
		}

		var userIDs []uuid.UUID
		err := tx.Table("users u").
			Joins("JOIN user_groups ug ON ug.user_id = u.id").
			Where("ug.group_id = ?", groupID).
			Where(`NOT EXISTS (
				SELECT 1 FROM application_group_policies p
				JOIN user_groups ug2 ON ug2.group_id = p.group_id
				WHERE p.application_id = ? AND p.effect = 'allow' AND ug2.user_id = u.id
			)`, applicationID).
			Pluck("DISTINCT u.id", &userIDs).Error
		if err != nil {
			return err
		}

		now := time.Now()
		for _, uid := range userIDs {
			if err := tx.Model(&models.AccessToken{}).
				Where("user_id = ? AND application_id = ? AND revoked_at IS NULL", uid, applicationID).
				Updates(map[string]any{"revoked_at": now}).Error; err != nil {
				return err
			}
			if err := createAccessPolicyChangedEvent(tx, uid, applicationID, "access_policy_changed"); err != nil {
				return err
			}
		}
		return nil
	})
}
