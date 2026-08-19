package repository

import (
	"context"
	"errors"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type GroupRepository struct{ db *gorm.DB }

var ErrGroupNotFound = errors.New("group not found")

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
	result := r.db.WithContext(ctx).Where("group_id = ? AND user_id = ?", groupID, userID).Delete(&models.UserGroup{})
	return result.Error
}
