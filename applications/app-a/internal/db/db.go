package db

import (
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Open connects to PostgreSQL using GORM. Migrations are applied by the store's
// AutoMigrate at startup (the project mandates ORM-based migration automation).
func Open(dsn string, gormLogger logger.Interface) (*gorm.DB, error) {
	if gormLogger == nil {
		gormLogger = logger.Default
	}
	return gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: gormLogger,
	})
}
