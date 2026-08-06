package db

import (
	"context"
	"fmt"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// ConnectGORM open connection ke DB buat query.
func ConnectGORM(ctx context.Context, databaseURL string) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(databaseURL), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("db: opening gorm: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("db: getting gorm sql db: %w", err)
	}
	if err := sqlDB.PingContext(ctx); err != nil { // B03
		_ = sqlDB.Close()
		return nil, fmt.Errorf("db: gorm ping failed: %w", err)
	}
	return db, nil
}
