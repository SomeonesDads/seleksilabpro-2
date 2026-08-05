// pgx connection pool & database migrations.
// ngubah schema cuma dipegang golang-migrate (dari sini doang).
package db

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
)

// buka connection pool + B03 tentang readiness probe (ping sekali)
func Connect(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("db: creating pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: initial ping failed: %w", err)
	}
	return pool, nil
}

// migration dari file file .up, beda connection dari pool (connection sendiri)
func RunMigrations(ctx context.Context, databaseURL, migrationsDir string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	absDir, err := filepath.Abs(migrationsDir)
	if err != nil {
		return fmt.Errorf("db: resolving migrations directory: %w", err)
	}
	if strings.HasSuffix(absDir, string(filepath.Separator)) {
		absDir = strings.TrimRight(absDir, string(filepath.Separator))
	}
	sourceURL := "file://" + filepath.ToSlash(absDir)

	m, err := migrate.New(sourceURL, databaseURL)
	if err != nil {
		return fmt.Errorf("db: creating migration runner: %w", err)
	}

	upErr := m.Up()
	closeSourceErr, closeDatabaseErr := m.Close()
	if upErr != nil && !errors.Is(upErr, migrate.ErrNoChange) {
		return fmt.Errorf("db: applying migrations: %w", upErr)
	}
	if closeSourceErr != nil {
		return fmt.Errorf("db: closing migration source: %w", closeSourceErr)
	}
	if closeDatabaseErr != nil {
		return fmt.Errorf("db: closing migration database: %w", closeDatabaseErr)
	}
	return nil
}
