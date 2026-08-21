// Command seed provisions a repeatable demo environment for the Auth Provider
// and its relying applications. It is idempotent: re-running it against the
// same database never duplicates users, groups, applications, redirect URIs, or
// policies. Raw credentials and internal auth tokens are printed once as the
// provisioning output and are not persisted beyond that.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	appdb "github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/db"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/seed"
)

func main() {
	ctx := context.Background()

	cfg, err := seed.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL is required")
	}

	if err := appdb.RunMigrations(ctx, dbURL, "migrations"); err != nil {
		log.Fatalf("seed: migrations: %v", err)
	}

	gormDB, err := appdb.ConnectGORM(ctx, dbURL)
	if err != nil {
		log.Fatalf("seed: connect: %v", err)
	}
	sqlDB, err := gormDB.DB()
	if err != nil {
		log.Fatalf("seed: sql db: %v", err)
	}
	defer sqlDB.Close()

	summary, err := cfg.Seed(ctx, gormDB)
	if err != nil {
		log.Fatalf("seed: %v", err)
	}

	fmt.Print(summary.Render())
}
