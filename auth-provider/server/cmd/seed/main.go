// cmd/seed is a placeholder for future idempotent demo-data seeding.
// It currently does not insert any data.
package main

import (
	"context"
	"log"
	"log/slog"
	"os"

	appdb "github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/db"
)

func main() {
	ctx := context.Background()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL is required")
	}

	pool, err := appdb.Connect(ctx, dbURL)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	// TODO: replace with real seeding logic. Sketch below — make it
	// idempotent (ON CONFLICT DO NOTHING / check-then-insert) so re-running
	// `docker compose up` doesn't fail or duplicate rows.

	slog.Info("seed: TODO — insert demo admin user, a couple of groups " +
		"(e.g. 'administrators', 'app-a-users', 'app-b-users'), App A and " +
		"App B application rows with their client_id/redirect_uri, and " +
		"application_group_policies granting access")
}
