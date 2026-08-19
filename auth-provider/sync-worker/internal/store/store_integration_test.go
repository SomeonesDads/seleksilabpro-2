package store

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/sync-worker/internal/worker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestStorePostgresIntegration(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set TEST_DATABASE_URL to run PostgreSQL integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer adminPool.Close()
	if err := adminPool.Ping(ctx); err != nil {
		t.Fatal(err)
	}

	schema := "sync_worker_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer adminPool.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE")

	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if poolConfig.ConnConfig.RuntimeParams == nil {
		poolConfig.ConnConfig.RuntimeParams = make(map[string]string)
	}
	poolConfig.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	for _, statement := range integrationSchema {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}

	store := New(pool)
	userID, sessionID, applicationID, unredeemedApplicationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	eventID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO applications (id, name, status, logout_notification_url)
		VALUES ($1, 'App A', 'active', 'http://app-a/internal/logout')`, applicationID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO applications (id, name, status, logout_notification_url)
		VALUES ($1, 'App B', 'active', 'http://app-b/internal/logout')`, unredeemedApplicationID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO events (id, event_type, user_id, central_session_id, payload, status, created_at)
		VALUES ($1, 'SessionRevoked', $2, $3, '{"eventId":"x"}', 'pending', now())`, eventID, userID, sessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO access_tokens (application_id, user_id, session_id)
		VALUES ($1, $2, $3)`, applicationID, userID, sessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO authorization_codes (application_id, user_id, sso_session_id)
		VALUES ($1, $2, $3)`, unredeemedApplicationID, userID, sessionID); err != nil {
		t.Fatal(err)
	}

	outbox, err := store.ListUnpublished(ctx, 10)
	if err != nil || len(outbox) != 1 || outbox[0].ID != eventID.String() {
		t.Fatalf("outbox = %+v err=%v", outbox, err)
	}
	if err := store.MarkPublished(ctx, eventID.String(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	outbox, err = store.ListUnpublished(ctx, 10)
	if err != nil || len(outbox) != 0 {
		t.Fatalf("published outbox = %+v err=%v", outbox, err)
	}

	configuredTargets := []worker.AppTarget{
		{
			ApplicationID:     applicationID,
			LogoutNotifyURL:   "http://app-a/internal/logout",
			InternalAuthToken: "secret",
		},
		{
			ApplicationID:     unredeemedApplicationID,
			LogoutNotifyURL:   "http://app-b/internal/logout",
			InternalAuthToken: "secret-b",
		},
	}
	targets, err := store.ResolveTargets(ctx, worker.EventPayload{UserID: userID, CentralSessionID: &sessionID}, configuredTargets)
	if err != nil || len(targets) != 1 || targets[0].InternalAuthToken != "secret" {
		t.Fatalf("targets = %+v err=%v; unredeemed authorization code must not create target", targets, err)
	}
	if err := store.ValidateTargets(ctx, configuredTargets); err != nil {
		t.Fatal(err)
	}

	state, err := store.BeginDelivery(ctx, eventID, applicationID)
	if err != nil || state.Status != "processing" || state.AttemptCount != 1 {
		t.Fatalf("first delivery state = %+v err=%v", state, err)
	}
	if err := store.MarkDeliveryRetrying(ctx, eventID, applicationID, time.Now().Add(time.Second), fmt.Errorf("temporary")); err != nil {
		t.Fatal(err)
	}
	state, err = store.BeginDelivery(ctx, eventID, applicationID)
	if err != nil || state.Status != "processing" || state.AttemptCount != 2 {
		t.Fatalf("retry delivery state = %+v err=%v", state, err)
	}
	if err := store.MarkDeliverySucceeded(ctx, eventID, applicationID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	state, err = store.BeginDelivery(ctx, eventID, applicationID)
	if err != nil || state.Status != "succeeded" || state.AttemptCount != 2 {
		t.Fatalf("idempotent delivery state = %+v err=%v", state, err)
	}

	failedEventID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO events (id, event_type, user_id, payload, status, created_at)
		VALUES ($1, 'SessionRevoked', $2, '{}', 'published', now())`, failedEventID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.BeginDelivery(ctx, failedEventID, applicationID); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkDeliveryFailed(ctx, failedEventID, applicationID, time.Now().UTC(), fmt.Errorf("permanent")); err != nil {
		t.Fatal(err)
	}
	state, err = store.BeginDelivery(ctx, failedEventID, applicationID)
	if err != nil || state.Status != "failed" || state.AttemptCount != 1 {
		t.Fatalf("failed delivery state = %+v err=%v", state, err)
	}

	rollbackEventID, rollbackApplicationID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO events (id, event_type, user_id, payload, status, created_at)
		VALUES ($1, 'SessionRevoked', $2, '{}', 'published', now())`, rollbackEventID, userID); err != nil {
		t.Fatal(err)
	}
	for _, statement := range rollbackTrigger(rollbackApplicationID) {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.BeginDelivery(ctx, rollbackEventID, rollbackApplicationID); err == nil {
		t.Fatal("expected delivery transaction failure")
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM event_deliveries WHERE event_id = $1`, rollbackEventID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("rolled-back delivery rows = %d", count)
	}
}

var integrationSchema = []string{
	`CREATE TABLE events (
		id uuid PRIMARY KEY, event_type text NOT NULL, user_id uuid NOT NULL,
		central_session_id uuid, application_id uuid, payload jsonb NOT NULL,
		status text NOT NULL, created_at timestamptz NOT NULL, published_at timestamptz
	)`,
	`CREATE TABLE applications (
		id uuid PRIMARY KEY, name text NOT NULL, status text NOT NULL,
		logout_notification_url text NOT NULL
	)`,
	`CREATE TABLE access_tokens (application_id uuid NOT NULL, user_id uuid NOT NULL, session_id uuid NOT NULL)`,
	`CREATE TABLE authorization_codes (application_id uuid NOT NULL, user_id uuid NOT NULL, sso_session_id uuid NOT NULL)`,
	`CREATE TABLE event_deliveries (
		event_id uuid NOT NULL, application_id uuid NOT NULL, status text NOT NULL,
		attempt_count integer NOT NULL, last_attempt_at timestamptz,
		next_retry_at timestamptz, processed_at timestamptz, last_error text,
		UNIQUE (event_id, application_id)
	)`,
}

func rollbackTrigger(applicationID uuid.UUID) []string {
	return []string{
		`CREATE OR REPLACE FUNCTION fail_delivery_update() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'forced delivery update failure'; END; $$`,
		fmt.Sprintf(`CREATE TRIGGER fail_delivery_update BEFORE UPDATE ON event_deliveries
			FOR EACH ROW WHEN (NEW.application_id = '%s') EXECUTE FUNCTION fail_delivery_update()`, applicationID),
	}
}
