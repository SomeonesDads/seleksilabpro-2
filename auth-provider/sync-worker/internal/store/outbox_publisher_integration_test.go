package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/shared/queue"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testPublisher records routing keys and optionally fails, standing in for the
// RabbitMQ broker so the outbox contract can be exercised against a real
// Postgres outbox store.
type testPublisher struct {
	keys []string
	err  error
}

func (p *testPublisher) Publish(_ context.Context, key string, _ []byte) error {
	p.keys = append(p.keys, key)
	return p.err
}

func newOutboxTestStore(t *testing.T) (*Store, func()) {
	t.Helper()
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
	if err := adminPool.Ping(ctx); err != nil {
		adminPool.Close()
		t.Fatal(err)
	}

	schema := "sync_worker_outbox_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		adminPool.Close()
		t.Fatal(err)
	}

	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		adminPool.Close()
		t.Fatal(err)
	}
	if poolConfig.ConnConfig.RuntimeParams == nil {
		poolConfig.ConnConfig.RuntimeParams = make(map[string]string)
	}
	poolConfig.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		adminPool.Close()
		t.Fatal(err)
	}
	for _, statement := range integrationSchema {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}

	cleanup := func() {
		adminPool.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		pool.Close()
		adminPool.Close()
	}
	return New(pool), cleanup
}

// TestOutboxPublisherSurvivesRestartUntilConfirmed proves finals.md item 4:
// a broker-confirm failure leaves published_at unset and permits retry, a
// successful confirm marks the row published, and a later run does not
// re-publish (survives a worker restart).
func TestOutboxPublisherSurvivesRestartUntilConfirmed(t *testing.T) {
	store, cleanup := newOutboxTestStore(t)
	defer cleanup()

	ctx := context.Background()
	eventID := uuid.New()
	userID := uuid.New()
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO events (id, event_type, user_id, payload, status, created_at)
		VALUES ($1, 'SessionRevoked', $2, '{"eventId":"x"}', 'pending', now())`, eventID, userID); err != nil {
		t.Fatal(err)
	}

	// Broker unavailable: publish must fail and the row must stay unpublished.
	failing := &testPublisher{err: errors.New("broker unavailable")}
	pub := queue.NewOutboxPublisher(failing, store, nil, time.Second)
	if err := pub.PublishBatch(ctx); err == nil {
		t.Fatal("expected publish failure")
	}
	unpublished, err := store.ListUnpublished(ctx, 10)
	if err != nil || len(unpublished) != 1 {
		t.Fatalf("event should remain unpublished: got %d, err=%v", len(unpublished), err)
	}

	// Broker recovers (simulating worker restart): the pending row is published.
	ok := &testPublisher{}
	pub = queue.NewOutboxPublisher(ok, store, nil, time.Second)
	if err := pub.PublishBatch(ctx); err != nil {
		t.Fatalf("publish after recovery: %v", err)
	}
	if len(ok.keys) != 1 || ok.keys[0] != "SessionRevoked" {
		t.Fatalf("published keys = %v", ok.keys)
	}
	unpublished, err = store.ListUnpublished(ctx, 10)
	if err != nil || len(unpublished) != 0 {
		t.Fatalf("event should now be published: got %d, err=%v", len(unpublished), err)
	}

	// Second run after restart must not re-publish the confirmed event.
	if err := pub.PublishBatch(ctx); err != nil {
		t.Fatalf("second publish: %v", err)
	}
	if len(ok.keys) != 1 {
		t.Fatalf("confirmed event was re-published on restart: keys=%v", ok.keys)
	}
}
