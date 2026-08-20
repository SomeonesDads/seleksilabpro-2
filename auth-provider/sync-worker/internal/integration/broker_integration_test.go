// Package integration proves the full outbox -> RabbitMQ flow against real
// PostgreSQL and RabbitMQ infrastructure (finals.md item 4 acceptance: a
// disposable PostgreSQL/RabbitMQ integration test proving an outbox row
// reaches the broker, is confirmed, and survives a worker restart without
// re-publishing).
//
// When TEST_DATABASE_URL / TEST_AMQP_URL are unset the suite stands up
// disposable Docker containers; when Docker is unavailable it skips.
package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/sync-worker/internal/store"
	"github.com/SomeonesDads/seleksilabpro-2/shared/queue"
	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const eventsSchema = `CREATE TABLE events (
	id uuid PRIMARY KEY, event_type text NOT NULL, user_id uuid NOT NULL,
	central_session_id uuid, application_id uuid, payload jsonb NOT NULL,
	status text NOT NULL, created_at timestamptz NOT NULL, published_at timestamptz
)`

var (
	testDatabaseURL string
	testAMQPURL     string
	pgContainer     string
	amqpContainer   string
)

func TestMain(m *testing.M) {
	testDatabaseURL = strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	testAMQPURL = strings.TrimSpace(os.Getenv("TEST_AMQP_URL"))
	if testDatabaseURL == "" {
		url, name, err := startContainer("postgres:16-alpine", "5432/tcp",
			[]string{"-e", "POSTGRES_USER=test", "-e", "POSTGRES_PASSWORD=test", "-e", "POSTGRES_DB=auth_test", "-p", "127.0.0.1::5432"},
			"pg_isready", "-U", "test", "-d", "auth_test")
		if err != nil {
			fmt.Fprintf(os.Stderr, "integration postgres skipped: %v\n", err)
		} else {
			testDatabaseURL = url
			pgContainer = name
		}
	}
	if testAMQPURL == "" {
		url, name, err := startContainer("rabbitmq:3-alpine", "5672/tcp",
			[]string{"-p", "127.0.0.1::5672"}, "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "integration rabbitmq skipped: %v\n", err)
		} else {
			testAMQPURL = url
			amqpContainer = name
		}
	}

	code := m.Run()

	if pgContainer != "" {
		_ = exec.Command("docker", "rm", "-f", pgContainer).Run()
	}
	if amqpContainer != "" {
		_ = exec.Command("docker", "rm", "-f", amqpContainer).Run()
	}
	os.Exit(code)
}

func startContainer(image, containerPort string, extraArgs []string, readyCmd ...string) (string, string, error) {
	name := "seleksilabpro-it-" + uuid.NewString()
	cmd := exec.Command("docker", "run", "--rm", "-d", "--name", name)
	cmd.Args = append(cmd.Args, extraArgs...)
	cmd.Args = append(cmd.Args, image)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("docker run %s: %w: %s", image, err, strings.TrimSpace(string(output)))
	}

	deadline := time.Now().Add(90 * time.Second)
	if strings.Contains(image, "postgres") {
		port, err := dockerPort(name, containerPort)
		if err != nil {
			_ = exec.Command("docker", "rm", "-f", name).Run()
			return "", "", err
		}
		for time.Now().Before(deadline) {
			if exec.Command("docker", "exec", name, "pg_isready", "-U", "test", "-d", "auth_test").Run() == nil {
				return "postgres://test:test@127.0.0.1:" + port + "/auth_test?sslmode=disable", name, nil
			}
			time.Sleep(500 * time.Millisecond)
		}
		_ = exec.Command("docker", "rm", "-f", name).Run()
		return "", "", fmt.Errorf("postgres %s not ready", name)
	}

	for time.Now().Before(deadline) {
		port, err := dockerPort(name, containerPort)
		if err == nil {
			amqpURL := "amqp://guest:guest@127.0.0.1:" + port + "/"
			if conn, derr := amqp.Dial(amqpURL); derr == nil {
				_ = conn.Close()
				return amqpURL, name, nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	_ = exec.Command("docker", "rm", "-f", name).Run()
	return "", "", fmt.Errorf("rabbitmq %s not ready", name)
}

func dockerPort(name, containerPort string) (string, error) {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		output, err := exec.Command("docker", "port", name, containerPort).CombinedOutput()
		if err == nil {
			address := strings.TrimSpace(strings.SplitN(string(output), "\n", 2)[0])
			if i := strings.LastIndex(address, ":"); i != -1 {
				return address[i+1:], nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return "", fmt.Errorf("docker port lookup failed for %s", name)
}

func setupBrokerStore(t *testing.T) (*store.Store, *pgxpool.Pool, func()) {
	t.Helper()
	if testDatabaseURL == "" || testAMQPURL == "" {
		t.Skip("PostgreSQL and RabbitMQ are not available (set TEST_DATABASE_URL / TEST_AMQP_URL or run docker)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	adminPool, err := pgxpool.New(ctx, testDatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := adminPool.Ping(ctx); err != nil {
		adminPool.Close()
		t.Fatal(err)
	}
	schema := "it_outbox_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		adminPool.Close()
		t.Fatal(err)
	}

	poolConfig, err := pgxpool.ParseConfig(testDatabaseURL)
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
	if _, err := pool.Exec(ctx, eventsSchema); err != nil {
		pool.Close()
		adminPool.Close()
		t.Fatal(err)
	}

	cleanup := func() {
		pool.Close()
		adminPool.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
		adminPool.Close()
	}
	return store.New(pool), pool, cleanup
}

func insertEvent(ctx context.Context, pool *pgxpool.Pool, eventID, userID uuid.UUID, eventType string) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO events (id, event_type, user_id, payload, status, created_at)
		VALUES ($1, $2, $3, '{"eventId":"x"}', 'pending', now())`, eventID, eventType, userID)
	return err
}

// TestOutboxRowReachesBrokerAndSurvivesWorkerRestart proves the item-4
// contract with real infrastructure and a real restart: an outbox row is
// published to RabbitMQ only after broker confirmation, marked published, and
// a NEW broker connection (worker restart) does not re-publish it. The
// delivered message remains durably in the queue across the restart.
func TestOutboxRowReachesBrokerAndSurvivesWorkerRestart(t *testing.T) {
	st, pool, cleanup := setupBrokerStore(t)
	defer cleanup()

	ctx := context.Background()
	eventID := uuid.New()
	userID := uuid.New()
	if err := insertEvent(ctx, pool, eventID, userID, "SessionRevoked"); err != nil {
		t.Fatal(err)
	}

	// First worker lifetime: connect, publish, confirm.
	conn1, err := queue.Connect(testAMQPURL)
	if err != nil {
		t.Fatal(err)
	}
	deliveries1, err := conn1.Consume()
	if err != nil {
		t.Fatal(err)
	}
	publisher := queue.NewOutboxPublisher(conn1, st, nil, 100*time.Millisecond)
	if err := publisher.PublishBatch(ctx); err != nil {
		t.Fatalf("publish: %v", err)
	}
	select {
	case d := <-deliveries1:
		if d.RoutingKey != "SessionRevoked" {
			t.Fatalf("unexpected routing key %q", d.RoutingKey)
		}
		// Leave the delivery unacked so it is redelivered after the worker
		// restart (closing conn1 returns it to the queue).
	case <-time.After(5 * time.Second):
		t.Fatal("SessionRevoked was not delivered to the broker")
	}

	unpublished, err := st.ListUnpublished(ctx, 10)
	if err != nil || len(unpublished) != 0 {
		t.Fatalf("row should be published after confirm: unpublished=%d err=%v", len(unpublished), err)
	}

	// Worker restart: close the connection and open a brand-new one.
	_ = conn1.Close()
	conn2, err := queue.Connect(testAMQPURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()

	// A publish pass on the restarted worker must NOT create a new delivery.
	publisher2 := queue.NewOutboxPublisher(conn2, st, nil, 100*time.Millisecond)
	if err := publisher2.PublishBatch(ctx); err != nil {
		t.Fatalf("second publish: %v", err)
	}
	deliveries2, err := conn2.Consume()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case d := <-deliveries2:
		if d.RoutingKey != "SessionRevoked" {
			t.Fatalf("unexpected routing key %q", d.RoutingKey)
		}
		_ = d.Ack(false)
	case <-time.After(2 * time.Second):
		// Expected: the already-published row is not re-delivered, but the
		// durable message from the first pass survives the restart. Either
		// way we must not receive a SECOND distinct message.
		t.Fatal("no message available after restart; durable delivery was lost")
	}

	// A second publish on the restarted worker must still produce nothing new.
	if err := publisher2.PublishBatch(ctx); err != nil {
		t.Fatalf("third publish: %v", err)
	}
	select {
	case d := <-deliveries2:
		_ = d.Nack(false, false)
		t.Fatalf("confirmed event was re-delivered after restart: %s", d.RoutingKey)
	case <-time.After(2 * time.Second):
		// Expected: nothing arrives.
	}
}

// TestUnknownEventTypeNotRoutedToBroker proves unsupported event types are not
// routed to the worker queue and stay pending.
func TestUnknownEventTypeNotRoutedToBroker(t *testing.T) {
	st, pool, cleanup := setupBrokerStore(t)
	defer cleanup()

	ctx := context.Background()
	eventID := uuid.New()
	userID := uuid.New()
	if err := insertEvent(ctx, pool, eventID, userID, "BogusType"); err != nil {
		t.Fatal(err)
	}

	conn, err := queue.Connect(testAMQPURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deliveries, err := conn.Consume()
	if err != nil {
		t.Fatal(err)
	}
	publisher := queue.NewOutboxPublisher(conn, st, nil, 100*time.Millisecond)
	// The publisher returns an error for unsupported types (it leaves the row
	// pending and never routes it); that is the behavior under test.
	if err := publisher.PublishBatch(ctx); err == nil {
		t.Fatal("expected publisher to reject the unsupported event type")
	}
	select {
	case d := <-deliveries:
		_ = d.Nack(false, false)
		t.Fatalf("unknown event type was routed to the broker: %s", d.RoutingKey)
	case <-time.After(2 * time.Second):
		// Expected: the unsupported event stays pending (not delivered).
	}
	unpublished, err := st.ListUnpublished(ctx, 10)
	if err != nil || len(unpublished) != 1 {
		t.Fatalf("unknown event should remain pending: unpublished=%d err=%v", len(unpublished), err)
	}
}
