// Package integration proves the real logout -> transactional outbox ->
// RabbitMQ flow end to end against real PostgreSQL and RabbitMQ (finals.md
// item 4 acceptance): logout creates exactly one outbox row, that row is
// published to the broker only after confirmation, and it survives a worker
// connection restart without re-publishing.
//
// When TEST_DATABASE_URL / TEST_AMQP_URL are unset the suite stands up
// disposable Docker containers; when Docker is unavailable it skips.
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appdb "github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/db"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/handlers"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/repository"
	"github.com/SomeonesDads/seleksilabpro-2/shared/idgen"
	"github.com/SomeonesDads/seleksilabpro-2/shared/queue"
	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

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

func startContainer(image, containerPort string, extraArgs []string, _ ...string) (string, string, error) {
	name := "seleksilabpro-srv-it-" + uuid.NewString()
	cmd := exec.Command("docker", "run", "--rm", "-d", "--name", name)
	cmd.Args = append(cmd.Args, extraArgs...)
	cmd.Args = append(cmd.Args, image)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("docker run %s: %w: %s", image, err, strings.TrimSpace(string(out)))
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
			if c, derr := amqp.Dial(amqpURL); derr == nil {
				_ = c.Close()
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
		out, err := exec.Command("docker", "port", name, containerPort).CombinedOutput()
		if err == nil {
			addr := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
			if i := strings.LastIndex(addr, ":"); i != -1 {
				return addr[i+1:], nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return "", fmt.Errorf("docker port lookup failed for %s", name)
}

// gormOutboxStore adapts the server's events table to the shared queue
// OutboxStore contract so the real publisher can read the rows logout writes.
type gormOutboxStore struct{ db *gorm.DB }

func (s *gormOutboxStore) ListUnpublished(ctx context.Context, limit int) ([]queue.OutboxEvent, error) {
	var events []models.Event
	if err := s.db.WithContext(ctx).Where("published_at IS NULL").Order("created_at ASC, id ASC").Limit(limit).Find(&events).Error; err != nil {
		return nil, err
	}
	out := make([]queue.OutboxEvent, 0, len(events))
	for _, e := range events {
		payload, err := json.Marshal(e.Payload)
		if err != nil {
			return nil, err
		}
		out = append(out, queue.OutboxEvent{ID: e.ID.String(), EventType: e.EventType, Payload: payload})
	}
	return out, nil
}

func (s *gormOutboxStore) MarkPublished(ctx context.Context, id string, publishedAt time.Time) error {
	return s.db.WithContext(ctx).Model(&models.Event{}).
		Where("id = ? AND published_at IS NULL", id).
		Updates(map[string]any{"status": "published", "published_at": publishedAt}).Error
}

func TestLogoutCreatesOutboxRowDeliveredToBrokerAndSurvivesRestart(t *testing.T) {
	if testDatabaseURL == "" || testAMQPURL == "" {
		t.Skip("PostgreSQL and RabbitMQ are not available (set TEST_DATABASE_URL / TEST_AMQP_URL or run docker)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	migrationsDir, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if err := appdb.RunMigrations(ctx, testDatabaseURL, migrationsDir); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	db, err := appdb.ConnectGORM(ctx, testDatabaseURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { sqlDB, e := db.DB(); if e == nil { _ = sqlDB.Close() } }()

	const reset = `TRUNCATE TABLE
		event_deliveries, events, audit_logs, access_tokens, authorization_codes,
		mfa_login_challenges, user_totp_credentials, sso_sessions,
		application_group_policies, application_redirect_uris, user_groups,
		applications, groups, users
		RESTART IDENTITY CASCADE`
	if err := db.Exec(reset).Error; err != nil {
		t.Fatalf("reset: %v", err)
	}

	users := repository.NewUserRepository(db)
	sessions := repository.NewSessionRepository(db)
	audit := repository.NewAuditRepository(db)
	handler := handlers.NewAuthHandlerWithDependencies(handlers.AuthRepositories{
		Users:             users,
		UserProfiles:      users,
		Sessions:          sessions,
		SessionLookup:     sessions,
		SessionRevocation: sessions,
		Audit:             audit,
	}, handlers.AuthHandlerConfig{
		AuthCodeTTL:    time.Minute,
		AccessTokenTTL: time.Minute,
		SessionTTL:     time.Hour,
		JWTIssuer:      "auth-provider",
		JWTSigningKey:  []byte("integration-test-signing-key-0000000000"),
		TokenStrategy:  "jwt",
	}, nil)

	user, err := users.CreateUser(ctx, "Ada", "ada-"+uuid.NewString()+"@example.com", "password", "active")
	if err != nil {
		t.Fatal(err)
	}
	rawToken := uuid.NewString()
	session := models.SSOSession{
		ID:               uuid.New(),
		UserID:           user.ID,
		SessionTokenHash: idgen.HashToken(rawToken),
		Status:           "active",
		ExpiresAt:        time.Now().Add(time.Hour),
	}
	if err := db.Create(&session).Error; err != nil {
		t.Fatal(err)
	}

	// Drive the real logout handler (not a manual insert).
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: rawToken})
	rec := httptest.NewRecorder()
	handler.Logout(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout failed: status=%d body=%s", rec.Code, rec.Body.String())
	}

	// Logout must create exactly one outbox row, still unconfirmed.
	var eventCount int64
	if err := db.Model(&models.Event{}).Count(&eventCount).Error; err != nil {
		t.Fatal(err)
	}
	if eventCount != 1 {
		t.Fatalf("logout created %d outbox rows, want exactly 1", eventCount)
	}
	var event models.Event
	if err := db.Where("central_session_id = ?", session.ID).First(&event).Error; err != nil {
		t.Fatal(err)
	}
	if event.EventType != models.EventSessionRevoked || event.PublishedAt != nil {
		t.Fatalf("unexpected outbox row: type=%q publishedAt=%v", event.EventType, event.PublishedAt)
	}

	// Publish the real outbox row to RabbitMQ using the shared publisher.
	conn1, err := queue.Connect(testAMQPURL)
	if err != nil {
		t.Fatal(err)
	}
	publisher := queue.NewOutboxPublisher(conn1, &gormOutboxStore{db: db}, nil, 100*time.Millisecond)
	if err := publisher.PublishBatch(ctx); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// The row is now confirmed/published.
	if err := db.Where("id = ?", event.ID).First(&event).Error; err != nil {
		t.Fatal(err)
	}
	if event.PublishedAt == nil {
		t.Fatal("outbox row was not marked published after broker confirmation")
	}

	// Worker restart: close the connection and reopen a brand-new one.
	_ = conn1.Close()
	conn2, err := queue.Connect(testAMQPURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	publisher2 := queue.NewOutboxPublisher(conn2, &gormOutboxStore{db: db}, nil, 100*time.Millisecond)

	// A publish on the restarted worker must NOT create a new delivery.
	if err := publisher2.PublishBatch(ctx); err != nil {
		t.Fatalf("restart publish: %v", err)
	}
	deliveries, err := conn2.Consume()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case d := <-deliveries:
		if d.RoutingKey != "SessionRevoked" {
			t.Fatalf("unexpected routing key %q", d.RoutingKey)
		}
		_ = d.Ack(false) // the single durable message survived the restart
	case <-time.After(3 * time.Second):
		t.Fatal("the published message was lost across the worker restart")
	}

	// A further publish must not re-deliver the already-published row.
	if err := publisher2.PublishBatch(ctx); err != nil {
		t.Fatalf("third publish: %v", err)
	}
	select {
	case d := <-deliveries:
		_ = d.Nack(false, false)
		t.Fatalf("confirmed event was re-delivered after restart: %s", d.RoutingKey)
	case <-time.After(2 * time.Second):
		// Expected: nothing new arrives.
	}
}
