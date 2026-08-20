package handlers

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/applications/app-a/internal/config"
	"github.com/SomeonesDads/seleksilabpro-2/applications/app-a/internal/store"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var testDatabaseURL string
var testContainerName string

func TestMain(m *testing.M) {
	testDatabaseURL = strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if testDatabaseURL == "" {
		url, err := startHandlerPostgres()
		if err != nil {
			fmt.Fprintf(os.Stderr, "app-a handler postgres setup skipped: %v\n", err)
		}
		testDatabaseURL = url
	}
	code := m.Run()
	stopHandlerPostgres()
	os.Exit(code)
}

func startHandlerPostgres() (string, error) {
	name := "seleksilabpro-app-a-handlers-" + uuid.NewString()
	out, err := exec.Command("docker", "run", "--rm", "-d",
		"--name", name,
		"-e", "POSTGRES_USER=test",
		"-e", "POSTGRES_PASSWORD=test",
		"-e", "POSTGRES_DB=app_a_test",
		"-p", "127.0.0.1::5432",
		"postgres:16-alpine",
	).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker run: %w: %s", err, strings.TrimSpace(string(out)))
	}
	testContainerName = name
	port, err := handlerContainerPort(name)
	if err != nil {
		stopHandlerPostgres()
		return "", err
	}
	dsn := fmt.Sprintf("postgres://test:test@127.0.0.1:%s/app_a_test?sslmode=disable", port)
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
		if err == nil {
			sqlDB, _ := db.DB()
			if pingErr := sqlDB.Ping(); pingErr == nil {
				_ = sqlDB.Close()
				return dsn, nil
			}
			_ = sqlDB.Close()
		}
		time.Sleep(500 * time.Millisecond)
	}
	stopHandlerPostgres()
	return "", fmt.Errorf("postgres container did not become ready")
}

func handlerContainerPort(name string) (string, error) {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.Command("docker", "port", name, "5432/tcp").CombinedOutput()
		if err == nil {
			line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
			idx := strings.LastIndex(line, ":")
			if idx >= 0 {
				return line[idx+1:], nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return "", fmt.Errorf("docker port lookup failed for %s", name)
}

func stopHandlerPostgres() {
	if testContainerName == "" {
		return
	}
	_, _ = exec.Command("docker", "rm", "-f", testContainerName).CombinedOutput()
	testContainerName = ""
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	if testDatabaseURL == "" {
		t.Skip("PostgreSQL test database is not configured")
	}
	db, err := gorm.Open(postgres.Open(testDatabaseURL), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	st := store.New(db)
	if err := st.AutoMigrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sqlDB, _ := db.DB()
	_, _ = sqlDB.Exec("TRUNCATE TABLE local_sessions, profile_cache, processed_events, activity_logs")
	t.Cleanup(func() { _ = sqlDB.Close() })
	return st
}

func newTestApp(t *testing.T) *App {
	t.Helper()
	st := openTestStore(t)
	cfg := config.Config{
		RedirectURI:       "http://localhost:5010/auth/callback",
		InternalAuthToken: "internal-test-token",
		SessionTTL:        12 * time.Hour,
		CookieSecure:      false,
		AppID:             "00000000-0000-0000-0000-0000000000a1",
	}
	return NewApp(cfg, st, &fakeProvider{})
}
