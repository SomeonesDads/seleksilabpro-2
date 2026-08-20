package store

import (
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

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
		url, err := startTestPostgres()
		if err != nil {
			fmt.Fprintf(os.Stderr, "app-a postgres setup skipped: %v\n", err)
		}
		testDatabaseURL = url
	}
	code := m.Run()
	stopTestPostgres()
	os.Exit(code)
}

func startTestPostgres() (string, error) {
	name := "seleksilabpro-app-a-tests-" + uuid.NewString()
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

	port, err := containerPort(name)
	if err != nil {
		stopTestPostgres()
		return "", err
	}
	deadline := time.Now().Add(60 * time.Second)
	dsn := fmt.Sprintf("postgres://test:test@127.0.0.1:%s/app_a_test?sslmode=disable", port)
	for time.Now().Before(deadline) {
		db, err := gorm.Open(openDialector(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
		if err == nil {
			sqlDB, _ := db.DB()
			if err := sqlDB.Ping(); err == nil {
				return dsn, nil
			}
			_ = sqlDB.Close()
		}
		time.Sleep(500 * time.Millisecond)
	}
	stopTestPostgres()
	return "", fmt.Errorf("postgres container did not become ready")
}

func openDialector(dsn string) gorm.Dialector {
	return postgres.Open(dsn)
}

func containerPort(name string) (string, error) {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.Command("docker", "port", name, "5432/tcp").CombinedOutput()
		if err == nil {
			line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
			_, port, splitErr := splitHostPort(line)
			if splitErr == nil && port != "" {
				return port, nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return "", fmt.Errorf("docker port lookup failed for %s", name)
}

func splitHostPort(address string) (string, string, error) {
	idx := strings.LastIndex(address, ":")
	if idx < 0 {
		return "", "", fmt.Errorf("invalid address %q", address)
	}
	return address[:idx], address[idx+1:], nil
}

func stopTestPostgres() {
	if testContainerName == "" {
		return
	}
	if out, err := exec.Command("docker", "rm", "-f", testContainerName).CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "app-a postgres cleanup failed: %v: %s\n", err, strings.TrimSpace(string(out)))
	}
	testContainerName = ""
}

// openTestStore returns a migrated store or skips the test when no database is
// available.
func openTestStore(t *testing.T) *Store {
	t.Helper()
	if testDatabaseURL == "" {
		t.Skip("PostgreSQL test database is not configured")
	}
	db, err := gorm.Open(openDialector(testDatabaseURL), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect test database: %v", err)
	}
	st := New(db)
	if err := st.AutoMigrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sqlDB, _ := db.DB()
	_, _ = sqlDB.Exec("TRUNCATE TABLE local_sessions, profile_cache, processed_events, activity_logs")
	t.Cleanup(func() {
		_ = sqlDB.Close()
	})
	return st
}

// ensure sql import retained for cleanup path
var _ = sql.ErrNoRows
