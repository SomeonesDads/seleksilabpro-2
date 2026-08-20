package repository

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	appdb "github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/db"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var policyTestDB *gorm.DB
var policyContainerName string

func TestMain(m *testing.M) {
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		url, err := startPolicyPostgres()
		if err != nil {
			fmt.Fprintf(os.Stderr, "policy postgres setup skipped: %v\n", err)
		}
		databaseURL = url
	}
	if databaseURL != "" && policyTestDB == nil {
		if err := openPolicyDB(databaseURL); err != nil {
			fmt.Fprintf(os.Stderr, "policy postgres connect failed: %v\n", err)
			policyTestDB = nil
		}
	}
	code := m.Run()
	stopPolicyPostgres()
	os.Exit(code)
}

func openPolicyDB(dsn string) error {
	if err := appdb.RunMigrations(context.Background(), dsn, migrationsDir()); err != nil {
		return err
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return err
	}
	policyTestDB = db
	return nil
}

func startPolicyPostgres() (string, error) {
	name := "seleksilabpro-policy-tests-" + uuid.NewString()
	out, err := exec.Command("docker", "run", "--rm", "-d",
		"--name", name,
		"-e", "POSTGRES_USER=test",
		"-e", "POSTGRES_PASSWORD=test",
		"-e", "POSTGRES_DB=policy_test",
		"-p", "127.0.0.1::5432",
		"postgres:16-alpine",
	).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker run: %w: %s", err, strings.TrimSpace(string(out)))
	}
	policyContainerName = name
	port, err := policyContainerPort(name)
	if err != nil {
		stopPolicyPostgres()
		return "", err
	}
	dsn := fmt.Sprintf("postgres://test:test@127.0.0.1:%s/policy_test?sslmode=disable", port)
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if err := appdb.RunMigrations(context.Background(), dsn, migrationsDir()); err == nil {
			db, connErr := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
			if connErr == nil {
				policyTestDB = db
				return dsn, nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	stopPolicyPostgres()
	return "", fmt.Errorf("policy postgres did not become ready")
}

func policyContainerPort(name string) (string, error) {
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

func stopPolicyPostgres() {
	if policyContainerName == "" {
		return
	}
	_, _ = exec.Command("docker", "rm", "-f", policyContainerName).CombinedOutput()
	policyContainerName = ""
}

func migrationsDir() string {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	return filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", "migrations"))
}

// TestPolicyDeleteRevokesOnlyUsersLosingFinalAccess verifies that removing a
// group->application allow policy revokes the application's access-token
// metadata only for users who lose their LAST allow path, and emits one
// AccessPolicyChanged event per affected user. A user who retains access
// through a second group policy is left untouched.
func TestPolicyDeleteRevokesOnlyUsersLosingFinalAccess(t *testing.T) {
	if policyTestDB == nil {
		t.Skip("PostgreSQL acceptance database is not configured")
	}
	ctx := context.Background()
	db := policyTestDB

	app := &models.Application{
		Name:                  "policy-app",
		ClientID:              "policy-app-" + uuid.NewString(),
		Status:                "active",
		LogoutNotificationURL: "http://app.example/internal/logout",
	}
	mustCreate(t, db, app)

	groupA := &models.Group{Name: "policy-group-a-" + uuid.NewString()}
	groupB := &models.Group{Name: "policy-group-b-" + uuid.NewString()}
	mustCreate(t, db, groupA, groupB)

	userLoses := &models.User{Name: "loses", Email: "loses-" + uuid.NewString() + "@example.com", PasswordHash: "x", Status: "active"}
	userKeeps := &models.User{Name: "keeps", Email: "keeps-" + uuid.NewString() + "@example.com", PasswordHash: "x", Status: "active"}
	mustCreate(t, db, userLoses, userKeeps)

	mustCreate(t, db, &models.UserGroup{UserID: userLoses.ID, GroupID: groupA.ID})
	mustCreate(t, db, &models.UserGroup{UserID: userKeeps.ID, GroupID: groupA.ID})
	mustCreate(t, db, &models.UserGroup{UserID: userKeeps.ID, GroupID: groupB.ID})

	policies := NewPolicyRepository(db)
	if err := policies.Set(ctx, &models.ApplicationGroupPolicy{ApplicationID: app.ID, GroupID: groupA.ID, Effect: "allow"}); err != nil {
		t.Fatalf("set policy A: %v", err)
	}
	if err := policies.Set(ctx, &models.ApplicationGroupPolicy{ApplicationID: app.ID, GroupID: groupB.ID, Effect: "allow"}); err != nil {
		t.Fatalf("set policy B: %v", err)
	}

	sessionLoses := &models.SSOSession{UserID: userLoses.ID, SessionTokenHash: uuid.NewString(), Status: "active", ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}
	sessionKeeps := &models.SSOSession{UserID: userKeeps.ID, SessionTokenHash: uuid.NewString(), Status: "active", ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}
	mustCreate(t, db, sessionLoses, sessionKeeps)

	tokenLoses := &models.AccessToken{JTI: uuid.New(), UserID: userLoses.ID, ApplicationID: app.ID, SessionID: sessionLoses.ID, ExpiresAt: time.Now().Add(time.Hour)}
	tokenKeeps := &models.AccessToken{JTI: uuid.New(), UserID: userKeeps.ID, ApplicationID: app.ID, SessionID: sessionKeeps.ID, ExpiresAt: time.Now().Add(time.Hour)}
	mustCreate(t, db, tokenLoses, tokenKeeps)

	if err := policies.Delete(ctx, app.ID, groupA.ID); err != nil {
		t.Fatalf("delete policy: %v", err)
	}

	var lost, kept models.AccessToken
	if err := db.First(&lost, "jti = ?", tokenLoses.JTI).Error; err != nil {
		t.Fatalf("load lost token: %v", err)
	}
	if err := db.First(&kept, "jti = ?", tokenKeeps.JTI).Error; err != nil {
		t.Fatalf("load kept token: %v", err)
	}
	if lost.RevokedAt == nil {
		t.Fatal("user who lost final access must have token revoked")
	}
	if lost.RevokeReason == nil || *lost.RevokeReason != "access_policy_changed" {
		t.Fatalf("revoked token must record reason, got %v", lost.RevokeReason)
	}
	if kept.RevokedAt != nil {
		t.Fatal("user retaining access via another group must NOT be revoked")
	}

	// Exactly one AccessPolicyChanged event, for the user who lost access.
	var events []models.Event
	if err := db.Where("event_type = ?", models.EventAccessPolicyChanged).Find(&events).Error; err != nil {
		t.Fatalf("load events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 AccessPolicyChanged event, got %d", len(events))
	}
	if events[0].UserID != userLoses.ID {
		t.Fatalf("event targeted wrong user: %s", events[0].UserID)
	}
	if events[0].ApplicationID == nil || *events[0].ApplicationID != app.ID {
		t.Fatalf("event targeted wrong application: %v", events[0].ApplicationID)
	}
}

func mustCreate(t *testing.T, db *gorm.DB, rows ...interface{}) {
	t.Helper()
	for _, row := range rows {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("create %T: %v", row, err)
		}
	}
}
