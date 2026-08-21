package seed

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	appdb "github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/db"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/google/uuid"
)

var testDatabaseURL string
var pgContainer string

// TestMain provisions a disposable PostgreSQL when TEST_DATABASE_URL is unset,
// so the idempotence assertion actually runs instead of skipping.
func TestMain(m *testing.M) {
	testDatabaseURL = strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if testDatabaseURL == "" {
		url, name, err := startPostgres()
		if err != nil {
			fmt.Fprintf(os.Stderr, "seed postgres skipped: %v\n", err)
		} else {
			testDatabaseURL = url
			pgContainer = name
		}
	}
	code := m.Run()
	if pgContainer != "" {
		_ = exec.Command("docker", "rm", "-f", pgContainer).Run()
	}
	os.Exit(code)
}

func startPostgres() (string, string, error) {
	name := "seleksilabpro-seed-" + uuid.NewString()
	out, err := exec.Command("docker", "run", "--rm", "-d", "--name", name,
		"-e", "POSTGRES_USER=test", "-e", "POSTGRES_PASSWORD=test", "-e", "POSTGRES_DB=auth_test",
		"-p", "127.0.0.1::5432", "postgres:16-alpine").CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("docker run: %w: %s", err, strings.TrimSpace(string(out)))
	}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if exec.Command("docker", "exec", name, "pg_isready", "-U", "test", "-d", "auth_test").Run() == nil {
			port, perr := dockerPort(name)
			if perr == nil {
				return "postgres://test:test@127.0.0.1:" + port + "/auth_test?sslmode=disable", name, nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	_ = exec.Command("docker", "rm", "-f", name).Run()
	return "", "", fmt.Errorf("postgres %s not ready", name)
}

func dockerPort(name string) (string, error) {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.Command("docker", "port", name, "5432/tcp").CombinedOutput()
		if err == nil {
			addr := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
			if i := strings.LastIndex(addr, ":"); i != -1 {
				return addr[i+1:], nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return "", fmt.Errorf("port lookup failed for %s", name)
}

// TestSeedIsIdempotent proves a second seed run creates no duplicate users,
// groups, applications, policies, or memberships (finals.md item 4 acceptance).
func TestSeedIsIdempotent(t *testing.T) {
	if testDatabaseURL == "" {
		t.Skip("PostgreSQL is not available (set TEST_DATABASE_URL or run docker)")
	}

	ctx := context.Background()
	if err := appdb.RunMigrations(ctx, testDatabaseURL, "../../migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	db, err := appdb.ConnectGORM(ctx, testDatabaseURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() {
		sqlDB, e := db.DB()
		if e == nil {
			_ = sqlDB.Close()
		}
	}()

	const reset = `TRUNCATE TABLE
		event_deliveries, events, audit_logs, access_tokens, authorization_codes,
		mfa_login_challenges, user_totp_credentials, sso_sessions,
		application_group_policies, application_redirect_uris, user_groups,
		applications, groups, users
		RESTART IDENTITY CASCADE`
	if err := db.Exec(reset).Error; err != nil {
		t.Fatalf("reset: %v", err)
	}

	cfg := testConfig()
	if _, err := cfg.Seed(ctx, db); err != nil {
		t.Fatalf("first seed: %v", err)
	}
	if _, err := cfg.Seed(ctx, db); err != nil {
		t.Fatalf("second seed: %v", err)
	}

	var users, groups, apps, policies, memberships, redirects int64
	db.Model(&models.User{}).Count(&users)
	db.Model(&models.Group{}).Count(&groups)
	db.Model(&models.Application{}).Count(&apps)
	db.Model(&models.ApplicationGroupPolicy{}).Count(&policies)
	db.Model(&models.UserGroup{}).Count(&memberships)
	db.Model(&models.ApplicationRedirectURI{}).Count(&redirects)

	if users != 2 {
		t.Fatalf("users = %d, want 2", users)
	}
	if groups != 3 {
		t.Fatalf("groups = %d, want 3", groups)
	}
	if apps != 2 {
		t.Fatalf("applications = %d, want 2", apps)
	}
	if policies != 2 {
		t.Fatalf("policies = %d, want 2", policies)
	}
	if memberships != 3 {
		t.Fatalf("memberships = %d, want 3", memberships)
	}
	if redirects != 2 {
		t.Fatalf("redirect URIs = %d, want 2", redirects)
	}
}

func testConfig() Config {
	return Config{
		AdminEmail:    "admin@example.com",
		AdminPassword: uuid.NewString(),
		AdminName:     "Admin",
		DemoEmail:     "demo@example.com",
		DemoPassword:  uuid.NewString(),
		DemoName:      "Demo User",

		AppAClientID:   "app-a-client",
		AppASecret:     uuid.NewString(),
		AppARedirect:   "http://app-a:5010/auth/callback",
		AppALogout:     "http://app-a:5010/internal/logout",
		AppABase:       "http://app-a:5010",
		InternalTokenA: uuid.NewString(),

		AppBClientID:   "app-b-client",
		AppBSecret:     uuid.NewString(),
		AppBRedirect:   "http://app-b:5020/auth/callback",
		AppBLogout:     "http://app-b:5020/internal/logout",
		AppBBase:       "http://app-b:5020",
		InternalTokenB: uuid.NewString(),
	}
}

func TestLoadConfigRequiresSecrets(t *testing.T) {
	for _, key := range []string{
		seedAdminPasswordEnv,
		seedDemoPasswordEnv,
		seedAppASecretEnv,
		seedAppBSecretEnv,
		seedInternalTokenAEnv,
		seedInternalTokenBEnv,
	} {
		t.Setenv(key, "")
	}
	if _, err := LoadConfig(); err == nil {
		t.Fatal("LoadConfig accepted missing seed secrets")
	}
}

func TestLoadConfigReadsSecrets(t *testing.T) {
	values := map[string]string{
		seedAdminPasswordEnv:  uuid.NewString(),
		seedDemoPasswordEnv:   uuid.NewString(),
		seedAppASecretEnv:     uuid.NewString(),
		seedAppBSecretEnv:     uuid.NewString(),
		seedInternalTokenAEnv: uuid.NewString(),
		seedInternalTokenBEnv: uuid.NewString(),
	}
	for key, value := range values {
		t.Setenv(key, value)
	}

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.AdminPassword != values[seedAdminPasswordEnv] ||
		cfg.DemoPassword != values[seedDemoPasswordEnv] ||
		cfg.AppASecret != values[seedAppASecretEnv] ||
		cfg.AppBSecret != values[seedAppBSecretEnv] ||
		cfg.InternalTokenA != values[seedInternalTokenAEnv] ||
		cfg.InternalTokenB != values[seedInternalTokenBEnv] {
		t.Fatal("LoadConfig did not copy configured seed secrets")
	}
}
