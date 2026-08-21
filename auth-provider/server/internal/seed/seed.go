// Package seed provisions a repeatable demo environment for the Auth Provider
// and its relying applications. Every write is idempotent: re-running the seed
// against the same database never duplicates users, groups, applications,
// redirect URIs, or policies.
//
// Credentials and internal auth tokens must be supplied through the environment
// and are printed only as intended provisioning output.
package seed

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Fixed application UUIDs so the worker APP_TARGETS_JSON and the seeded rows
// agree. The application_id in every revocation target must match the primary
// key the server writes here.
var (
	AppAID = uuid.MustParse("00000000-0000-0000-0000-0000000000a1")
	AppBID = uuid.MustParse("00000000-0000-0000-0000-0000000000b2")
)

// Config carries demo identities and application provisioning values. Secret
// fields are loaded by LoadConfig and are never given source-level defaults.
type Config struct {
	AdminEmail, AdminPassword, AdminName string
	DemoEmail, DemoPassword, DemoName    string

	AppAClientID, AppASecret, AppARedirect, AppALogout, AppABase, InternalTokenA string
	AppBClientID, AppBSecret, AppBRedirect, AppBLogout, AppBBase, InternalTokenB string
}

const (
	seedAdminPasswordEnv  = "SEED_ADMIN_PASSWORD"
	seedDemoPasswordEnv   = "SEED_DEMO_PASSWORD"
	seedAppASecretEnv     = "SEED_APP_A_CLIENT_SECRET"
	seedAppBSecretEnv     = "SEED_APP_B_CLIENT_SECRET"
	seedInternalTokenAEnv = "SEED_APP_A_INTERNAL_AUTH_TOKEN"
	seedInternalTokenBEnv = "SEED_APP_B_INTERNAL_AUTH_TOKEN"
)

// LoadConfig returns demo metadata plus secrets supplied by the operator.
// Missing values are reported by name only; secret contents never enter errors.
func LoadConfig() (Config, error) {
	cfg := Config{
		AdminEmail:    "admin@example.com",
		AdminPassword: os.Getenv(seedAdminPasswordEnv),
		AdminName:     "Admin",
		DemoEmail:     "demo@example.com",
		DemoPassword:  os.Getenv(seedDemoPasswordEnv),
		DemoName:      "Demo User",

		AppAClientID:   "app-a-client",
		AppASecret:     os.Getenv(seedAppASecretEnv),
		AppARedirect:   "http://localhost:5010/auth/callback",
		AppALogout:     "http://app-a:5010/internal/logout",
		AppABase:       "http://localhost:5010",
		InternalTokenA: os.Getenv(seedInternalTokenAEnv),

		AppBClientID:   "app-b-client",
		AppBSecret:     os.Getenv(seedAppBSecretEnv),
		AppBRedirect:   "http://localhost:5020/auth/callback",
		AppBLogout:     "http://app-b:5020/internal/logout",
		AppBBase:       "http://localhost:5020",
		InternalTokenB: os.Getenv(seedInternalTokenBEnv),
	}

	missing := make([]string, 0, 6)
	for _, key := range []string{
		seedAdminPasswordEnv,
		seedDemoPasswordEnv,
		seedAppASecretEnv,
		seedAppBSecretEnv,
		seedInternalTokenAEnv,
		seedInternalTokenBEnv,
	} {
		if strings.TrimSpace(os.Getenv(key)) == "" {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("seed: required environment variables are missing: %s", strings.Join(missing, ", "))
	}
	return cfg, nil
}

// Summary reports what the seed provisioned so the operator can wire the
// worker and relying applications.
type Summary struct {
	Admin *models.User
	Demo  *models.User
	AppA  *models.Application
	AppB  *models.Application
	Config
}

// Seed creates the demo users, groups, applications, redirect URIs, group
// policies, and memberships. It is safe to call repeatedly.
func (c Config) Seed(ctx context.Context, db *gorm.DB) (*Summary, error) {
	users := repository.NewUserRepository(db)
	groups := repository.NewGroupRepository(db)
	apps := repository.NewApplicationRepository(db)
	policies := repository.NewPolicyRepository(db)

	admin, err := ensureUser(ctx, users, c.AdminName, c.AdminEmail, c.AdminPassword)
	if err != nil {
		return nil, fmt.Errorf("seed admin user: %w", err)
	}
	demo, err := ensureUser(ctx, users, c.DemoName, c.DemoEmail, c.DemoPassword)
	if err != nil {
		return nil, fmt.Errorf("seed demo user: %w", err)
	}

	admins, err := ensureGroup(ctx, db, groups, "administrators", "Users permitted to administer the Auth Provider")
	if err != nil {
		return nil, fmt.Errorf("seed administrators group: %w", err)
	}
	appAUsers, err := ensureGroup(ctx, db, groups, "app-a-users", "Users permitted to access App A")
	if err != nil {
		return nil, fmt.Errorf("seed app-a-users group: %w", err)
	}
	appBUsers, err := ensureGroup(ctx, db, groups, "app-b-users", "Users permitted to access App B")
	if err != nil {
		return nil, fmt.Errorf("seed app-b-users group: %w", err)
	}

	if err := ensureMembership(ctx, db, admins.ID, admin.ID); err != nil {
		return nil, fmt.Errorf("add admin to administrators: %w", err)
	}
	if err := ensureMembership(ctx, db, appAUsers.ID, demo.ID); err != nil {
		return nil, fmt.Errorf("add demo to app-a-users: %w", err)
	}
	if err := ensureMembership(ctx, db, appBUsers.ID, demo.ID); err != nil {
		return nil, fmt.Errorf("add demo to app-b-users: %w", err)
	}

	appA, err := ensureApplication(ctx, apps, AppAID, "App A", c.AppAClientID, c.AppASecret, c.AppARedirect, c.AppALogout, c.AppABase)
	if err != nil {
		return nil, fmt.Errorf("seed App A: %w", err)
	}
	appB, err := ensureApplication(ctx, apps, AppBID, "App B", c.AppBClientID, c.AppBSecret, c.AppBRedirect, c.AppBLogout, c.AppBBase)
	if err != nil {
		return nil, fmt.Errorf("seed App B: %w", err)
	}

	if err := ensurePolicy(ctx, policies, appA.ID, appAUsers.ID); err != nil {
		return nil, fmt.Errorf("seed App A policy: %w", err)
	}
	if err := ensurePolicy(ctx, policies, appB.ID, appBUsers.ID); err != nil {
		return nil, fmt.Errorf("seed App B policy: %w", err)
	}

	return &Summary{Admin: admin, Demo: demo, AppA: appA, AppB: appB, Config: c}, nil
}

func ensureUser(ctx context.Context, repo *repository.UserRepository, name, email, password string) (*models.User, error) {
	user, err := repo.FindByEmail(ctx, email)
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, repository.ErrUserNotFound) {
		return nil, err
	}
	return repo.CreateUser(ctx, name, email, password, "active")
}

func ensureGroup(ctx context.Context, db *gorm.DB, repo *repository.GroupRepository, name, description string) (*models.Group, error) {
	var group models.Group
	err := db.WithContext(ctx).Where("name = ?", name).First(&group).Error
	if err == nil {
		return &group, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	group = models.Group{Name: name, Description: &description}
	if err := repo.Create(ctx, &group); err != nil {
		return nil, err
	}
	return &group, nil
}

func ensureMembership(ctx context.Context, db *gorm.DB, groupID, userID uuid.UUID) error {
	var count int64
	if err := db.WithContext(ctx).Model(&models.UserGroup{}).
		Where("group_id = ? AND user_id = ?", groupID, userID).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	return db.WithContext(ctx).Create(&models.UserGroup{GroupID: groupID, UserID: userID}).Error
}

func ensureApplication(ctx context.Context, repo *repository.ApplicationRepository, id uuid.UUID, name, clientID, secret, redirect, logout, launch string) (*models.Application, error) {
	app, err := repo.FindByClientID(ctx, clientID)
	if err == nil {
		// Re-run after a partial failure: make sure the redirect URI exists.
		ok, derr := repo.HasExactRedirectURI(ctx, app.ID, redirect)
		if derr != nil {
			return nil, derr
		}
		if !ok {
			if aerr := repo.AddRedirectURI(ctx, &models.ApplicationRedirectURI{ApplicationID: app.ID, RedirectURI: redirect}); aerr != nil {
				return nil, aerr
			}
		}
		return app, nil
	}
	if !errors.Is(err, repository.ErrApplicationNotFound) {
		return nil, err
	}
	application := &models.Application{
		ID:                    id,
		Name:                  name,
		ClientID:              clientID,
		Status:                "active",
		LogoutNotificationURL: logout,
		LaunchURL:             &launch,
	}
	if err := repo.CreateWithSecretAndRedirect(ctx, application, secret, redirect); err != nil {
		return nil, err
	}
	return application, nil
}

func ensurePolicy(ctx context.Context, repo *repository.PolicyRepository, applicationID, groupID uuid.UUID) error {
	return repo.Set(ctx, &models.ApplicationGroupPolicy{
		ApplicationID: applicationID,
		GroupID:       groupID,
		Effect:        "allow",
	})
}

// Render returns the provisioning output: the credentials needed to operate the
// demo and the worker APP_TARGETS_JSON. This is the intended place raw secrets
// are surfaced.
func (s *Summary) Render() string {
	var b strings.Builder
	b.WriteString("\n=== Auth Provider demo seed complete ===\n")
	b.WriteString("Admin login: " + s.Admin.Email + " / " + s.Config.AdminPassword + "\n")
	b.WriteString("Demo login:  " + s.Demo.Email + " / " + s.Config.DemoPassword + "\n\n")
	b.WriteString("Worker APP_TARGETS_JSON:\n")
	b.WriteString(fmt.Sprintf(
		`[{"name":"App A","applicationId":"%s","logoutNotifyURL":"%s","internalAuthToken":"%s"},{"name":"App B","applicationId":"%s","logoutNotifyURL":"%s","internalAuthToken":"%s"}]`+"\n",
		s.AppA.ID, s.Config.AppALogout, s.Config.InternalTokenA,
		s.AppB.ID, s.Config.AppBLogout, s.Config.InternalTokenB))
	b.WriteString("\nApp A: client_id=" + s.Config.AppAClientID + " client_secret=" + s.Config.AppASecret +
		" redirect_uri=" + s.Config.AppARedirect + " internal_auth_token=" + s.Config.InternalTokenA + "\n")
	b.WriteString("App B: client_id=" + s.Config.AppBClientID + " client_secret=" + s.Config.AppBSecret +
		" redirect_uri=" + s.Config.AppBRedirect + " internal_auth_token=" + s.Config.InternalTokenB + "\n")
	return b.String()
}
