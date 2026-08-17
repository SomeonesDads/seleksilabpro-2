package repository

import (
	"context"
	"regexp"
	"testing"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func dryRunDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.New(postgres.Config{DSN: "host=localhost user=test dbname=test", PreferSimpleProtocol: true}), &gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatalf("open dry-run db: %v", err)
	}
	return db
}

func TestAuthorizationCodeConsumeAtomicallyIncludesReplayAndExpiryGuards(t *testing.T) {
	db := dryRunDB(t)
	query := db.ToSQL(func(tx *gorm.DB) *gorm.DB {
		return tx.WithContext(context.Background()).Model(&models.AuthorizationCode{}).
			Where("id = ? AND used_at IS NULL AND expires_at > now()", uuid.New()).
			UpdateColumn("used_at", gorm.Expr("now()"))
	})
	for _, want := range []string{"used_at IS NULL", "expires_at > now()"} {
		if !regexp.MustCompile(`(?i)` + regexp.QuoteMeta(want)).MatchString(query) {
			t.Fatalf("generated consume query %q does not contain %q", query, want)
		}
	}
}

func TestApplicationExactRedirectURIUsesEqualityPredicate(t *testing.T) {
	db := dryRunDB(t)
	query := db.ToSQL(func(tx *gorm.DB) *gorm.DB {
		return tx.WithContext(context.Background()).Model(&models.ApplicationRedirectURI{}).
			Where("application_id = ? AND redirect_uri = ?", uuid.New(), "https://app.example/callback").Count(new(int64))
	})
	if !regexp.MustCompile(`(?i)redirect_uri\s*=`).MatchString(query) {
		t.Fatalf("generated redirect query %q does not use exact equality", query)
	}
}
