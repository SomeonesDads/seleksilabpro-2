package config

import "testing"

func TestLoadParsesApplicationTargets(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://db")
	t.Setenv("BROKER_URL", "amqp://broker")
	t.Setenv("APP_TARGETS_JSON", `[{"name":"App A","applicationId":"00000000-0000-0000-0000-000000000001","logoutNotifyURL":"http://app-a/internal/logout","internalAuthToken":"secret"}]`)

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Targets) != 1 || cfg.Targets[0].ApplicationID != "00000000-0000-0000-0000-000000000001" || cfg.Targets[0].InternalAuthToken != "secret" {
		t.Fatalf("targets = %+v", cfg.Targets)
	}
}

func TestLoadRejectsInvalidApplicationTarget(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://db")
	t.Setenv("BROKER_URL", "amqp://broker")
	t.Setenv("APP_TARGETS_JSON", `[{"applicationId":"not-a-uuid","logoutNotifyURL":"http://app/internal/logout"}]`)

	if _, err := Load(); err == nil {
		t.Fatal("expected invalid target error")
	}
}

func TestLoadRequiresApplicationTargetCredentials(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://db")
	t.Setenv("BROKER_URL", "amqp://broker")
	t.Setenv("APP_TARGETS_JSON", `[{"applicationId":"00000000-0000-0000-0000-000000000001","logoutNotifyURL":"http://app/internal/logout"}]`)

	if _, err := Load(); err == nil {
		t.Fatal("expected missing internalAuthToken error")
	}
}

func TestLoadRequiresApplicationTargets(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://db")
	t.Setenv("BROKER_URL", "amqp://broker")
	t.Setenv("APP_TARGETS_JSON", "")

	if _, err := Load(); err == nil {
		t.Fatal("expected missing APP_TARGETS_JSON error")
	}
}
