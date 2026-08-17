package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSSOSessionIsValidRequiresActiveUnexpiredAndUnrevoked(t *testing.T) {
	now := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)
	base := SSOSession{ID: uuid.New(), Status: "active", ExpiresAt: now.Add(time.Minute)}
	if !base.IsValid(now) {
		t.Fatal("active, unexpired, unrevoked session should be valid")
	}

	cases := []struct {
		name   string
		mutate func(*SSOSession)
	}{
		{name: "inactive", mutate: func(s *SSOSession) { s.Status = "revoked" }},
		{name: "expired", mutate: func(s *SSOSession) { s.ExpiresAt = now }},
		{name: "revoked timestamp", mutate: func(s *SSOSession) { s.RevokedAt = &now }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			session := base
			tc.mutate(&session)
			if session.IsValid(now) {
				t.Fatalf("%s session should be invalid", tc.name)
			}
		})
	}
}
