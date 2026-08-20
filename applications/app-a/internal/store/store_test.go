package store

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSessionLifecycle(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()

	raw := "raw-session-token-value"
	sess := &LocalSession{
		ID:               uuid.New(),
		SessionTokenHash: raw, // callers hash before persisting; here we just need a value
		ExternalUserID:   uuid.NewString(),
		CentralSessionID: uuid.NewString(),
		ApplicationID:    "app-a",
		Status:           "active",
		ExpiresAt:        time.Now().Add(time.Hour),
	}
	if err := st.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	got, err := st.FindSessionByTokenHash(ctx, raw)
	if err != nil || got == nil {
		t.Fatalf("find session: %v (got=%v)", err, got)
	}
	if !st.IsSessionActive(got, time.Now()) {
		t.Fatal("expected active session")
	}

	if err := st.RevokeSession(ctx, sess.ID, "local_logout", time.Now().UTC()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	got, _ = st.FindSessionByTokenHash(ctx, raw)
	if got != nil && st.IsSessionActive(got, time.Now()) {
		t.Fatal("expected revoked session to be inactive")
	}
}

func TestRevokeSessionsByUser(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	userID := uuid.NewString()

	for i := 0; i < 2; i++ {
		sess := &LocalSession{
			ID:             uuid.New(),
			SessionTokenHash: uuid.NewString(),
			ExternalUserID: userID,
			ApplicationID:  "app-a",
			Status:         "active",
			ExpiresAt:      time.Now().Add(time.Hour),
		}
		if err := st.CreateSession(ctx, sess); err != nil {
			t.Fatalf("create: %v", err)
		}
	}

	n, err := st.RevokeSessionsByUser(ctx, userID, "sso_logout", time.Now().UTC())
	if err != nil {
		t.Fatalf("revoke by user: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 revoked, got %d", n)
	}

	// Second pass is a no-op (idempotent status filter).
	n2, _ := st.RevokeSessionsByUser(ctx, userID, "sso_logout", time.Now().UTC())
	if n2 != 0 {
		t.Fatalf("expected 0 on repeat, got %d", n2)
	}
}

func TestEventIdempotency(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	eventID := uuid.New()

	first, err := st.RecordEvent(ctx, eventID, "SessionRevoked", "local_sessions_revoked")
	if err != nil {
		t.Fatalf("record event: %v", err)
	}
	if !first {
		t.Fatal("first record should be new")
	}
	done, _ := st.EventProcessed(ctx, eventID)
	if !done {
		t.Fatal("event should be marked processed")
	}
	second, err := st.RecordEvent(ctx, eventID, "SessionRevoked", "local_sessions_revoked")
	if err != nil {
		t.Fatalf("record duplicate: %v", err)
	}
	if second {
		t.Fatal("duplicate record should be idempotent (false)")
	}
}

func TestProcessRevocationConcurrentExactlyOnce(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	eventID := uuid.New()
	userID := uuid.NewString()
	const nSessions = 5

	for i := 0; i < nSessions; i++ {
		sess := &LocalSession{
			ID:               uuid.New(),
			SessionTokenHash: uuid.NewString(),
			ExternalUserID:   userID,
			ApplicationID:    "app-a",
			Status:           "active",
			ExpiresAt:        time.Now().Add(time.Hour),
		}
		if err := st.CreateSession(ctx, sess); err != nil {
			t.Fatalf("create session: %v", err)
		}
	}

	const workers = 12
	var (
		mu          sync.Mutex
		insertCount int
		revokedSum  int64
	)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			inserted, revoked, err := st.ProcessRevocation(ctx, eventID, "PasswordChanged", "local_sessions_revoked", userID, "", "sso_logout", time.Now().UTC())
			if err != nil {
				t.Errorf("process revocation: %v", err)
				return
			}
			mu.Lock()
			if inserted {
				insertCount++
			}
			revokedSum += revoked
			mu.Unlock()
		}()
	}
	wg.Wait()

	if insertCount != 1 {
		t.Fatalf("expected exactly one inserted=true, got %d", insertCount)
	}
	if revokedSum != nSessions {
		t.Fatalf("expected revoked sum %d (applied once), got %d", nSessions, revokedSum)
	}
	active, err := st.ListActiveByUser(ctx, userID)
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("expected 0 active sessions after revocation, got %d", len(active))
	}
}

func TestSchemaStoresNoProhibitedFields(t *testing.T) {
	st := openTestStore(t)

	forbidden := map[string]bool{
		"password":           true,
		"password_hash":      true,
		"client_secret":      true,
		"client_secret_hash": true,
		"access_token":       true,
		"authorization_code": true,
		"code":               true,
		"session_token":      true,
		"raw_token":          true,
	}
	tables := []string{"local_sessions", "profile_cache", "processed_events", "activity_logs"}
	for _, table := range tables {
		var names []string
		if err := st.DB.Raw(
			"SELECT column_name FROM information_schema.columns WHERE table_name = ?", table,
		).Scan(&names).Error; err != nil {
			t.Fatalf("list columns for %s: %v", table, err)
		}
		for _, c := range names {
			if forbidden[c] {
				t.Fatalf("table %s stores prohibited field %q", table, c)
			}
		}
	}

	// The local session must hash its token, never store the raw value.
	var count int64
	if err := st.DB.Raw(
		"SELECT count(*) FROM information_schema.columns WHERE table_name = 'local_sessions' AND column_name = 'session_token_hash'",
	).Scan(&count).Error; err != nil || count != 1 {
		t.Fatal("local_sessions must store session_token_hash")
	}
}
