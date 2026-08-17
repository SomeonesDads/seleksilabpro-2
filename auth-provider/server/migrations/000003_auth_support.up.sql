-- JWT access-token metadata. The signed token is intentionally not stored.
CREATE TABLE IF NOT EXISTS access_tokens (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    jti            UUID NOT NULL UNIQUE,
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    session_id     UUID NOT NULL REFERENCES sso_sessions(id) ON DELETE CASCADE,
    expires_at     TIMESTAMPTZ NOT NULL,
    revoked_at     TIMESTAMPTZ,
    revoke_reason  VARCHAR(100),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT access_tokens_revocation_consistency CHECK (
        (revoked_at IS NULL AND revoke_reason IS NULL)
        OR revoked_at IS NOT NULL
    )
);

CREATE INDEX IF NOT EXISTS idx_access_tokens_user_id ON access_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_application_id ON access_tokens(application_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_session_id ON access_tokens(session_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_active_expiry
    ON access_tokens(expires_at) WHERE revoked_at IS NULL;

-- Reverse membership and policy lookups used when evaluating application access.
CREATE INDEX IF NOT EXISTS idx_user_groups_group_id ON user_groups(group_id);
CREATE INDEX IF NOT EXISTS idx_application_group_policies_group_id
    ON application_group_policies(group_id);

-- The existing unique constraints cover application/client and application/URI
-- lookup. These indexes cover the remaining common audit and outbox lookups.
CREATE INDEX IF NOT EXISTS idx_audit_logs_application_id ON audit_logs(application_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_session_id ON audit_logs(session_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_events_user_id ON events(user_id);
CREATE INDEX IF NOT EXISTS idx_events_session_id ON events(central_session_id);
CREATE INDEX IF NOT EXISTS idx_events_application_id ON events(application_id);

-- Preserve audit/outbox rows when an associated principal is removed.
ALTER TABLE audit_logs
    ADD CONSTRAINT audit_logs_actor_id_fkey
        FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL,
    ADD CONSTRAINT audit_logs_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    ADD CONSTRAINT audit_logs_application_id_fkey
        FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE SET NULL,
    ADD CONSTRAINT audit_logs_session_id_fkey
        FOREIGN KEY (session_id) REFERENCES sso_sessions(id) ON DELETE SET NULL;

ALTER TABLE events
    ADD CONSTRAINT events_central_session_id_fkey
        FOREIGN KEY (central_session_id) REFERENCES sso_sessions(id) ON DELETE SET NULL,
    ADD CONSTRAINT events_application_id_fkey
        FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE SET NULL;
