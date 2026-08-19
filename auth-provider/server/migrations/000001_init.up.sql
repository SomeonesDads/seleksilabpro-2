CREATE EXTENSION IF NOT EXISTS "pgcrypto"; -- import gen_random_uuid()

-- main
CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          VARCHAR(255) NOT NULL,
    email         VARCHAR(320) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    status        VARCHAR(20)  NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_groups (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id   UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, group_id)
);

CREATE TABLE IF NOT EXISTS applications (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                   VARCHAR(255) NOT NULL,
    client_id              VARCHAR(255) NOT NULL UNIQUE,
    client_secret_hash     VARCHAR(255),
    status                 VARCHAR(20)  NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
    launch_url             TEXT,
    logout_notification_url TEXT NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS application_redirect_uris (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    redirect_uri   TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (application_id, redirect_uri)
);

CREATE TABLE IF NOT EXISTS application_group_policies (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    group_id       UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    effect         VARCHAR(20) NOT NULL DEFAULT 'allow' CHECK (effect IN ('allow')),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (application_id, group_id, effect)
);

CREATE TABLE IF NOT EXISTS sso_sessions (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token_hash VARCHAR(255) NOT NULL UNIQUE,
    status             VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked')),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    last_activity_at   TIMESTAMPTZ,
    revoked_at         TIMESTAMPTZ,
    revoke_reason      VARCHAR(100),
    ip_address         VARCHAR(64),
    user_agent         TEXT
);

CREATE TABLE IF NOT EXISTS mfa_login_challenges (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sso_sessions_user_id ON sso_sessions(user_id);

CREATE TABLE IF NOT EXISTS authorization_codes (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code_hash             VARCHAR(255) NOT NULL UNIQUE,
    user_id               UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    application_id        UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    sso_session_id        UUID NOT NULL REFERENCES sso_sessions(id) ON DELETE CASCADE,
    redirect_uri          TEXT NOT NULL,
    code_challenge        VARCHAR(255) NOT NULL,
    code_challenge_method VARCHAR(10)  NOT NULL DEFAULT 'S256' CHECK (code_challenge_method = 'S256'),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at            TIMESTAMPTZ NOT NULL,
    used_at               TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_auth_codes_app_id ON authorization_codes(application_id);

-- Logging

CREATE TABLE IF NOT EXISTS audit_logs (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type     VARCHAR(100) NOT NULL,
    actor_id       UUID,
    user_id        UUID,
    application_id UUID,
    session_id     UUID,
    result         VARCHAR(20) NOT NULL CHECK (result IN ('success', 'failed')),
    metadata       JSONB,
    ip_address     VARCHAR(64),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);

-- RabbitMQ shi

CREATE TABLE IF NOT EXISTS events (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type        VARCHAR(100) NOT NULL, -- SessionRevoked | PasswordChanged | AccessPolicyChanged
    user_id           UUID NOT NULL REFERENCES users(id),
    central_session_id UUID,
    application_id    UUID, -- NULL = semua app di session user skrg
    payload           JSONB NOT NULL,
    status            VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'published')),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_events_unpublished ON events(created_at) WHERE published_at IS NULL;

CREATE TABLE IF NOT EXISTS event_deliveries (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id       UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    status         VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'succeeded', 'retrying', 'failed')),
    attempt_count  INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMPTZ,
    next_retry_at  TIMESTAMPTZ,
    processed_at   TIMESTAMPTZ,
    last_error     TEXT,
    UNIQUE (event_id, application_id)
);
CREATE INDEX IF NOT EXISTS idx_event_deliveries_retry ON event_deliveries (status, next_retry_at); 


-- Non-Tables

CREATE OR REPLACE FUNCTION set_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_users_updated_at ON users;
CREATE TRIGGER trg_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_groups_updated_at ON groups;
CREATE TRIGGER trg_groups_updated_at BEFORE UPDATE ON groups
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_applications_updated_at ON applications;
CREATE TRIGGER trg_applications_updated_at BEFORE UPDATE ON applications
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
