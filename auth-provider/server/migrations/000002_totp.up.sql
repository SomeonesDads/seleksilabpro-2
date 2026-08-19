CREATE TABLE IF NOT EXISTS user_totp_credentials (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    encrypted_secret BYTEA NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

DROP TRIGGER IF EXISTS trg_user_totp_credentials_updated_at ON user_totp_credentials;
CREATE TRIGGER trg_user_totp_credentials_updated_at BEFORE UPDATE ON user_totp_credentials
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
