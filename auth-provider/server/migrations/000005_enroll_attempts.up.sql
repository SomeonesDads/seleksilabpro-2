ALTER TABLE user_totp_credentials
    ADD COLUMN IF NOT EXISTS enroll_attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS enroll_locked_until TIMESTAMPTZ;
