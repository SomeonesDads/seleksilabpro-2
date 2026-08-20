ALTER TABLE user_totp_credentials
    DROP COLUMN IF EXISTS enroll_locked_until,
    DROP COLUMN IF EXISTS enroll_attempts;
