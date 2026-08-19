DROP TRIGGER IF EXISTS trg_applications_updated_at ON applications;
DROP TRIGGER IF EXISTS trg_groups_updated_at ON groups;
DROP TRIGGER IF EXISTS trg_users_updated_at ON users;
DROP FUNCTION IF EXISTS set_updated_at();

DROP TABLE IF EXISTS event_deliveries;
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS authorization_codes;
DROP TABLE IF EXISTS mfa_login_challenges;
DROP TABLE IF EXISTS sso_sessions;
DROP TABLE IF EXISTS application_group_policies;
DROP TABLE IF EXISTS application_redirect_uris;
DROP TABLE IF EXISTS applications;
DROP TABLE IF EXISTS user_groups;
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS users;
