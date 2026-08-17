ALTER TABLE events
    DROP CONSTRAINT IF EXISTS events_application_id_fkey,
    DROP CONSTRAINT IF EXISTS events_central_session_id_fkey;

ALTER TABLE audit_logs
    DROP CONSTRAINT IF EXISTS audit_logs_session_id_fkey,
    DROP CONSTRAINT IF EXISTS audit_logs_application_id_fkey,
    DROP CONSTRAINT IF EXISTS audit_logs_user_id_fkey,
    DROP CONSTRAINT IF EXISTS audit_logs_actor_id_fkey;

DROP INDEX IF EXISTS idx_events_application_id;
DROP INDEX IF EXISTS idx_events_session_id;
DROP INDEX IF EXISTS idx_events_user_id;
DROP INDEX IF EXISTS idx_audit_logs_created_at;
DROP INDEX IF EXISTS idx_audit_logs_session_id;
DROP INDEX IF EXISTS idx_audit_logs_application_id;
DROP INDEX IF EXISTS idx_application_group_policies_group_id;
DROP INDEX IF EXISTS idx_user_groups_group_id;
DROP INDEX IF EXISTS idx_access_tokens_active_expiry;
DROP INDEX IF EXISTS idx_access_tokens_session_id;
DROP INDEX IF EXISTS idx_access_tokens_application_id;
DROP INDEX IF EXISTS idx_access_tokens_user_id;

DROP TABLE IF EXISTS access_tokens;
