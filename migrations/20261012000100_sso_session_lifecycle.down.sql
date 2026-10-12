-- Dropping live activity or tightened policy would lose security metadata.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM sso_sessions WHERE last_used_at IS NOT NULL
        OR maximum_lifetime_seconds <> 43200 OR idle_timeout_seconds <> 1800) THEN
        RAISE EXCEPTION 'cannot downgrade after session lifecycle activity or policy has been recorded';
    END IF;
END $$;
ALTER TABLE sso_sessions DROP CONSTRAINT sso_session_lifecycle_policy,
    DROP COLUMN last_used_at, DROP COLUMN maximum_lifetime_seconds,
    DROP COLUMN idle_timeout_seconds;
