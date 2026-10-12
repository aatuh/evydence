-- Existing rows retain their history. NULL activity means created_at; no
-- upgrade-time timestamp grants an idle session a fresh authentication window.
ALTER TABLE sso_sessions
    ADD COLUMN last_used_at timestamptz,
    ADD COLUMN maximum_lifetime_seconds bigint NOT NULL DEFAULT 43200,
    ADD COLUMN idle_timeout_seconds bigint NOT NULL DEFAULT 1800,
    ADD CONSTRAINT sso_session_lifecycle_policy CHECK (
        maximum_lifetime_seconds BETWEEN 60 AND 43200 AND
        idle_timeout_seconds BETWEEN 60 AND maximum_lifetime_seconds
    );
