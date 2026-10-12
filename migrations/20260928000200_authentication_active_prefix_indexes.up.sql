CREATE INDEX IF NOT EXISTS api_keys_auth_prefix_idx
    ON api_keys (prefix, id) WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS sso_sessions_auth_prefix_idx
    ON sso_sessions (prefix, id) WHERE revoked_at IS NULL;
