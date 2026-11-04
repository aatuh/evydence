CREATE TABLE IF NOT EXISTS schema_migration_operations (
 sequence bigint PRIMARY KEY CHECK (sequence > 0),
 operation_id text NOT NULL,
 phase text NOT NULL CHECK (phase IN ('started','succeeded','failed','uncertain')),
 target_version text NOT NULL,
 runtime_role name NOT NULL,
 performed_by name NOT NULL DEFAULT session_user,
 committed_migrations integer CHECK (committed_migrations >= 0),
 policy_sha256 text NOT NULL CHECK (policy_sha256 ~ '^[a-f0-9]{64}$'),
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 schema_version text NOT NULL DEFAULT 'migration-operation.v1',
 CHECK ((phase = 'uncertain') = (committed_migrations IS NULL)),
 UNIQUE (operation_id,phase)
);
