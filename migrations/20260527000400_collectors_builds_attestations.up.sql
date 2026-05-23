CREATE TABLE IF NOT EXISTS collectors (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  name text NOT NULL,
  type text NOT NULL,
  version text NOT NULL,
  api_key_id text NOT NULL,
  status text NOT NULL,
  allowed_scopes jsonb NOT NULL,
  last_seen_at timestamptz,
  schema_version text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS collectors_tenant_type_idx
  ON collectors(tenant_id, type, status);

CREATE TABLE IF NOT EXISTS build_runs (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  project_id text NOT NULL,
  release_id text NOT NULL,
  collector_id text,
  provider text NOT NULL,
  commit_sha text NOT NULL,
  repository text,
  workflow_ref text,
  run_id text,
  run_attempt integer,
  job_id text,
  actor text,
  ref text,
  oidc_subject text,
  status text NOT NULL,
  started_at timestamptz NOT NULL,
  finished_at timestamptz,
  parameters_hash text,
  environment_hash text,
  source_identity jsonb,
  outputs jsonb NOT NULL,
  schema_version text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS build_runs_tenant_release_idx
  ON build_runs(tenant_id, release_id, status, created_at);

CREATE INDEX IF NOT EXISTS build_runs_tenant_project_idx
  ON build_runs(tenant_id, project_id, created_at);

CREATE UNIQUE INDEX IF NOT EXISTS build_runs_tenant_provider_run_idx
  ON build_runs(tenant_id, provider, repository, run_id, run_attempt)
  WHERE repository IS NOT NULL AND run_id IS NOT NULL AND run_attempt IS NOT NULL;

CREATE TABLE IF NOT EXISTS build_attestations (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  build_id text NOT NULL,
  evidence_id text NOT NULL,
  payload_ref text,
  payload_hash text NOT NULL,
  payload_size bigint NOT NULL,
  payload_type text NOT NULL,
  predicate_type text NOT NULL,
  subject_digests jsonb NOT NULL,
  builder_id text,
  build_type text,
  materials_count integer NOT NULL,
  signature_count integer NOT NULL,
  verification_status text NOT NULL,
  schema_version text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS build_attestations_tenant_build_idx
  ON build_attestations(tenant_id, build_id, created_at);

CREATE INDEX IF NOT EXISTS build_attestations_tenant_payload_hash_idx
  ON build_attestations(tenant_id, payload_hash);
