CREATE TABLE IF NOT EXISTS ledger_state (
  id text PRIMARY KEY,
  state jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS idempotency_records (
  tenant_id text NOT NULL,
  actor_key_id text NOT NULL,
  method text NOT NULL,
  path text NOT NULL,
  idempotency_key text NOT NULL,
  request_hash text NOT NULL,
  status integer NOT NULL,
  response jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, actor_key_id, method, path, idempotency_key)
);

CREATE TABLE IF NOT EXISTS outbox_jobs (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  kind text NOT NULL,
  subject_type text NOT NULL,
  subject_id text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL,
  attempts integer NOT NULL DEFAULT 0,
  max_attempts integer NOT NULL DEFAULT 5,
  run_after timestamptz NOT NULL DEFAULT now(),
  locked_at timestamptz,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS outbox_jobs_claim_idx
  ON outbox_jobs(status, run_after, created_at)
  WHERE status IN ('queued', 'retrying');

CREATE INDEX IF NOT EXISTS outbox_jobs_tenant_subject_idx
  ON outbox_jobs(tenant_id, subject_type, subject_id);

CREATE TABLE IF NOT EXISTS object_payloads (
  tenant_id text NOT NULL,
  object_key text PRIMARY KEY,
  digest text NOT NULL,
  media_type text,
  size bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS object_payloads_tenant_digest_idx
  ON object_payloads(tenant_id, digest);

CREATE TABLE IF NOT EXISTS chain_checkpoints (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  sequence bigint NOT NULL,
  head_hash text NOT NULL,
  signature_ref text,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, sequence)
);

CREATE INDEX IF NOT EXISTS products_tenant_created_idx ON products(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS projects_tenant_product_idx ON projects(tenant_id, product_id);
CREATE INDEX IF NOT EXISTS releases_tenant_product_idx ON releases(tenant_id, product_id, created_at);
CREATE INDEX IF NOT EXISTS artifacts_tenant_created_idx ON artifacts(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS sboms_tenant_release_idx ON sboms(tenant_id, release_id);
CREATE INDEX IF NOT EXISTS vulnerability_scans_tenant_created_idx ON vulnerability_scans(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS openapi_contracts_tenant_product_idx ON openapi_contracts(tenant_id, product_id);
CREATE INDEX IF NOT EXISTS release_bundles_tenant_release_idx ON release_bundles(tenant_id, release_id);
CREATE INDEX IF NOT EXISTS verification_results_tenant_subject_idx ON verification_results(tenant_id, subject_type, subject_id);
