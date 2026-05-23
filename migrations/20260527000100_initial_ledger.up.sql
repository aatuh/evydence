CREATE TABLE IF NOT EXISTS tenants (
  id text PRIMARY KEY,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS api_keys (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  name text NOT NULL,
  prefix text NOT NULL,
  hash text NOT NULL,
  scopes jsonb NOT NULL,
  expires_at timestamptz,
  revoked_at timestamptz,
  last_used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS api_keys_tenant_prefix_idx ON api_keys(tenant_id, prefix);

CREATE TABLE IF NOT EXISTS products (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  name text NOT NULL,
  slug text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, slug)
);

CREATE TABLE IF NOT EXISTS projects (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  product_id text NOT NULL REFERENCES products(id),
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS releases (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  product_id text NOT NULL REFERENCES products(id),
  version text NOT NULL,
  state text NOT NULL,
  frozen_at timestamptz,
  approved_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, product_id, version)
);

CREATE TABLE IF NOT EXISTS artifacts (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  name text NOT NULL,
  media_type text NOT NULL,
  size bigint NOT NULL,
  digest text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, digest)
);

CREATE TABLE IF NOT EXISTS evidence_items (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  product_id text,
  project_id text,
  release_id text,
  type text NOT NULL,
  subtype text,
  title text NOT NULL,
  source_system text NOT NULL,
  source_identity jsonb,
  collector_id text,
  uploaded_by text,
  observed_at timestamptz NOT NULL,
  schema_version text NOT NULL,
  payload_ref text,
  payload_hash text NOT NULL,
  payload_media_type text,
  payload_size bigint,
  canonical_hash text NOT NULL,
  canonicalization text NOT NULL,
  subject_refs jsonb,
  related_evidence_refs jsonb,
  supersedes text,
  superseded_by text,
  trust_level text NOT NULL,
  verification_status text NOT NULL,
  signature_refs jsonb,
  chain_entry_id text,
  tags jsonb,
  metadata jsonb,
  warnings jsonb,
  limitations jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS evidence_items_tenant_type_created_idx ON evidence_items(tenant_id, type, created_at);
CREATE INDEX IF NOT EXISTS evidence_items_tenant_release_idx ON evidence_items(tenant_id, release_id);

CREATE TABLE IF NOT EXISTS audit_chain_entries (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  sequence bigint NOT NULL,
  entry_type text NOT NULL,
  subject_type text NOT NULL,
  subject_id text NOT NULL,
  actor_type text NOT NULL,
  actor_id text NOT NULL,
  occurred_at timestamptz NOT NULL,
  payload_hash text,
  canonical_entry_hash text NOT NULL,
  previous_entry_hash text NOT NULL,
  entry_hash text NOT NULL,
  signature_ref text,
  metadata jsonb,
  schema_version text NOT NULL,
  UNIQUE (tenant_id, sequence)
);

CREATE TABLE IF NOT EXISTS signing_keys (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  kid text NOT NULL,
  algorithm text NOT NULL,
  status text NOT NULL,
  public_key text NOT NULL,
  encrypted_private_key bytea,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);

CREATE TABLE IF NOT EXISTS signatures (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  subject_type text NOT NULL,
  subject_id text NOT NULL,
  key_id text NOT NULL REFERENCES signing_keys(id),
  algorithm text NOT NULL,
  value text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sboms (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  evidence_id text NOT NULL REFERENCES evidence_items(id),
  release_id text,
  artifact_id text,
  format text NOT NULL,
  spec_version text NOT NULL,
  component_count integer NOT NULL,
  components jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS vulnerability_scans (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  evidence_id text NOT NULL REFERENCES evidence_items(id),
  scanner text NOT NULL,
  target_ref text NOT NULL,
  summary jsonb NOT NULL,
  findings jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS openapi_contracts (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  product_id text NOT NULL,
  release_id text,
  version text NOT NULL,
  hash text NOT NULL,
  path_count integer NOT NULL,
  evidence_id text NOT NULL REFERENCES evidence_items(id),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS policy_evaluations (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  release_id text NOT NULL,
  result text NOT NULL,
  policy_set text NOT NULL,
  checks jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS release_bundles (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  release_id text NOT NULL,
  state text NOT NULL,
  manifest jsonb NOT NULL,
  manifest_hash text NOT NULL,
  signature_refs jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz,
  revoked_at timestamptz
);

CREATE TABLE IF NOT EXISTS verification_results (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  subject_type text NOT NULL,
  subject_id text NOT NULL,
  result text NOT NULL,
  checks jsonb NOT NULL,
  verified_at timestamptz NOT NULL
);
