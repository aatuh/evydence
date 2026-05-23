CREATE TABLE IF NOT EXISTS control_frameworks (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  name text NOT NULL,
  slug text NOT NULL,
  version text NOT NULL,
  description text,
  status text NOT NULL,
  schema_version text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, slug, version)
);

CREATE INDEX IF NOT EXISTS control_frameworks_tenant_slug_idx
  ON control_frameworks(tenant_id, slug, version);

CREATE TABLE IF NOT EXISTS security_controls (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  framework_id text NOT NULL REFERENCES control_frameworks(id),
  code text NOT NULL,
  title text NOT NULL,
  objective text NOT NULL,
  evidence_requirements jsonb NOT NULL,
  applicability jsonb NOT NULL,
  limitations jsonb NOT NULL,
  schema_version text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, framework_id, code)
);

CREATE INDEX IF NOT EXISTS security_controls_tenant_framework_idx
  ON security_controls(tenant_id, framework_id, code);

CREATE TABLE IF NOT EXISTS control_evidence (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  control_id text NOT NULL REFERENCES security_controls(id),
  evidence_type text NOT NULL,
  subject_type text NOT NULL,
  subject_id text NOT NULL,
  product_id text,
  release_id text,
  confidence text NOT NULL,
  notes text,
  schema_version text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS control_evidence_unique_link_idx
  ON control_evidence(tenant_id, control_id, evidence_type, subject_type, subject_id, coalesce(product_id, ''), coalesce(release_id, ''));

CREATE INDEX IF NOT EXISTS control_evidence_tenant_control_idx
  ON control_evidence(tenant_id, control_id, created_at);

CREATE INDEX IF NOT EXISTS control_evidence_tenant_scope_idx
  ON control_evidence(tenant_id, product_id, release_id);
