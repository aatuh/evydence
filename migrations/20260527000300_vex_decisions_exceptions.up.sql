CREATE TABLE IF NOT EXISTS vex_documents (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  evidence_id text NOT NULL REFERENCES evidence_items(id),
  release_id text,
  artifact_id text,
  format text NOT NULL,
  author text NOT NULL,
  version text,
  statement_count integer NOT NULL,
  status_summary jsonb NOT NULL,
  schema_version text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS vex_documents_tenant_release_idx
  ON vex_documents(tenant_id, release_id, created_at);

CREATE TABLE IF NOT EXISTS vulnerability_decisions (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  finding_id text NOT NULL,
  scan_id text NOT NULL,
  release_id text,
  vulnerability text NOT NULL,
  component text,
  status text NOT NULL,
  justification text NOT NULL,
  impact_statement text,
  action_statement text,
  source text NOT NULL,
  evidence_id text,
  vex_document_id text,
  supersedes text,
  superseded_by text,
  approved_by text,
  schema_version text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS vulnerability_decisions_tenant_finding_idx
  ON vulnerability_decisions(tenant_id, finding_id, created_at);

CREATE INDEX IF NOT EXISTS vulnerability_decisions_tenant_release_idx
  ON vulnerability_decisions(tenant_id, release_id, status);

CREATE TABLE IF NOT EXISTS exceptions (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  release_id text NOT NULL,
  reason text NOT NULL,
  owner text NOT NULL,
  expires_at timestamptz NOT NULL,
  approved boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE exceptions
  ADD COLUMN IF NOT EXISTS finding_id text,
  ADD COLUMN IF NOT EXISTS control_id text,
  ADD COLUMN IF NOT EXISTS approved_by text,
  ADD COLUMN IF NOT EXISTS approved_at timestamptz;

CREATE INDEX IF NOT EXISTS exceptions_tenant_release_idx
  ON exceptions(tenant_id, release_id, approved, expires_at);

CREATE INDEX IF NOT EXISTS exceptions_tenant_finding_idx
  ON exceptions(tenant_id, finding_id);
