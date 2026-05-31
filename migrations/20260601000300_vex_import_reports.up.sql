CREATE TABLE IF NOT EXISTS vex_import_reports (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  vex_document_id text NOT NULL,
  evidence_id text NOT NULL,
  release_id text,
  artifact_id text,
  parser_version text NOT NULL,
  status text NOT NULL,
  statement_count integer NOT NULL DEFAULT 0,
  decisions_created integer NOT NULL DEFAULT 0,
  decisions_superseded integer NOT NULL DEFAULT 0,
  unsupported_fields text[] NOT NULL DEFAULT ARRAY[]::text[],
  warnings jsonb NOT NULL DEFAULT '[]'::jsonb,
  invalid_statements jsonb NOT NULL DEFAULT '[]'::jsonb,
  mapping_failures jsonb NOT NULL DEFAULT '[]'::jsonb,
  schema_version text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS vex_import_reports_tenant_vex_idx
  ON vex_import_reports(tenant_id, vex_document_id);

CREATE INDEX IF NOT EXISTS vex_import_reports_tenant_release_idx
  ON vex_import_reports(tenant_id, release_id, created_at);
