CREATE TABLE object_reconciliation_receipts (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  dry_run boolean NOT NULL,
  metadata_cursor integer NOT NULL CHECK (metadata_cursor >= 0),
  next_metadata_cursor integer CHECK (next_metadata_cursor IS NULL OR next_metadata_cursor >= 0),
  provider_cursor integer NOT NULL CHECK (provider_cursor >= 0),
  next_provider_cursor integer CHECK (next_provider_cursor IS NULL OR next_provider_cursor >= 0),
  scanned_payloads integer NOT NULL CHECK (scanned_payloads >= 0),
  healthy_payloads integer NOT NULL CHECK (healthy_payloads >= 0),
  missing_final_objects integer NOT NULL CHECK (missing_final_objects >= 0),
  missing_staged_objects integer NOT NULL CHECK (missing_staged_objects >= 0),
  digest_mismatches integer NOT NULL CHECK (digest_mismatches >= 0),
  recovered_finalizations integer NOT NULL CHECK (recovered_finalizations >= 0),
  abandoned_staging integer NOT NULL CHECK (abandoned_staging >= 0),
  provider_orphans integer NOT NULL CHECK (provider_orphans >= 0),
  quarantined_payloads integer NOT NULL CHECK (quarantined_payloads >= 0),
  created_at timestamptz NOT NULL
);

CREATE INDEX object_reconciliation_receipts_tenant_created_idx
  ON object_reconciliation_receipts (tenant_id, created_at DESC);
