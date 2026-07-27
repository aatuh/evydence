CREATE TABLE IF NOT EXISTS tenant_audit_sequences (
  tenant_id text PRIMARY KEY REFERENCES tenants(id),
  next_sequence bigint NOT NULL CHECK (next_sequence >= 1)
);

INSERT INTO tenant_audit_sequences (tenant_id, next_sequence)
SELECT tenant_id, COALESCE(MAX(sequence), 0) + 1
FROM audit_chain_entries
GROUP BY tenant_id
ON CONFLICT (tenant_id) DO UPDATE
SET next_sequence = GREATEST(tenant_audit_sequences.next_sequence, EXCLUDED.next_sequence);

ALTER TABLE releases
  ADD COLUMN IF NOT EXISTS revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1);

ALTER TABLE release_candidates
  ADD COLUMN IF NOT EXISTS revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1);
