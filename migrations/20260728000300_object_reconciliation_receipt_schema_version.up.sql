ALTER TABLE object_reconciliation_receipts
  ADD COLUMN IF NOT EXISTS schema_version text;

UPDATE object_reconciliation_receipts
SET schema_version = 'object-reconciliation.v1'
WHERE schema_version IS NULL OR schema_version = '';

ALTER TABLE object_reconciliation_receipts
  ALTER COLUMN schema_version SET NOT NULL;
