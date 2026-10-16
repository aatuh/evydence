-- Operational log references only. Existing jobs retain empty correlation;
-- evidence payloads, deduplication keys and historical audit hashes are unchanged.
ALTER TABLE outbox_jobs
 ADD COLUMN log_request_id text NOT NULL DEFAULT '',
 ADD COLUMN log_operation_id text NOT NULL DEFAULT '',
 ADD CONSTRAINT outbox_log_request_id_shape CHECK (
  log_request_id = '' OR (length(log_request_id) = 71 AND log_request_id ~ '^sha256:[0-9a-f]{64}$')),
 ADD CONSTRAINT outbox_log_operation_id_shape CHECK (
  log_operation_id = '' OR (length(log_operation_id) = 71 AND log_operation_id ~ '^sha256:[0-9a-f]{64}$'));
