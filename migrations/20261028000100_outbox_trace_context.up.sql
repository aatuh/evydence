-- Operational trace context only. Existing and older writers create jobs with
-- no trace. Evidence, payloads, deduplication keys and frozen backups are unchanged.
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '30s';

ALTER TABLE outbox_jobs
 ADD COLUMN trace_id text NOT NULL DEFAULT '',
 ADD COLUMN trace_parent_span_id text NOT NULL DEFAULT '',
 ADD COLUMN trace_sampled boolean NOT NULL DEFAULT false,
 ADD CONSTRAINT outbox_trace_context_shape CHECK (
  (trace_id = '' AND trace_parent_span_id = '' AND NOT trace_sampled)
  OR (
   length(trace_id) = 32 AND trace_id ~ '^[0-9a-f]{32}$'
   AND trace_id <> '00000000000000000000000000000000'
   AND length(trace_parent_span_id) = 16 AND trace_parent_span_id ~ '^[0-9a-f]{16}$'
   AND trace_parent_span_id <> '0000000000000000'
  )
 );
