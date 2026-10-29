-- Downgrading loses only diagnostic context; jobs, payloads and evidence remain.
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '30s';

ALTER TABLE outbox_jobs
 DROP COLUMN trace_id,
 DROP COLUMN trace_parent_span_id,
 DROP COLUMN trace_sampled;
