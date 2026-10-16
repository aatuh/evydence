-- Downgrading loses only diagnostic correlation; jobs and evidence remain.
ALTER TABLE outbox_jobs
 DROP COLUMN log_request_id,
 DROP COLUMN log_operation_id;
