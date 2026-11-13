CREATE INDEX IF NOT EXISTS outbox_jobs_dead_letter_id_idx
  ON outbox_jobs (id COLLATE "C") WHERE status = 'dead_letter';
