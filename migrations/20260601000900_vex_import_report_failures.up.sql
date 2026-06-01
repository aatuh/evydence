ALTER TABLE vex_import_reports
  ADD COLUMN IF NOT EXISTS failure_code text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS failure_detail text NOT NULL DEFAULT '';
