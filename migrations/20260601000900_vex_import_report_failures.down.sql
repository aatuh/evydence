ALTER TABLE vex_import_reports
  DROP COLUMN IF EXISTS failure_detail,
  DROP COLUMN IF EXISTS failure_code;
