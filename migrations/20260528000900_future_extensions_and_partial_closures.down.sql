DROP TABLE IF EXISTS signing_operations;
DROP TABLE IF EXISTS provider_verifications;
DROP TABLE IF EXISTS anomaly_reports;
DROP TABLE IF EXISTS pdf_report_packages;
DROP TABLE IF EXISTS marketplace_collectors;
DROP TABLE IF EXISTS public_transparency_log_entries;
DROP TABLE IF EXISTS public_transparency_logs;
DROP TABLE IF EXISTS saas_edition_profiles;
DROP TABLE IF EXISTS evidence_graph_snapshots;
DROP TABLE IF EXISTS questionnaire_drafts;
DROP TABLE IF EXISTS evidence_summaries;

ALTER TABLE object_retention_policies
    DROP COLUMN IF EXISTS verification_hash;
