DROP TABLE IF EXISTS questionnaire_answer_library;

ALTER TABLE customer_portal_access
    DROP COLUMN IF EXISTS watermark,
    DROP COLUMN IF EXISTS nda_accepted_by,
    DROP COLUMN IF EXISTS nda_accepted_at,
    DROP COLUMN IF EXISTS require_nda;
