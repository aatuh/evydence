ALTER TABLE customer_portal_access
    ADD COLUMN IF NOT EXISTS require_nda boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS nda_accepted_at timestamptz,
    ADD COLUMN IF NOT EXISTS nda_accepted_by text,
    ADD COLUMN IF NOT EXISTS watermark text;

CREATE TABLE IF NOT EXISTS questionnaire_answer_library (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    question_id text,
    evidence_type text,
    control_id text,
    product_id text,
    release_id text,
    answer text NOT NULL,
    evidence_ids text[] NOT NULL DEFAULT '{}',
    limitations text[] NOT NULL DEFAULT '{}',
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS questionnaire_answer_library_tenant_question_idx
    ON questionnaire_answer_library (tenant_id, question_id, created_at);

CREATE INDEX IF NOT EXISTS questionnaire_answer_library_tenant_release_idx
    ON questionnaire_answer_library (tenant_id, release_id, created_at);
