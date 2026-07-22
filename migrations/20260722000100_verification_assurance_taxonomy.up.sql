ALTER TABLE verification_results
    ADD COLUMN IF NOT EXISTS assurance_profile jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS limitations text[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS schema_version text NOT NULL DEFAULT 'verification-result.v2.0.0';

ALTER TABLE cosign_verifications
    ADD COLUMN IF NOT EXISTS assurance_profile jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS limitations text[] NOT NULL DEFAULT '{}';

ALTER TABLE provider_verifications
    ADD COLUMN IF NOT EXISTS assurance_profile jsonb NOT NULL DEFAULT '{}'::jsonb;

UPDATE verification_results
SET result = CASE
        WHEN result = 'failed' THEN 'failed'
        WHEN result = 'error' THEN 'error'
        WHEN result IN ('not_verified', 'limited', 'skipped') THEN result
        ELSE 'limited'
    END,
    assurance_profile = jsonb_build_object(
        'id', 'legacy-ambiguous-verification.v1',
        'version', 'verification-profile.v1.0.0',
        'required_checks', '[]'::jsonb,
        'trust_material', '[]'::jsonb,
        'identity_policy', 'not recorded in legacy result',
        'transparency_proof', 'not recorded in legacy result',
        'payload_scope', 'not recorded in legacy result',
        'limitations', jsonb_build_array('Legacy verification records were migrated conservatively because their assurance profile was not recorded.')
    ),
    limitations = ARRAY['Legacy verification records were migrated conservatively because their assurance profile was not recorded.'],
    schema_version = 'verification-result.v2.0.0'
WHERE assurance_profile = '{}'::jsonb;

UPDATE cosign_verifications
SET result = CASE
        WHEN result = 'failed' THEN 'failed'
        WHEN result = 'error' THEN 'error'
        ELSE 'limited'
    END,
    assurance_profile = jsonb_build_object(
        'id', 'legacy-cosign-metadata.v1',
        'version', 'verification-profile.v1.0.0',
        'required_checks', '[]'::jsonb,
        'trust_material', '[]'::jsonb,
        'identity_policy', 'not recorded in legacy result',
        'transparency_proof', 'not recorded in legacy result',
        'payload_scope', 'stored Cosign metadata only',
        'limitations', jsonb_build_array('Legacy Cosign records were migrated to limited because they did not record a cryptographic verifier or trust policy.')
    ),
    limitations = ARRAY['Legacy Cosign records were migrated to limited because they did not record a cryptographic verifier or trust policy.'],
    schema_version = 'cosign-verification.v2.0.0'
WHERE assurance_profile = '{}'::jsonb;

UPDATE provider_verifications
SET result = CASE
        WHEN result = 'failed' THEN 'failed'
        WHEN result = 'error' THEN 'error'
        ELSE 'limited'
    END,
    assurance_profile = jsonb_build_object(
        'id', 'legacy-provider-verification.v1',
        'version', 'verification-profile.v1.0.0',
        'required_checks', '[]'::jsonb,
        'trust_material', '[]'::jsonb,
        'identity_policy', 'not recorded in legacy result',
        'transparency_proof', 'not recorded in legacy result',
        'payload_scope', 'not recorded in legacy result',
        'limitations', jsonb_build_array('Legacy provider verification records were migrated conservatively because their assurance profile was not recorded.')
    ),
    limitations = ARRAY['Legacy provider verification records were migrated conservatively because their assurance profile was not recorded.'],
    schema_version = 'provider-verification.v2.0.0'
WHERE assurance_profile = '{}'::jsonb;
