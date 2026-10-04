package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// Private component of the complete read-only customer snapshot. These are
// recorded receipts, not fresh provider/cryptographic checks. Audit integrity
// is inspected separately and added by the complete reader in this same view.
func readCustomerPackageVerificationMetadataTx(ctx context.Context, tx pgx.Tx, tenant, product, release string, budget *customerSnapshotBudget) (map[string]any, error) {
	if err := validateCustomerSnapshotRead(ctx, tx, tenant, product, release, budget); err != nil {
		return nil, err
	}
	if err := requireCustomerSnapshotScope(ctx, tx, tenant, product, release); err != nil {
		return nil, err
	}
	if release != "" {
		if err := checkCustomerCatalogAssociationBudget(ctx, tx, tenant, product, release); err != nil {
			return nil, err
		}
	}
	if err := checkCustomerVerificationSubjectInventory(ctx, tx, tenant, product, release); err != nil {
		return nil, err
	}
	working := *budget
	bundles, err := readCustomerSnapshotMetadataRows(ctx, tx, customerVerificationBundlesSQL, tenant, product, release, &working)
	if err != nil {
		return nil, err
	}
	for _, row := range bundles {
		values, err := customerSnapshotStringList(row["signature_refs"])
		if err != nil {
			return nil, err
		}
		row["signature_refs"] = values
	}
	out := map[string]any{
		"hash_algorithm": "sha256", "canonicalization": verificationdomain.CanonicalizationProfileVersion,
		"manifest_hash_field": "manifest_hash", "release_bundles": bundles,
	}
	for _, part := range []struct{ key, query string }{
		{"verification_results", customerVerificationResultsSQL}, {"cosign_assessments", customerVerificationCosignSQL},
	} {
		rows, err := readCustomerSnapshotMetadataRows(ctx, tx, part.query, tenant, product, release, &working)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			var stored []struct{ Name, Result, Detail string }
			raw, err := json.Marshal(row["checks"])
			if err != nil || json.Unmarshal(raw, &stored) != nil {
				return nil, packageapp.ErrConflict
			}
			values := make([]packageapp.CustomerPackageVerificationCheck, 0, len(stored))
			for _, v := range stored {
				values = append(values, packageapp.CustomerPackageVerificationCheck{Name: v.Name, Result: v.Result, Detail: v.Detail})
			}
			row["checks"] = packageapp.CustomerPackageVerificationCheckSummaries(values)
			// The legacy tagged DTO is confined to this adapter so the established
			// public JSON/omitempty shape survives without exporting unknown fields.
			var profile domain.VerificationProfile
			raw, err = json.Marshal(row["profile"])
			if err != nil || json.Unmarshal(raw, &profile) != nil {
				return nil, packageapp.ErrConflict
			}
			row["profile"] = profile
			limitations, err := customerSnapshotStringList(row["limitations"])
			if err != nil {
				return nil, err
			}
			row["limitations"] = limitations
		}
		out[part.key] = rows
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	*budget = working
	return out, nil
}

// Fixed column names only. Guard type-specific expansion before JSON arrays
// are expanded. Private extension fields are never included in selected JSON.
func customerVerificationChecksInvalidSQL(column string) string {
	return `CASE WHEN jsonb_typeof(` + column + `)='null' THEN false
	 WHEN jsonb_typeof(` + column + `) IS DISTINCT FROM 'array' THEN true
	 WHEN jsonb_array_length(` + column + `)>4096 OR octet_length(` + column + `::text)>8388608 THEN true
	 ELSE EXISTS(SELECT 1 FROM jsonb_array_elements(` + column + `) c WHERE jsonb_typeof(c) IS DISTINCT FROM 'object'
	 OR NOT coalesce(jsonb_typeof(c->'name') IN ('string','null'),true)
	 OR NOT coalesce(jsonb_typeof(c->'result') IN ('string','null'),true)
	 OR NOT coalesce(jsonb_typeof(c->'detail') IN ('string','null'),true)) END`
}

func customerVerificationChecksSQL(column string) string {
	return `CASE WHEN (` + customerVerificationChecksInvalidSQL(column) + `) THEN '[]'::jsonb ELSE
	 (SELECT coalesce(jsonb_agg(jsonb_build_object('name',coalesce(c->>'name',''),'result',coalesce(c->>'result',''),'detail',coalesce(c->>'detail',''))),'[]'::jsonb)
	 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(` + column + `)='array' THEN ` + column + ` ELSE '[]'::jsonb END)c) END`
}

func customerVerificationProfileInvalidSQL(column string) string {
	invalid := `CASE WHEN jsonb_typeof(` + column + `)='null' THEN false WHEN jsonb_typeof(` + column + `) IS DISTINCT FROM 'object' THEN true
	 WHEN octet_length(` + column + `::text)>8388608 THEN true ELSE false`
	for _, key := range []string{"id", "version", "identity_policy", "transparency_proof", "payload_scope", "payload_digest"} {
		invalid += ` OR NOT coalesce(jsonb_typeof(` + column + `->'` + key + `') IN ('string','null'),true)`
	}
	for _, key := range []string{"required_checks", "trust_material", "limitations"} {
		invalid += ` OR (` + customerSnapshotStringListInvalidSQL(column+`->'`+key+`'`) + `)`
	}
	return invalid + ` END`
}

func customerVerificationProfileSQL(column string) string {
	// Include only the nine established profile fields. The adapter restores
	// the legacy DTO, preserving required nil lists and optional omissions.
	return `jsonb_build_object('id',coalesce(` + column + `->>'id',''),'version',coalesce(` + column + `->>'version',''),
	 'required_checks',` + column + `->'required_checks','trust_material',` + column + `->'trust_material',
	 'identity_policy',coalesce(` + column + `->>'identity_policy',''),'transparency_proof',coalesce(` + column + `->>'transparency_proof',''),
	 'payload_scope',coalesce(` + column + `->>'payload_scope',''),'payload_digest',coalesce(` + column + `->>'payload_digest',''),
	 'limitations',` + column + `->'limitations')`
}

var customerVerificationBundlesSQL = `SELECT b.id AS sort_id,jsonb_build_object('id',b.id,'state',b.state,'manifest_hash',b.manifest_hash,
	'signature_refs',b.signature_refs,'created_at',to_char(b.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')) AS metadata,
	(octet_length(b.id)>1024 OR ` + customerSnapshotStringListInvalidSQL("b.signature_refs") + ` OR octet_length(b.signature_refs::text)>8388608
	 OR ` + customerGovernanceTimeInvalidSQL("b.created_at") + `) AS invalid
	FROM scope s JOIN release_bundles b ON s.release_id<>'' AND b.tenant_id=s.tenant_id AND b.release_id=s.release_id
	WHERE CASE WHEN (` + customerSnapshotStringListInvalidSQL("b.signature_refs") + `) OR octet_length(b.signature_refs::text)>8388608 THEN true ELSE
	 NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(b.signature_refs)='array' THEN b.signature_refs ELSE '[]'::jsonb END)ref
	 WHERE NOT EXISTS(SELECT 1 FROM signatures sig JOIN signing_keys k ON k.id=sig.key_id AND k.tenant_id=s.tenant_id
	 WHERE sig.id=ref AND sig.tenant_id=s.tenant_id AND sig.subject_type='release_bundle' AND sig.subject_id=b.id)) END ORDER BY b.id`

// Reuse the catalog's selected-artifact association rules and the provenance
// component's complete typed-source ownership instead of parallel definitions.
var customerVerificationArtifactsCTE = `WITH selected_artifacts AS MATERIALIZED (
	SELECT sort_id AS id FROM (` + customerCatalogArtifactsSQL + `) a WHERE (SELECT release_id<>'' FROM scope) LIMIT 4097
	), selected_attestations AS MATERIALIZED (
	SELECT sort_id AS id FROM (` + customerProvenanceAttestationsSQL + `) a LIMIT 4097
	) `

func checkCustomerVerificationSubjectInventory(ctx context.Context, tx pgx.Tx, tenant, product, release string) error {
	var count int
	err := tx.QueryRow(ctx, `WITH scope AS (SELECT $1::text AS tenant_id,$2::text AS product_id,$3::text AS release_id)
	 SELECT greatest((`+customerVerificationArtifactsCTE+`SELECT count(*) FROM selected_artifacts),
	 (`+customerVerificationArtifactsCTE+`SELECT count(*) FROM selected_attestations))`, tenant, product, release).Scan(&count)
	if err != nil {
		return fmt.Errorf("read customer-package verification subject budget: %w", err)
	}
	if count > packageapp.MaxSecurityReviewEvidenceIDs {
		return packageapp.ErrConflict
	}
	return nil
}

const customerVerificationSubjectScopeSQL = `(
	(v.subject_type='release_bundle' AND s.release_id<>'' AND EXISTS(SELECT 1 FROM release_bundles b WHERE b.id=v.subject_id AND b.tenant_id=s.tenant_id AND b.release_id=s.release_id))
	OR (v.subject_type='evidence_item' AND EXISTS(SELECT 1 FROM evidence_items e WHERE e.id=v.subject_id AND coalesce(e.release_id,'')=s.release_id AND ` + customerCatalogEvidenceOwnershipSQL + `))
	OR (v.subject_type='artifact_signature' AND EXISTS(SELECT 1 FROM artifact_signatures sig JOIN artifacts a ON a.id=sig.artifact_id AND a.tenant_id=sig.tenant_id JOIN selected_artifacts selected ON selected.id=a.id WHERE sig.id=v.subject_id AND sig.tenant_id=s.tenant_id))
	OR (v.subject_type='build_attestation' AND EXISTS(SELECT 1 FROM selected_attestations a WHERE a.id=v.subject_id)))`

var customerVerificationResultsSQL = customerVerificationArtifactsCTE + `SELECT v.id AS sort_id,
	jsonb_build_object('id',v.id,'subject_type',v.subject_type,'subject_id',v.subject_id,'result',v.result,
	'checks',` + customerVerificationChecksSQL("v.checks") + `,'profile',` + customerVerificationProfileSQL("v.assurance_profile") + `,
	'limitations',v.limitations,'schema_version',v.schema_version,'verified_at',to_char(v.verified_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')) AS metadata,
	(octet_length(v.id)>1024 OR octet_length(v.subject_id)>1024 OR ` + customerVerificationChecksInvalidSQL("v.checks") + ` OR ` + customerVerificationProfileInvalidSQL("v.assurance_profile") + `
	OR ` + customerGovernanceTextArrayInvalidSQL("v.limitations") + ` OR ` + customerGovernanceTimeInvalidSQL("v.verified_at") + `) AS invalid
	FROM scope s JOIN verification_results v ON v.tenant_id=s.tenant_id WHERE ` + customerVerificationSubjectScopeSQL + ` ORDER BY v.id`

var customerVerificationCosignSQL = `WITH selected_artifacts AS MATERIALIZED (
	SELECT sort_id AS id FROM (` + customerCatalogArtifactsSQL + `) a WHERE (SELECT release_id<>'' FROM scope) LIMIT 4097
	) SELECT v.id AS sort_id,jsonb_build_object('id',v.id,'artifact_id',v.artifact_id,'result',v.result,
	'checks',` + customerVerificationChecksSQL("v.checks") + `,'profile',` + customerVerificationProfileSQL("v.assurance_profile") + `,
	'limitations',v.limitations,'schema_version',v.schema_version,'created_at',to_char(v.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')) AS metadata,
	(octet_length(v.id)>1024 OR octet_length(v.artifact_id)>1024 OR ` + customerVerificationChecksInvalidSQL("v.checks") + ` OR ` + customerVerificationProfileInvalidSQL("v.assurance_profile") + `
	OR ` + customerGovernanceTextArrayInvalidSQL("v.limitations") + ` OR ` + customerGovernanceTimeInvalidSQL("v.created_at") + `) AS invalid
	FROM scope s JOIN cosign_verifications v ON v.tenant_id=s.tenant_id
	JOIN artifacts a ON a.id=v.artifact_id AND a.tenant_id=s.tenant_id JOIN selected_artifacts selected ON selected.id=a.id
	JOIN artifact_signatures sig ON sig.id=v.artifact_signature_id AND sig.tenant_id=s.tenant_id AND sig.artifact_id=a.id AND sig.subject_digest=v.subject_digest
	WHERE (coalesce(v.container_image_id,'')='' OR EXISTS(SELECT 1 FROM container_images i WHERE i.id=v.container_image_id AND i.tenant_id=s.tenant_id AND i.artifact_id=a.id AND i.digest=v.subject_digest)) ORDER BY v.id`
