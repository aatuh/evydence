package postgres

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"

	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// Private component of the complete customer snapshot. The caller owns the
// read-only repeatable-read transaction and the shared metadata budget. These
// recorded provenance fields do not perform attestation/signature verification.
func readCustomerPackageProvenanceTx(ctx context.Context, tx pgx.Tx, tenant, product, release string, profile packagedomain.RedactionProfile, budget *customerSnapshotBudget) (map[string]any, error) {
	if err := validateCustomerSnapshotRead(ctx, tx, tenant, product, release, budget); err != nil {
		return nil, err
	}
	if profile.TenantID != tenant {
		return nil, packageapp.ErrValidation
	}
	if err := requireCustomerSnapshotScope(ctx, tx, tenant, product, release); err != nil {
		return nil, err
	}
	working := *budget
	out := map[string]any{"builds": []map[string]any{}, "build_attestations": []map[string]any{}}
	// Preserve the existing format: attestations are selected only through the
	// included build inventory, even when only build_attestation is allowed.
	if packageapp.CustomerPackageIncludesType(profile, "build") {
		builds, err := readCustomerSnapshotMetadataRows(ctx, tx, customerProvenanceBuildsSQL, tenant, product, release, &working)
		if err != nil {
			return nil, err
		}
		for _, row := range builds {
			var stored []struct {
				ArtifactID string `json:"artifact_id"`
				Digest     string `json:"digest"`
			}
			raw, err := json.Marshal(row["outputs"])
			if err != nil || json.Unmarshal(raw, &stored) != nil {
				return nil, packageapp.ErrConflict
			}
			values := make([]packageapp.CustomerPackageBuildOutput, 0, len(stored))
			for _, v := range stored {
				if !customerSnapshotID(v.ArtifactID, true) {
					return nil, packageapp.ErrConflict
				}
				values = append(values, packageapp.CustomerPackageBuildOutput{ArtifactID: v.ArtifactID, Digest: v.Digest})
			}
			row["outputs"] = packageapp.CustomerPackageBuildOutputSummaries(values)
		}
		out["builds"] = builds
		if packageapp.CustomerPackageIncludesType(profile, "build_attestation") {
			attestations, err := readCustomerSnapshotMetadataRows(ctx, tx, customerProvenanceAttestationsSQL, tenant, product, release, &working)
			if err != nil {
				return nil, err
			}
			for _, row := range attestations {
				values, err := customerSnapshotStringList(row["subject_digests"])
				if err != nil {
					return nil, err
				}
				row["subject_digests"] = values
			}
			out["build_attestations"] = attestations
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	*budget = working
	return out, nil
}

const customerProvenanceOutputFieldsInvalidSQL = `CASE WHEN jsonb_typeof(o) IS DISTINCT FROM 'object' THEN true ELSE
	NOT coalesce(jsonb_typeof(o->'artifact_id') IN ('string','null'),true)
	OR NOT coalesce(jsonb_typeof(o->'digest') IN ('string','null'),true)
	OR octet_length(coalesce(o->>'artifact_id',''))>1024 END`

const customerProvenanceOutputsInvalidSQL = `CASE WHEN jsonb_typeof(b.outputs)='null' THEN false
	WHEN jsonb_typeof(b.outputs) IS DISTINCT FROM 'array' THEN true
	WHEN jsonb_array_length(b.outputs)>4096 OR octet_length(b.outputs::text)>8388608 THEN true
	ELSE EXISTS(SELECT 1 FROM jsonb_array_elements(b.outputs)o WHERE ` + customerProvenanceOutputFieldsInvalidSQL + `) END`

const customerProvenanceBuildScopeSQL = `b.tenant_id=s.tenant_id AND b.release_id=s.release_id
	AND EXISTS(SELECT 1 FROM projects p WHERE p.id=b.project_id AND p.tenant_id=s.tenant_id AND p.product_id=s.product_id)
	AND (s.release_id='' OR EXISTS(SELECT 1 FROM releases r WHERE r.id=b.release_id AND r.tenant_id=s.tenant_id AND r.product_id=s.product_id))
	AND (coalesce(b.collector_id,'')='' OR EXISTS(SELECT 1 FROM collectors c WHERE c.id=b.collector_id AND c.tenant_id=s.tenant_id))
	AND CASE WHEN (` + customerProvenanceOutputsInvalidSQL + `) THEN true ELSE NOT EXISTS(
	 SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(b.outputs)='array' THEN b.outputs ELSE '[]'::jsonb END)o
	 WHERE coalesce(o->>'artifact_id','')<>'' AND NOT EXISTS(SELECT 1 FROM artifacts a WHERE a.id=o->>'artifact_id' AND a.tenant_id=s.tenant_id AND a.digest=o->>'digest')) END`

var customerProvenanceBuildsSQL = `SELECT b.id AS sort_id,jsonb_build_object('id',b.id,'project_id',b.project_id,'collector_id',coalesce(b.collector_id,''),
	'provider',b.provider,'commit_sha',b.commit_sha,'repository',coalesce(b.repository,''),'workflow_ref',coalesce(b.workflow_ref,''),'run_id',coalesce(b.run_id,''),
	'run_attempt',coalesce(b.run_attempt,0),'status',b.status,'parameters_hash',coalesce(b.parameters_hash,''),'environment_hash',coalesce(b.environment_hash,''),
	'started_at',to_char(b.started_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
	'finished_at',coalesce(to_char(b.finished_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),''),
	'schema_version',b.schema_version,'created_at',to_char(b.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
	'outputs',CASE WHEN (` + customerProvenanceOutputsInvalidSQL + `) THEN '[]'::jsonb ELSE
	 (SELECT coalesce(jsonb_agg(jsonb_build_object('artifact_id',o->'artifact_id','digest',o->'digest')),'[]'::jsonb)
	 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(b.outputs)='array' THEN b.outputs ELSE '[]'::jsonb END)o) END) AS metadata,
	(octet_length(b.id)>1024 OR coalesce(b.run_attempt<0,false) OR (` + customerProvenanceOutputsInvalidSQL + `)
	OR ` + customerGovernanceTimeInvalidSQL("b.started_at") + ` OR ` + customerGovernanceTimeInvalidSQL("b.finished_at") + ` OR ` + customerGovernanceTimeInvalidSQL("b.created_at") + `) AS invalid
	FROM scope s JOIN build_runs b ON ` + customerProvenanceBuildScopeSQL + ` ORDER BY b.id`

var customerProvenanceAttestationsSQL = `SELECT a.id AS sort_id,jsonb_build_object('id',a.id,'build_id',a.build_id,'evidence_id',a.evidence_id,
	'payload_hash',a.payload_hash,'payload_size',a.payload_size,'payload_type',a.payload_type,'predicate_type',a.predicate_type,'subject_digests',a.subject_digests,
	'signature_count',a.signature_count,'verification_status',a.verification_status,'schema_version',a.schema_version,
	'created_at',to_char(a.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')) AS metadata,
	(octet_length(a.id)>1024 OR a.payload_size<0 OR a.signature_count<0 OR ` + customerGovernanceTimeInvalidSQL("a.created_at") + `
	OR ` + customerSnapshotStringListInvalidSQL("a.subject_digests") + `) AS invalid
	FROM scope s JOIN build_runs b ON ` + customerProvenanceBuildScopeSQL + `
	JOIN build_attestations a ON a.build_id=b.id AND a.tenant_id=b.tenant_id
	JOIN evidence_items e ON e.id=a.evidence_id AND e.tenant_id=a.tenant_id AND e.type='build_attestation'
	 AND e.product_id=s.product_id AND e.project_id=b.project_id AND e.release_id=b.release_id AND e.build_id=b.id
	 AND e.deployment_id IS NULL AND e.payload_hash=a.payload_hash AND e.payload_size=a.payload_size AND e.payload_ref IS NOT DISTINCT FROM a.payload_ref
	 AND ` + customerCatalogEvidenceOwnershipSQL + ` ORDER BY a.id`
