package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

const importedDecisionColumns = `id,tenant_id,finding_id,scan_id,release_id,vulnerability,
	component,sbom_id,sbom_component_purl,sbom_component_name,status,justification,
	impact_statement,action_statement,customer_visible,internal_notes,source,evidence_id,
	evidence_ids,supporting_refs,vex_document_id,supersedes,superseded_by,approved_by,
	reviewed_at,review_due_at,schema_version,created_at`

// Cast every field before comparing so PostgreSQL's actual null, array, JSON,
// and timestamp representations match both new inserts and existing rows.
const importedDecisionRow = `SELECT
	$1::text AS id,$2::text AS tenant_id,$3::text AS finding_id,$4::text AS scan_id,
	$5::text AS release_id,$6::text AS vulnerability,$7::text AS component,
	$8::text AS sbom_id,$9::text AS sbom_component_purl,$10::text AS sbom_component_name,
	$11::text AS status,$12::text AS justification,$13::text AS impact_statement,
	$14::text AS action_statement,$15::boolean AS customer_visible,$16::text AS internal_notes,
	$17::text AS source,$18::text AS evidence_id,$19::text[] AS evidence_ids,
	$20::jsonb AS supporting_refs,$21::text AS vex_document_id,$22::text AS supersedes,
	$23::text AS superseded_by,$24::text AS approved_by,$25::timestamptz AS reviewed_at,
	$26::timestamptz AS review_due_at,$27::text AS schema_version,$28::timestamptz AS created_at`

// importDecisionRow is only for the existing trusted relational import/sync
// paths. It preserves legacy historical fields on initial insertion, rejects
// content changes on replay, and appends new supersession relationships. It is
// not an authorization or current-finding validation port for API commands.
// Callers hold the affected tenants' projection fences through commit, acquired
// before audit-chain locks. A failed insert or deferred constraint must roll
// back the surrounding transaction, including any previously appended links.
func importDecisionRow(ctx context.Context, tx pgx.Tx, d domain.VulnerabilityDecision, supersessionTime time.Time) error {
	refs := d.SupportingRefs
	if refs == nil {
		refs = []domain.SubjectRef{}
	}
	encodedRefs, err := json.Marshal(refs)
	if err != nil {
		return fmt.Errorf("encode vulnerability decision supporting refs: %w", err)
	}
	args := []any{d.ID, d.TenantID, d.FindingID, d.ScanID, nullableString(d.ReleaseID), d.Vulnerability,
		nullableString(d.Component), nullableString(d.SBOMID), nullableString(d.SBOMComponentPURL), nullableString(d.SBOMComponentName),
		d.Status, d.Justification, nullableString(d.ImpactStatement), nullableString(d.ActionStatement), d.CustomerVisible,
		nullableString(d.InternalNotes), d.Source, nullableString(d.EvidenceID), textArray(d.EvidenceIDs), encodedRefs,
		nullableString(d.VEXDocumentID), nullableString(d.Supersedes), nullableString(d.SupersededBy), nullableString(d.ApprovedBy),
		nullableTime(d.ReviewedAt), nullableTime(d.ReviewDueAt), d.SchemaVersion, nonZeroTime(d.CreatedAt)}
	result, err := tx.Exec(ctx, `INSERT INTO vulnerability_decisions (`+importedDecisionColumns+`)
		SELECT `+importedDecisionColumns+` FROM (`+importedDecisionRow+`) incoming ON CONFLICT(id) DO NOTHING`, args...)
	if err != nil {
		return fmt.Errorf("insert imported vulnerability decision: %w", err)
	}
	if result.RowsAffected() == 1 {
		return nil
	}
	// A missing historical creation time means unspecified, not permission to
	// replace the recorded timestamp with this replay's fallback clock value.
	args = append(args, d.CreatedAt.IsZero())
	var sameContent, sameSuccessor, active bool
	err = tx.QueryRow(ctx, `WITH incoming AS (`+importedDecisionRow+`)
		SELECT
		(to_jsonb(d)-CASE WHEN $29::boolean THEN ARRAY['superseded_by','created_at'] ELSE ARRAY['superseded_by'] END)
		 = (to_jsonb(i)-CASE WHEN $29::boolean THEN ARRAY['superseded_by','created_at'] ELSE ARRAY['superseded_by'] END),
		COALESCE(s.successor_id,d.superseded_by,'')=COALESCE(i.superseded_by,''),
		COALESCE(s.successor_id,d.superseded_by,'')=''
		FROM vulnerability_decisions d CROSS JOIN incoming i
		LEFT JOIN vulnerability_decision_supersessions s ON s.tenant_id=d.tenant_id AND s.finding_id=d.finding_id AND s.predecessor_id=d.id
		WHERE d.tenant_id=$2 AND d.id=$1`, args...).Scan(&sameContent, &sameSuccessor, &active)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("compare imported vulnerability decision: %w", err)
	}
	if !sameContent {
		return app.ErrConflict
	}
	// Replaying an original active row never deletes a later relationship or
	// reactivates history. Identical linked/legacy history is also a no-op.
	if d.SupersededBy == "" || sameSuccessor {
		return nil
	}
	if !active {
		return app.ErrConflict
	}
	_, err = tx.Exec(ctx, `INSERT INTO vulnerability_decision_supersessions
		(tenant_id,finding_id,predecessor_id,successor_id,created_at,schema_version)
		VALUES($1,$2,$3,$4,$5,'decision-supersession.v1')`, d.TenantID, d.FindingID, d.ID, d.SupersededBy, nonZeroTime(supersessionTime))
	if err != nil {
		return fmt.Errorf("append imported decision supersession: %w", err)
	}
	return nil
}
