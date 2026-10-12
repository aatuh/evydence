package repositories

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func (r evidence) LockRelationshipTenant(ctx context.Context, tenant string) error {
	_, err := r.ResolveEvidenceCreationScope(ctx, tenant, application.ResourceReferences{})
	return err
}
func (r evidence) LockRelationshipEvidence(ctx context.Context, tenant, id string) (application.ResourceReferences, error) {
	if err := r.LockRelationshipTenant(ctx, tenant); err != nil {
		return application.ResourceReferences{}, err
	}
	return r.LockEvidenceBundleEvidence(ctx, tenant, id)
}
func (r evidence) LockRelationshipTarget(ctx context.Context, tenant, kind, id string) (application.ResourceReferences, error) {
	refs := application.ResourceReferences{}
	switch kind {
	case "product":
		refs.ProductID = id
	case "release":
		refs.ReleaseID = id
	default:
		return refs, app.ErrValidation
	}
	return r.ResolveEvidenceCreationScope(ctx, tenant, refs)
}
func (r evidence) ReadRelationshipEvidence(ctx context.Context, tenant, id string) (evidencedomain.EvidenceItem, error) {
	return ReadEvidenceWithWorkerProvenance(ctx, r.tx, tenant, id)
}

// Only authoritative relationship origins are selected, not a full timeline.
func (r evidence) ReadRelationshipOrigins(ctx context.Context, tenant, id string) ([]evidencedomain.EvidenceLifecycleEvent, error) {
	const budget = 8 << 20
	const maxRows = 4096
	rows, err := r.tx.Query(ctx, `SELECT CASE WHEN octet_length(body::text)<=$5 THEN body ELSE NULL END FROM(SELECT jsonb_build_object('id',id,'tenant_id',tenant_id,'evidence_id',evidence_id,'action',action,'schema_version',schema_version,'details',jsonb_build_object($3::text,details->$3)) body FROM evidence_lifecycle_events WHERE tenant_id=$1 AND evidence_id=$2 AND schema_version=$4 AND details ? $3 ORDER BY id LIMIT $6 FOR SHARE)selected`, tenant, id, evidencedomain.LegacyCanonicalOriginDetailKey, evidencedomain.EvidenceRelationshipLifecycleSchemaVersion, budget, maxRows+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]evidencedomain.EvidenceLifecycleEvent, 0)
	used := 0
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if len(raw) == 0 || len(raw) > budget-used || len(result) == maxRows {
			return nil, app.ErrConflict
		}
		used += len(raw)
		var event domain.EvidenceLifecycleEvent
		d := json.NewDecoder(strings.NewReader(string(raw)))
		d.UseNumber()
		if err := d.Decode(&event); err != nil {
			return nil, app.ErrConflict
		}
		action, err := evidencedomain.ParseEvidenceLifecycleState(event.Action)
		if err != nil {
			return nil, app.ErrConflict
		}
		result = append(result, evidencedomain.EvidenceLifecycleEvent{ID: event.ID, TenantID: event.TenantID, EvidenceID: event.EvidenceID, Action: action, Details: event.Details, SchemaVersion: event.SchemaVersion})
	}
	return result, rows.Err()
}
