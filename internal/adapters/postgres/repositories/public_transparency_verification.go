package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	e "github.com/aatuh/evydence/internal/experimental/app"
	d "github.com/aatuh/evydence/internal/experimental/domain"
)

var _ e.PublicTransparencyVerificationReader = futureExtensions{}

func (r futureExtensions) ReadPublicTransparencyVerification(ctx context.Context, tenant, id string) (d.PublicTransparencyLogEntry, error) {
	if err := r.ReadPublicTransparencyTenant(ctx, tenant); err != nil {
		return d.PublicTransparencyLogEntry{}, err
	}
	var v d.PublicTransparencyLogEntry
	// The immutable source chain and assessment are locked through the ambient
	// replay commit. CASE bounds transfer of corrupt text before decoding it.
	err := r.tx.QueryRow(ctx, `SELECT e.id,
CASE WHEN octet_length(e.log_id)<=1024 THEN e.log_id ELSE '' END,
CASE WHEN octet_length(e.checkpoint_id)<=1024 THEN e.checkpoint_id ELSE '' END,
CASE WHEN octet_length(e.merkle_batch_id)<=1024 THEN e.merkle_batch_id ELSE '' END,
CASE WHEN octet_length(e.external_id)<=1024 THEN e.external_id ELSE '' END,
CASE WHEN octet_length(e.entry_hash)<=128 THEN e.entry_hash ELSE '' END,
CASE WHEN octet_length(e.inclusion_root_hash)<=128 THEN e.inclusion_root_hash ELSE '' END,
CASE WHEN octet_length(e.inclusion_proof_hash)<=128 THEN e.inclusion_proof_hash ELSE '' END,
e.inclusion_verified_at,
CASE WHEN octet_length(e.state)<=64 THEN e.state ELSE '' END,
CASE WHEN octet_length(e.schema_version)<=128 THEN e.schema_version ELSE '' END,e.created_at
FROM public_transparency_log_entries e
JOIN public_transparency_logs l ON l.id=e.log_id AND l.tenant_id=e.tenant_id
JOIN transparency_checkpoints c ON c.id=e.checkpoint_id AND c.tenant_id=e.tenant_id AND c.batch_id=e.merkle_batch_id
JOIN merkle_batches b ON b.id=e.merkle_batch_id AND b.tenant_id=e.tenant_id
WHERE e.id=$2 AND e.tenant_id=$1 FOR UPDATE OF e FOR SHARE OF l,c,b`, tenant, id).Scan(&v.ID, &v.LogID, &v.CheckpointID, &v.MerkleBatchID, &v.ExternalID, &v.EntryHash, &v.InclusionRootHash, &v.InclusionProofHash, &v.InclusionVerifiedAt, &v.State, &v.SchemaVersion, &v.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return d.PublicTransparencyLogEntry{}, app.ErrNotFound
	}
	if err != nil {
		return d.PublicTransparencyLogEntry{}, fmt.Errorf("read public transparency verification coordinates: %w", err)
	}
	v.TenantID = tenant
	return v, nil
}
func (r futureExtensions) UpdateFocusedPublicTransparencyVerification(ctx context.Context, v, expected d.PublicTransparencyLogEntry) error {
	if err := e.ValidatePublicTransparencyVerificationSource(v.TenantID, v.ID, v); err != nil {
		return app.ErrValidation
	}
	immutable := v
	immutable.State, immutable.InclusionRootHash, immutable.InclusionProofHash, immutable.InclusionVerifiedAt = expected.State, expected.InclusionRootHash, expected.InclusionProofHash, expected.InclusionVerifiedAt
	if !e.SamePublicTransparencyAssessment(immutable, expected) {
		return app.ErrValidation
	}
	current, err := r.ReadPublicTransparencyVerification(ctx, v.TenantID, v.ID)
	if err != nil {
		return err
	}
	if !e.SamePublicTransparencyAssessment(current, expected) {
		return app.ErrConflict
	}
	return r.UpdatePublicTransparencyLogEntry(ctx, app.PublicTransparencyVerificationLegacyRecord(v), expected.State)
}
