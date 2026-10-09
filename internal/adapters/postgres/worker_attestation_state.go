package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

const maxWorkerAttestationDigestsBytes = 32 << 20

// loadWorkerAttestation resolves one claimed subject and its immutable source
// through current tenant-owned parents in one PostgreSQL statement.
func (s *Store) loadWorkerAttestation(ctx context.Context, tenantID, id string) (domain.BuildAttestation, error) {
	var attestation domain.BuildAttestation
	var payloadRef, builderID, buildType sql.NullString
	var subjectDigests []byte
	err := s.pool.QueryRow(ctx, `
		SELECT a.id, a.tenant_id, a.build_id, a.evidence_id, a.payload_ref,
		       a.payload_hash, a.payload_size, a.payload_type, a.predicate_type,
		       a.subject_digests, a.builder_id, a.build_type, a.materials_count,
		       a.signature_count, a.verification_status, a.schema_version, a.created_at
		FROM build_attestations AS a
		JOIN build_runs AS b ON b.id = a.build_id AND b.tenant_id = a.tenant_id
		JOIN projects AS p ON p.id = b.project_id AND p.tenant_id = b.tenant_id
		JOIN products AS product ON product.id = p.product_id AND product.tenant_id = b.tenant_id
		JOIN releases AS r ON r.id = b.release_id AND r.tenant_id = b.tenant_id
		    AND r.product_id = product.id
		JOIN evidence_items AS source ON source.id = a.evidence_id AND source.tenant_id = a.tenant_id
		    AND source.type = 'build_attestation' AND source.product_id = product.id
		    AND source.project_id = p.id AND source.release_id = r.id
		    AND source.build_id = b.id AND source.deployment_id IS NULL
		    AND source.payload_hash = a.payload_hash AND source.payload_size = a.payload_size
		    AND source.payload_ref IS NOT DISTINCT FROM a.payload_ref
		WHERE a.tenant_id = $1 AND a.id = $2`, tenantID, id).Scan(
		&attestation.ID, &attestation.TenantID, &attestation.BuildID, &attestation.EvidenceID,
		&payloadRef, &attestation.PayloadHash, &attestation.PayloadSize,
		&attestation.PayloadType, &attestation.PredicateType, &subjectDigests,
		&builderID, &buildType, &attestation.MaterialsCount, &attestation.SignatureCount,
		&attestation.VerificationStatus, &attestation.SchemaVersion, &attestation.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.BuildAttestation{}, app.ErrNotFound
	}
	if err != nil {
		return domain.BuildAttestation{}, fmt.Errorf("load worker attestation: %w", err)
	}
	if len(subjectDigests) > maxWorkerAttestationDigestsBytes {
		return domain.BuildAttestation{}, app.ErrConflict
	}
	attestation.PayloadRef = nullableSQLString(payloadRef)
	attestation.BuilderID = nullableSQLString(builderID)
	attestation.BuildType = nullableSQLString(buildType)
	if err := decodeJSON(subjectDigests, &attestation.SubjectDigests); err != nil {
		return domain.BuildAttestation{}, app.ErrConflict
	}
	return attestation, nil
}
