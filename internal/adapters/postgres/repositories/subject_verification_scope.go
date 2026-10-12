package repositories

import (
	"context"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

// ResolveSubjectVerificationScope locks only current ownership coordinates.
// It intentionally does not read digests, manifests, roots, signatures, prior
// receipts or audit-chain pages. Locks remain held through the replay commit.
func (r verification) ResolveSubjectVerificationScope(ctx context.Context, tenant, kind, id string) (verificationapp.SubjectReference, error) {
	subject := verificationapp.SubjectReference{TenantID: tenant, Type: kind, ID: id}
	if ctx == nil || r.tx == nil || !validRetentionCoordinate(tenant) {
		return subject, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return subject, err
	}
	normalKind, normalID, err := verificationapp.NormalizeSubjectVerificationInput(kind, id)
	if err != nil || normalKind != kind || normalID != id {
		return subject, app.ErrValidation
	}
	// All entry points take the writer fence before tenant/parent/subject locks,
	// including standalone authorization and guards joined to durable commands.
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return subject, err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenant); err != nil {
		return subject, err
	}
	switch kind {
	case "audit_chain":
		return subject, nil
	case "evidence_item":
		return r.ResolveEvidenceVerificationSubject(ctx, tenant, id)
	case "build_attestation":
		return r.ResolveDSSEVerificationSubject(ctx, tenant, id)
	case "release_bundle":
		return r.ResolveReleaseBundleVerificationSubject(ctx, tenant, id)
	case "artifact_signature":
		// The inspection resolver also reads subject_digest; replay must not.
		subject.Resources, err = r.LockCosignVerificationScope(ctx, tenant, id)
	case "merkle_batch", "audit_chain_checkpoint":
		err = requireRow(ctx, r.tx, `SELECT 1 FROM merkle_batches WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id)
	case "audit_chain_release_manifest":
		// Lock the current release/product ownership but require a tenant-wide
		// grant: this profile inspects the full chain, not just a release scope.
		_, err = r.ResolveReleaseBundleVerificationSubject(ctx, tenant, id)
		subject.Resources = application.ResourceReferences{}
	case "backup_manifest":
		err = requireRow(ctx, r.tx, `SELECT 1 FROM backup_manifests WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id)
	default:
		err = app.ErrValidation
	}
	return subject, err
}
