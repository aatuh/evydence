package app

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

// Historical map-backed characterization only. HTTP DSSE fixtures use the
// focused command and current transaction reader instead.
// AuthorizeSubjectVerification is only the explicit local-memory replay guard.
// It reads current map ownership/grants, never inspection metadata or worker
// projections. Native generic verification uses the transactional scope port.
func (l *Ledger) AuthorizeSubjectVerification(ctx context.Context, a domain.Actor, kind, id string) error {
	if ctx == nil {
		return context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := require(a, ScopeVerifyRead); err != nil {
		return err
	}
	tenant, err := verificationapp.NormalizeSigningKeyID(a.TenantID)
	if err != nil || tenant != a.TenantID {
		return ErrValidation
	}
	kind, id, err = verificationapp.NormalizeSubjectVerificationInput(kind, id)
	if err != nil {
		return ErrValidation
	}
	if kind == "build_attestation" {
		return l.AuthorizeDSSEVerification(ctx, a, id)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[tenant]; !ok {
		return ErrNotFound
	}
	subject, err := resolveVerificationSubjectLocked(l, tenant, kind, id)
	if err != nil {
		return fromVerificationContextError(err)
	}
	refs := subject.Resources
	switch kind {
	case "release_bundle", "audit_chain_release_manifest":
		release, ok := l.releases[refs.ReleaseID]
		product, productOK := l.products[release.ProductID]
		if !ok || !productOK || release.TenantID != tenant || product.TenantID != tenant {
			return ErrNotFound
		}
		refs.ProductID = product.ID
	case "evidence_item":
		if err := validateLedgerEvidenceScopeLocked(l, tenant, evidenceapp.EvidenceScope{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID, BuildID: refs.BuildID, DeploymentID: refs.DeploymentID}); err != nil {
			return err
		}
	}
	if kind != "evidence_item" && kind != "release_bundle" {
		return fromVerificationContextError(application.AuthorizeTenantWideScope(ctx, a, ScopeVerifyRead))
	}
	return l.authorizeResourceLocked(a, ScopeVerifyRead, resourceRefs{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID, BuildID: refs.BuildID, DeploymentID: refs.DeploymentID})
}

// AuthorizeDSSEVerification is only the explicit local-memory replay guard.
// Native HTTP uses the focused service and flat PostgreSQL ownership locks;
// this method neither refreshes worker projections nor inspects attestations.
func (l *Ledger) AuthorizeDSSEVerification(ctx context.Context, a domain.Actor, raw string) error {
	if ctx == nil {
		return context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := require(a, ScopeVerifyRead); err != nil {
		return err
	}
	tenant, err := verificationapp.NormalizeSigningKeyID(a.TenantID)
	if err != nil || tenant != a.TenantID {
		return ErrValidation
	}
	id, err := verificationapp.NormalizeSigningKeyID(raw)
	if err != nil {
		return ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	subject, err := resolveVerificationSubjectLocked(l, tenant, "build_attestation", id)
	if err != nil {
		return fromVerificationContextError(err)
	}
	refs := subject.Resources
	project, projectFound := l.projects[refs.ProjectID]
	release, releaseFound := l.releases[refs.ReleaseID]
	product, productFound := l.products[project.ProductID]
	if !projectFound || !releaseFound || !productFound || project.TenantID != tenant || release.TenantID != tenant || product.TenantID != tenant || project.ProductID != release.ProductID {
		return ErrNotFound
	}
	item, found := l.evidence[l.attestations[id].EvidenceID]
	if !found || item.TenantID != tenant || item.BuildID != refs.BuildID || item.ProductID != "" && item.ProductID != product.ID || item.ProjectID != "" && item.ProjectID != project.ID || item.ReleaseID != "" && item.ReleaseID != release.ID {
		return ErrNotFound
	}
	return l.authorizeResourceLocked(a, ScopeVerifyRead, resourceRefs{ProductID: product.ID, ProjectID: project.ID, ReleaseID: release.ID, BuildID: refs.BuildID})
}

func (l *Ledger) VerifyDSSEAttestationSignature(ctx context.Context, actor domain.Actor, attestationID string) (domain.VerificationResult, error) {
	return l.VerifySubject(ctx, actor, "build_attestation", attestationID)
}
