package app

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// AuthorizeArtifactSignatureCreation is only the local-memory replay guard.
// It checks current artifact ownership and grants without staging payloads or
// refreshing worker projections. Native HTTP uses the flat transaction port.
func (l *Ledger) AuthorizeArtifactSignatureCreation(ctx context.Context, a domain.Actor, in verificationapp.CreateArtifactSignatureInput) error {
	if ctx == nil {
		return context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := require(a, ScopeEvidenceWrite); err != nil {
		return err
	}
	tenant, err := verificationapp.NormalizeSigningKeyID(a.TenantID)
	if err != nil || tenant != a.TenantID {
		return ErrValidation
	}
	in, err = verificationapp.NormalizeArtifactSignatureInput(in)
	if err != nil {
		return ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[tenant]; !ok {
		return ErrNotFound
	}
	artifact, ok := l.artifacts[in.ArtifactID]
	if !ok || artifact.TenantID != tenant {
		return ErrNotFound
	}
	return l.authorizeArtifactSignatureCreationLocked(a, artifact)
}

// Local-only association matching mirrors the identity-only PostgreSQL write
// query. Tenant grants need no narrower association; scoped grants require
// current owned/coherent parents and build outputs matching the artifact digest.
func (l *Ledger) authorizeArtifactSignatureCreationLocked(a domain.Actor, artifact domain.Artifact) error {
	if !humanSessionActor(a) {
		return nil
	}
	for _, grant := range a.ResourceGrants {
		if !grantHasScope(grant, ScopeEvidenceWrite) {
			continue
		}
		if (grant.ResourceType == "" || grant.ResourceType == "tenant") && (grant.ResourceID == "" || grant.ResourceID == a.TenantID) {
			return nil
		}
		if grant.ResourceID == "" {
			continue
		}
		matches := func(product, project, release string) bool {
			switch grant.ResourceType {
			case "product":
				return grant.ResourceID == product
			case "project":
				return grant.ResourceID == project
			case "release":
				return grant.ResourceID == release
			default:
				return false
			}
		}
		for _, item := range l.evidence {
			if item.TenantID != a.TenantID || !evidenceReferencesArtifact(item, artifact.ID) || !matches(item.ProductID, item.ProjectID, item.ReleaseID) {
				continue
			}
			if validateLedgerEvidenceScopeLocked(l, a.TenantID, evidenceapp.EvidenceScope{ProductID: item.ProductID, ProjectID: item.ProjectID, ReleaseID: item.ReleaseID}) == nil {
				return nil
			}
		}
		for _, build := range l.buildRuns {
			if build.TenantID != a.TenantID {
				continue
			}
			project, ok := l.projects[build.ProjectID]
			if !ok || !matches(project.ProductID, build.ProjectID, build.ReleaseID) || validateLedgerEvidenceScopeLocked(l, a.TenantID, evidenceapp.EvidenceScope{ProductID: project.ProductID, ProjectID: build.ProjectID, ReleaseID: build.ReleaseID, BuildID: build.ID}) != nil {
				continue
			}
			for _, output := range build.Outputs {
				if output.ArtifactID == artifact.ID && output.Digest == artifact.Digest {
					return nil
				}
			}
		}
	}
	return ErrForbidden
}

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

// AuthorizeSigningKeyRevocation is only the explicit local-memory replay
// guard. Native HTTP uses the flat transactional ownership guard instead.
func (l *Ledger) AuthorizeSigningKeyRevocation(ctx context.Context, a domain.Actor, raw string) error {
	if err := application.AuthorizeTenantWideScope(ctx, a, ScopeKeysAdmin); err != nil {
		return fromVerificationContextError(err)
	}
	id, err := verificationapp.NormalizeSigningKeyID(raw)
	if err != nil {
		return ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key, ok := l.signingKeys[id]
	if !ok || key.TenantID != a.TenantID {
		return ErrNotFound
	}
	return nil
}

func (l *Ledger) VerifySubject(ctx context.Context, actor domain.Actor, subjectType, subjectID string) (domain.VerificationResult, error) {
	value, err := l.verificationCommands.VerifySubject(ctx, actor, subjectType, subjectID)
	return domain.VerificationResultFromContextModel(value), fromVerificationContextError(err)
}

func (l *Ledger) VerifyMerkleBatch(ctx context.Context, actor domain.Actor, id string) (domain.VerificationResult, error) {
	return l.VerifySubject(ctx, actor, "merkle_batch", id)
}

func (l *Ledger) VerifyBackupManifest(ctx context.Context, actor domain.Actor, id string) (domain.VerificationResult, error) {
	return l.VerifySubject(ctx, actor, "backup_manifest", id)
}

func (l *Ledger) RotateSigningKey(ctx context.Context, actor domain.Actor, reason string) (domain.SigningKey, error) {
	value, err := l.verificationCommands.RotateSigningKey(ctx, actor, reason)
	return signingKeyFromVerificationContext(value, nil), fromVerificationContextError(err)
}

func (l *Ledger) ListSigningKeys(ctx context.Context, actor domain.Actor) ([]domain.SigningKey, error) {
	values, err := l.verificationCommands.ListSigningKeys(ctx, actor)
	if err != nil {
		return nil, fromVerificationContextError(err)
	}
	result := make([]domain.SigningKey, 0, len(values))
	for _, value := range values {
		result = append(result, signingKeyFromVerificationContext(value, nil))
	}
	return result, nil
}

func (l *Ledger) RevokeSigningKeyWithPolicy(ctx context.Context, actor domain.Actor, keyID string, in SigningKeyRevocationInput) (domain.SigningKey, error) {
	value, err := l.verificationCommands.RevokeSigningKey(ctx, actor, keyID, verificationapp.SigningKeyRevocationInput{
		Reason: in.Reason, Semantics: in.Semantics, HistoricalValidityPolicy: in.HistoricalValidityPolicy,
	})
	return signingKeyFromVerificationContext(value, nil), fromVerificationContextError(err)
}

func (l *Ledger) CreateSigningProvider(ctx context.Context, actor domain.Actor, in CreateSigningProviderInput) (domain.SigningProvider, error) {
	value, err := l.verificationCommands.CreateSigningProvider(ctx, actor, verificationapp.CreateSigningProviderInput{
		Name: in.Name, Type: in.Type, KeyRef: in.KeyRef, Encrypted: in.Encrypted,
	})
	return signingProviderFromVerificationService(value), fromVerificationContextError(err)
}

func signingProviderFromVerificationService(value verificationdomain.SigningProvider) domain.SigningProvider {
	return domain.SigningProviderFromContextModel(value)
}
func (l *Ledger) CreateDSSETrustRoot(ctx context.Context, actor domain.Actor, in CreateDSSETrustRootInput) (domain.DSSETrustRoot, error) {
	value, err := l.verificationCommands.CreateDSSETrustRoot(ctx, actor, verificationapp.CreateDSSETrustRootInput{
		Name: in.Name, KeyID: in.KeyID, Algorithm: in.Algorithm, PublicKey: in.PublicKey,
		AllowedPredicateTypes: append([]string(nil), in.AllowedPredicateTypes...),
		ExpectedBuilderIDs:    append([]string(nil), in.ExpectedBuilderIDs...), RequiredClaims: append([]string(nil), in.RequiredClaims...),
	})
	return dsseTrustRootFromVerificationContext(value), fromVerificationContextError(err)
}
func (l *Ledger) VerifyDSSEAttestationSignature(ctx context.Context, actor domain.Actor, attestationID string) (domain.VerificationResult, error) {
	return l.VerifySubject(ctx, actor, "build_attestation", attestationID)
}
func (l *Ledger) VerifyCosignSignature(ctx context.Context, actor domain.Actor, in VerifyCosignInput) (domain.CosignVerification, error) {
	value, err := l.verificationCommands.VerifyCosign(ctx, actor, verificationapp.VerifyCosignInput{
		ArtifactSignatureID: in.ArtifactSignatureID, ExpectedIdentity: in.ExpectedIdentity, ExpectedIssuer: in.ExpectedIssuer,
		Mode: verificationapp.CosignVerificationMode(in.Mode), Offline: in.Offline,
	})
	return cosignVerificationFromVerificationContext(value), fromVerificationContextError(err)
}
func (l *Ledger) CreateMerkleBatch(ctx context.Context, actor domain.Actor, in CreateMerkleBatchInput) (domain.MerkleBatch, error) {
	value, err := l.verificationCommands.CreateMerkleBatch(ctx, actor, verificationapp.CreateMerkleBatchInput{FromSequence: in.FromSequence, ToSequence: in.ToSequence})
	return merkleBatchFromVerificationContext(value), fromVerificationContextError(err)
}

func (l *Ledger) CreateTransparencyCheckpoint(ctx context.Context, actor domain.Actor, in CreateTransparencyCheckpointInput) (domain.TransparencyCheckpoint, error) {
	value, err := l.verificationCommands.CreateTransparencyCheckpoint(ctx, actor, verificationapp.CreateTransparencyCheckpointInput{
		BatchID: in.BatchID, Provider: in.Provider, ExternalURL: in.ExternalURL, ExternalID: in.ExternalID,
	})
	return transparencyCheckpointFromVerificationContext(value), fromVerificationContextError(err)
}

func (l *Ledger) CreateObjectRetentionPolicy(ctx context.Context, actor domain.Actor, in CreateObjectRetentionPolicyInput) (domain.ObjectRetentionPolicy, error) {
	value, err := l.verificationCommands.CreateObjectRetentionPolicy(ctx, actor, verificationapp.CreateObjectRetentionPolicyInput{
		Name: in.Name, ObjectPrefix: in.ObjectPrefix, ObjectKey: in.ObjectKey, Mode: in.Mode,
		RetentionDays: in.RetentionDays, MaxVerificationAgeHours: in.MaxVerificationAgeHours,
		RequireLegalHold: in.RequireLegalHold,
	})
	return objectRetentionPolicyFromVerificationContext(value), fromVerificationContextError(err)
}

func (l *Ledger) VerifyObjectRetentionPolicy(ctx context.Context, actor domain.Actor, id string) (domain.ObjectRetentionPolicy, error) {
	value, err := l.verificationCommands.VerifyObjectRetentionPolicy(ctx, actor, id)
	return objectRetentionPolicyFromVerificationContext(value), fromVerificationContextError(err)
}

func (l *Ledger) SigningCustodyReviewReport(ctx context.Context, actor domain.Actor) (domain.SigningCustodyReviewReport, error) {
	value, err := l.verificationCommands.SigningCustodyReviewReport(ctx, actor)
	return signingCustodyReviewReportFromVerificationContext(value), fromVerificationContextError(err)
}

func (l *Ledger) GenerateBackupManifest(ctx context.Context, actor domain.Actor) (domain.BackupManifest, error) {
	value, err := l.verificationCommands.GenerateBackupManifest(ctx, actor)
	return backupManifestFromVerificationContext(value), fromVerificationContextError(err)
}

func signingCustodyReviewReportFromVerificationContext(value verificationdomain.SigningCustodyReviewReport) domain.SigningCustodyReviewReport {
	return domain.SigningCustodyReviewFromContextModel(value)
}
