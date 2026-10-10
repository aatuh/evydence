package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

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

type CreateArtifactSignatureInput struct {
	ArtifactID       string
	Algorithm        string
	KeyID            string
	Signature        string
	RawPayload       []byte
	PayloadMediaType string
}

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

func (l *Ledger) CreateArtifactSignature(ctx context.Context, actor domain.Actor, in CreateArtifactSignatureInput) (domain.ArtifactSignature, error) {
	if err := ctx.Err(); err != nil {
		return domain.ArtifactSignature{}, err
	}
	if err := require(actor, ScopeEvidenceWrite); err != nil {
		return domain.ArtifactSignature{}, err
	}
	in.ArtifactID, in.Algorithm, in.Signature = strings.TrimSpace(in.ArtifactID), strings.TrimSpace(in.Algorithm), strings.TrimSpace(in.Signature)
	if in.ArtifactID == "" || in.Algorithm == "" || in.Signature == "" {
		return domain.ArtifactSignature{}, ErrValidation
	}
	l.mu.Lock()
	artifact, ok := l.artifacts[in.ArtifactID]
	if !ok || artifact.TenantID != actor.TenantID {
		l.mu.Unlock()
		return domain.ArtifactSignature{}, ErrNotFound
	}
	if err := l.authorizeArtifactSignatureCreationLocked(actor, artifact); err != nil {
		l.mu.Unlock()
		return domain.ArtifactSignature{}, err
	}
	l.mu.Unlock()
	payloadHash, payloadRef := "", ""
	var stagedPayload ObjectPayload
	if len(in.RawPayload) > 0 {
		payloadHash = hashBytes(in.RawPayload)
		var err error
		stagedPayload, err = l.stagePayload(ctx, actor.TenantID, nonEmpty(in.PayloadMediaType, "application/octet-stream"), payloadHash, in.RawPayload)
		if err != nil {
			return domain.ArtifactSignature{}, err
		}
		payloadRef = stagedPayload.Reference()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	sig := domain.ArtifactSignature{
		ID:                 newID("artsig"),
		TenantID:           actor.TenantID,
		ArtifactID:         artifact.ID,
		SubjectDigest:      artifact.Digest,
		Algorithm:          in.Algorithm,
		KeyID:              strings.TrimSpace(in.KeyID),
		Signature:          in.Signature,
		PayloadRef:         payloadRef,
		PayloadHash:        payloadHash,
		VerificationStatus: "recorded",
		SchemaVersion:      domain.ArtifactSignatureSchemaVersion,
		CreatedAt:          l.now(),
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := l.persistStagedObjectPayload(ctx, repos, stagedPayload); err != nil {
				return err
			}
			if err := repos.SupplyChain.InsertArtifactSignature(ctx, sig); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(sig.CreatedAt, actor.TenantID, "artifact_signature.created", "artifact_signature", sig.ID, actorType(actor), actorID(actor), artifact.Digest, ""))
			return err
		}); err != nil {
			return domain.ArtifactSignature{}, err
		}
		l.artifactSigs[sig.ID] = sig
		l.publishCommittedAuditEntryLocked(entry)
		return sig, nil
	}
	l.artifactSigs[sig.ID] = sig
	_, _ = l.appendChainLocked(actor.TenantID, "artifact_signature.created", "artifact_signature", sig.ID, actorType(actor), actorID(actor), artifact.Digest, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.ArtifactSignature{}, err
	}
	return sig, nil
}
