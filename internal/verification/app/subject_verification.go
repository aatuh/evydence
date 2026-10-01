package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// SubjectVerificationConfig binds a closed set of focused commands. Each
// command retains its own transactional resource authorization and receipt
// policy; the dispatcher cannot resolve arbitrary services or tenant state.
type SubjectVerificationConfig struct {
	Authorizer application.Authorizer
	AuditChain interface {
		VerifyAuditChain(context.Context, identitydomain.Actor) (verificationdomain.VerificationResult, error)
	}
	Evidence interface {
		VerifyEvidence(context.Context, identitydomain.Actor, string) (verificationdomain.VerificationResult, error)
	}
	ReleaseBundle interface {
		VerifyReleaseBundle(context.Context, identitydomain.Actor, string) (verificationdomain.VerificationResult, error)
	}
	DSSE interface {
		VerifyDSSEAttestationSignature(context.Context, identitydomain.Actor, string) (verificationdomain.VerificationResult, error)
	}
	ArtifactSignature interface {
		VerifyArtifactSignature(context.Context, identitydomain.Actor, string) (verificationdomain.VerificationResult, error)
	}
	Merkle interface {
		VerifyMerkleBatch(context.Context, identitydomain.Actor, string) (verificationdomain.VerificationResult, error)
	}
	MerkleCheckpoint interface {
		VerifyMerkleCheckpoint(context.Context, identitydomain.Actor, string) (verificationdomain.VerificationResult, error)
	}
	ReleaseManifestCheckpoint interface {
		VerifyReleaseManifestCheckpoint(context.Context, identitydomain.Actor, string) (verificationdomain.VerificationResult, error)
	}
	Backup interface {
		VerifyBackupManifest(context.Context, identitydomain.Actor, string) (verificationdomain.VerificationResult, error)
	}
}

type SubjectVerificationCommands struct{ config SubjectVerificationConfig }

func NewSubjectVerificationCommands(c SubjectVerificationConfig) (*SubjectVerificationCommands, error) {
	if c.Authorizer == nil || c.AuditChain == nil || c.Evidence == nil || c.ReleaseBundle == nil || c.DSSE == nil || c.ArtifactSignature == nil || c.Merkle == nil || c.MerkleCheckpoint == nil || c.ReleaseManifestCheckpoint == nil || c.Backup == nil {
		return nil, ErrValidation
	}
	return &SubjectVerificationCommands{config: c}, nil
}

func (s *SubjectVerificationCommands) VerifySubject(ctx context.Context, actor identitydomain.Actor, kind, id string) (verificationdomain.VerificationResult, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if err := validateActor(actor); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if err := s.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeVerifyRead, ScopeOnly: true}); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	kind, id = strings.TrimSpace(kind), strings.TrimSpace(id)
	if !validSigningKeyText(kind) || len(kind) > 64 || len(id) > 1024 || id != "" && !validSigningKeyText(id) || kind == "audit_chain" && id != "" || kind != "audit_chain" && id == "" {
		return verificationdomain.VerificationResult{}, ErrValidation
	}
	switch kind {
	case "audit_chain":
		return s.config.AuditChain.VerifyAuditChain(ctx, actor)
	case "evidence_item":
		return s.config.Evidence.VerifyEvidence(ctx, actor, id)
	case "release_bundle":
		return s.config.ReleaseBundle.VerifyReleaseBundle(ctx, actor, id)
	case "build_attestation":
		return s.config.DSSE.VerifyDSSEAttestationSignature(ctx, actor, id)
	case "artifact_signature":
		return s.config.ArtifactSignature.VerifyArtifactSignature(ctx, actor, id)
	case "merkle_batch":
		return s.config.Merkle.VerifyMerkleBatch(ctx, actor, id)
	case "audit_chain_checkpoint":
		return s.config.MerkleCheckpoint.VerifyMerkleCheckpoint(ctx, actor, id)
	case "audit_chain_release_manifest":
		return s.config.ReleaseManifestCheckpoint.VerifyReleaseManifestCheckpoint(ctx, actor, id)
	case "backup_manifest":
		return s.config.Backup.VerifyBackupManifest(ctx, actor, id)
	default:
		return verificationdomain.VerificationResult{}, ErrValidation
	}
}
