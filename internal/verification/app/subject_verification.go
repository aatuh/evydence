package app

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// SubjectVerificationConfig binds a closed set of focused commands. Each
// command retains its own transactional resource authorization and receipt
// policy; the dispatcher cannot resolve arbitrary services or tenant state.
type SubjectVerificationConfig struct {
	Authorizer         application.Authorizer
	ReplayTransactions SubjectVerificationScopeTransactions
	AuditChain         interface {
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
	if c.Authorizer == nil || c.ReplayTransactions == nil || c.AuditChain == nil || c.Evidence == nil || c.ReleaseBundle == nil || c.DSSE == nil || c.ArtifactSignature == nil || c.Merkle == nil || c.MerkleCheckpoint == nil || c.ReleaseManifestCheckpoint == nil || c.Backup == nil {
		return nil, ErrValidation
	}
	return &SubjectVerificationCommands{config: c}, nil
}

func (s *SubjectVerificationCommands) VerifySubject(ctx context.Context, actor identitydomain.Actor, kind, id string) (verificationdomain.VerificationResult, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if err := validateSigningKeyActor(actor); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if err := s.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeVerifyRead, ScopeOnly: true}); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	var err error
	kind, id, err = NormalizeSubjectVerificationInput(kind, id)
	if err != nil {
		return verificationdomain.VerificationResult{}, err
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

// NormalizeSubjectVerificationInput bounds raw bytes before trimming, including
// an audit-chain ID consisting entirely of whitespace. The subject set is closed.
func NormalizeSubjectVerificationInput(kind, id string) (string, string, error) {
	if len(kind) > 64 || len(id) > 1024 || !validSigningKeyText(kind) || !utf8.ValidString(id) || strings.ContainsRune(id, 0) {
		return "", "", ErrValidation
	}
	kind, id = strings.TrimSpace(kind), strings.TrimSpace(id)
	switch kind {
	case "audit_chain":
		if id != "" {
			return "", "", ErrValidation
		}
	case "evidence_item", "release_bundle", "build_attestation", "artifact_signature", "merkle_batch", "audit_chain_checkpoint", "audit_chain_release_manifest", "backup_manifest":
		if id == "" {
			return "", "", ErrValidation
		}
	default:
		return "", "", ErrValidation
	}
	return kind, id, nil
}

// These ports resolve only current ownership, never mutable inspection facts,
// payloads, stored receipts, signing material or a tenant-wide state snapshot.
type SubjectVerificationScopeReader interface {
	ResolveSubjectVerificationScope(context.Context, string, string, string) (SubjectReference, error)
}
type SubjectVerificationScopeTransaction interface {
	SubjectVerificationScopeReader
	application.Authorizer
}
type SubjectVerificationScopeTransactions interface {
	ExecuteSubjectVerificationScope(context.Context, func(context.Context, SubjectVerificationScopeTransaction) error) error
}

// AuthorizeSubjectVerification joins the caller's durable replay transaction.
// Fresh execution still delegates inspection and receipt policy to its focused
// command; a stored success never substitutes for current resource permission.
func (s *SubjectVerificationCommands) AuthorizeSubjectVerification(ctx context.Context, actor identitydomain.Actor, kind, id string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := validateSigningKeyActor(actor); err != nil {
		return err
	}
	kind, id, err := NormalizeSubjectVerificationInput(kind, id)
	if err != nil {
		return err
	}
	if err := s.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeVerifyRead, ScopeOnly: true}); err != nil {
		return err
	}
	return s.config.ReplayTransactions.ExecuteSubjectVerificationScope(ctx, func(ctx context.Context, tx SubjectVerificationScopeTransaction) error {
		subject, err := tx.ResolveSubjectVerificationScope(ctx, actor.TenantID, kind, id)
		if err != nil {
			return err
		}
		if !validSubjectReference(subject, actor.TenantID, kind, id) {
			return ErrNotFound
		}
		if !validSubjectVerificationScope(kind, subject.Resources) {
			return ErrConflict
		}
		return tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeVerifyRead, Resources: subject.Resources, TenantWide: emptyResources(subject.Resources)})
	})
}

func validSubjectVerificationScope(kind string, refs application.ResourceReferences) bool {
	for _, id := range []string{refs.ProductID, refs.ProjectID, refs.ReleaseID, refs.ArtifactID, refs.BuildID, refs.DeploymentID, refs.EnvironmentID, refs.CustomerPackageID} {
		if id != "" && (!validSigningKeyText(id) || len(id) > 1024 || strings.TrimSpace(id) != id) {
			return false
		}
	}
	switch kind {
	case "audit_chain", "merkle_batch", "audit_chain_checkpoint", "audit_chain_release_manifest", "backup_manifest":
		return emptyResources(refs)
	case "release_bundle":
		return refs.ProductID != "" && refs.ReleaseID != "" && refs == (application.ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID})
	case "artifact_signature":
		return refs.ArtifactID != "" && refs == (application.ResourceReferences{ArtifactID: refs.ArtifactID})
	case "evidence_item", "build_attestation":
		if kind == "build_attestation" && (refs.BuildID == "" || refs.ProjectID == "" || refs.ReleaseID == "") {
			return false
		}
		return refs.ArtifactID == "" && refs.EnvironmentID == "" && refs.CustomerPackageID == ""
	default:
		return false
	}
}
