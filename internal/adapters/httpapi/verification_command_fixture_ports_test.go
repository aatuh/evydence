package httpapi

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/authz"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// These adapters exist only in the test binary. Guards retain the actual
// former policies, while commands run on the fixture's isolated replay clone.
// They do not emulate PostgreSQL ownership locks or its v2 backup commitment.
type verificationCommandFixture struct {
	catalogFixtureCommands
	dsseObjects      app.BoundedObjectReader
	backupCommitment backupGenerationContractCommitment
}

func (f verificationCommandFixture) AuthorizeSubjectVerification(ctx context.Context, actor domain.Actor, kind, id string) error {
	if strings.TrimSpace(kind) == "build_attestation" {
		return f.AuthorizeDSSEVerification(ctx, actor, id)
	}
	if strings.TrimSpace(kind) == "evidence_item" {
		return f.authorizeCurrentEvidenceVerification(ctx, actor, id)
	}
	if strings.TrimSpace(kind) == "artifact_signature" {
		return f.authorizeCurrentArtifactMetadata(ctx, actor, id)
	}
	if strings.TrimSpace(kind) == "backup_manifest" {
		return f.authorizeCurrentBackup(ctx, actor, id)
	}
	if strings.TrimSpace(kind) == "release_bundle" {
		return f.authorizeCurrentReleaseBundle(ctx, actor, id)
	}
	if strings.TrimSpace(kind) == "merkle_batch" {
		return f.authorizeCurrentMerkle(ctx, actor, id)
	}
	return f.authorizeCurrentSubjectScope(ctx, actor, kind, id)
}

func (f verificationCommandFixture) VerifySubject(ctx context.Context, actor domain.Actor, kind, id string) (verificationdomain.VerificationResult, error) {
	var err error
	kind, id, err = verificationapp.NormalizeSubjectVerificationInput(kind, id)
	if err != nil {
		return verificationdomain.VerificationResult{}, mapVerificationCommandError(err)
	}
	if strings.TrimSpace(kind) == "build_attestation" {
		return f.VerifyDSSEAttestationSignature(ctx, actor, id)
	}
	if strings.TrimSpace(kind) == "evidence_item" {
		return f.verifyCurrentEvidence(ctx, actor, id)
	}
	if strings.TrimSpace(kind) == "artifact_signature" {
		return f.verifyCurrentArtifactMetadata(ctx, actor, id)
	}
	if strings.TrimSpace(kind) == "backup_manifest" {
		return f.verifyCurrentBackup(ctx, actor, id)
	}
	if strings.TrimSpace(kind) == "release_bundle" {
		return f.verifyCurrentReleaseBundle(ctx, actor, id)
	}
	if strings.TrimSpace(kind) == "merkle_batch" {
		return f.verifyCurrentMerkle(ctx, actor, id)
	}
	switch kind {
	case "audit_chain":
		return f.verifyCurrentAuditChain(ctx, actor)
	case "audit_chain_checkpoint":
		return f.verifyCurrentAuditMerkleCheckpoint(ctx, actor, id)
	case "audit_chain_release_manifest":
		return f.verifyCurrentAuditManifestCheckpoint(ctx, actor, id)
	default:
		return verificationdomain.VerificationResult{}, app.ErrValidation
	}
}

func (f verificationCommandFixture) VerifyReleaseBundle(ctx context.Context, actor domain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return f.VerifySubject(ctx, actor, "release_bundle", id)
}

func (f verificationCommandFixture) AuthorizeDSSEVerification(ctx context.Context, actor domain.Actor, id string) error {
	c, err := f.nativeDSSE(true)
	if err != nil {
		return mapVerificationCommandError(err)
	}
	return mapVerificationCommandError(c.AuthorizeDSSEVerification(ctx, actor, id))
}

func (f verificationCommandFixture) VerifyDSSEAttestationSignature(ctx context.Context, actor domain.Actor, id string) (verificationdomain.VerificationResult, error) {
	if ctx == nil {
		return verificationdomain.VerificationResult{}, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	c, err := f.nativeDSSE(false)
	if err != nil {
		return verificationdomain.VerificationResult{}, mapVerificationCommandError(err)
	}
	value, err := c.VerifyDSSEAttestationSignature(ctx, actor, id)
	return value, mapVerificationCommandError(err)
}

func (f verificationCommandFixture) AuthorizeCosignVerification(ctx context.Context, actor domain.Actor, _ verificationapp.VerifyCosignInput) error {
	return authz.Authorize(ctx, actor, authz.Request{Action: authz.ActionTenantSubjectVerify})
}

func fixtureVerificationProfile(value domain.VerificationProfile) verificationdomain.VerificationProfile {
	return verificationdomain.VerificationProfile{ID: value.ID, Version: value.Version, RequiredChecks: slices.Clone(value.RequiredChecks), TrustMaterial: slices.Clone(value.TrustMaterial), IdentityPolicy: value.IdentityPolicy, TransparencyProof: value.TransparencyProof, PayloadScope: value.PayloadScope, PayloadDigest: value.PayloadDigest, Limitations: slices.Clone(value.Limitations)}
}

func fixtureCosignVerification(value domain.CosignVerification, err error) (verificationdomain.CosignVerification, error) {
	if err != nil && !errors.Is(err, app.ErrVerificationFailed) {
		return verificationdomain.CosignVerification{}, err
	}
	checks := make([]verificationdomain.VerifyCheck, 0, len(value.Checks))
	for _, check := range value.Checks {
		checks = append(checks, verificationdomain.VerifyCheck(check))
	}
	return verificationdomain.CosignVerification{ID: value.ID, TenantID: value.TenantID, ArtifactID: value.ArtifactID, ContainerImageID: value.ContainerImageID, ArtifactSignatureID: value.ArtifactSignatureID, SubjectDigest: value.SubjectDigest, RekorUUID: value.RekorUUID, RekorLogIndex: value.RekorLogIndex, CertificateIdentity: value.CertificateIdentity, CertificateIssuer: value.CertificateIssuer, VerifierLibraryVersion: value.VerifierLibraryVersion, TrustRootVersion: value.TrustRootVersion, VerificationMode: value.VerificationMode, Result: value.Result, Checks: checks, Profile: fixtureVerificationProfile(value.Profile), Limitations: slices.Clone(value.Limitations), SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt}, err
}

func (f verificationCommandFixture) VerifyCosign(ctx context.Context, actor domain.Actor, input verificationapp.VerifyCosignInput) (verificationdomain.CosignVerification, error) {
	c, err := f.nativeCosign()
	if err != nil {
		return verificationdomain.CosignVerification{}, err
	}
	v, err := c.VerifyCosign(ctx, actor, input)
	return v, mapVerificationCommandError(err)
}

func (f verificationCommandFixture) AuthorizeBackupGeneration(ctx context.Context, actor domain.Actor) error {
	if err := authz.Authorize(ctx, actor, authz.Request{Action: authz.ActionBackupGenerate}); err != nil {
		return err
	}
	c, err := f.nativeBackupGeneration()
	if err != nil {
		return mapVerificationCommandError(err)
	}
	return mapVerificationCommandError(c.AuthorizeBackupGeneration(ctx, actor))
}

func fixtureBackupManifest(value domain.BackupManifest) verificationdomain.BackupManifest {
	counts := make(map[string]int, len(value.ResourceCounts))
	for name, count := range value.ResourceCounts {
		counts[name] = count
	}
	checks := make([]verificationdomain.VerifyCheck, 0, len(value.ConsistencyChecks))
	for _, check := range value.ConsistencyChecks {
		checks = append(checks, verificationdomain.VerifyCheck(check))
	}
	return verificationdomain.BackupManifest{ID: value.ID, TenantID: value.TenantID, StateHash: value.StateHash, ResourceCounts: counts, ConsistencyChecks: checks, Limitations: slices.Clone(value.Limitations), SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt}
}

func (f verificationCommandFixture) GenerateBackupManifest(ctx context.Context, actor domain.Actor) (verificationdomain.BackupManifest, error) {
	c, err := f.nativeBackupGeneration()
	if err != nil {
		return verificationdomain.BackupManifest{}, mapVerificationCommandError(err)
	}
	value, err := c.GenerateBackupManifest(ctx, actor)
	return value, mapVerificationCommandError(err)
}

func (f verificationCommandFixture) AuthorizeMerkleCreation(ctx context.Context, actor domain.Actor) error {
	return (merkleCreationFixtureCommands{catalogFixtureCommands: f.catalogFixtureCommands}).AuthorizeMerkleCreation(ctx, actor)
}

func (f verificationCommandFixture) CreateMerkleBatch(ctx context.Context, actor domain.Actor, input verificationapp.CreateMerkleBatchInput) (verificationdomain.MerkleBatch, error) {
	return (merkleCreationFixtureCommands{catalogFixtureCommands: f.catalogFixtureCommands}).CreateMerkleBatch(ctx, actor, input)
}

func (f verificationCommandFixture) AuthorizeTransparencyCheckpoint(ctx context.Context, actor domain.Actor, id string) error {
	return (merkleCreationFixtureCommands{catalogFixtureCommands: f.catalogFixtureCommands}).AuthorizeTransparencyCheckpoint(ctx, actor, id)
}

func (f verificationCommandFixture) CreateTransparencyCheckpoint(ctx context.Context, actor domain.Actor, input verificationapp.CreateTransparencyCheckpointInput) (verificationdomain.TransparencyCheckpoint, error) {
	return (merkleCreationFixtureCommands{catalogFixtureCommands: f.catalogFixtureCommands}).CreateTransparencyCheckpoint(ctx, actor, input)
}

func (f verificationCommandFixture) AuthorizeCreateObjectRetentionPolicy(ctx context.Context, actor domain.Actor, in verificationapp.CreateObjectRetentionPolicyInput) error {
	return (retentionFixtureCommands{catalogFixtureCommands: f.catalogFixtureCommands}).AuthorizeCreateObjectRetentionPolicy(ctx, actor, in)
}

func (f verificationCommandFixture) AuthorizeVerifyObjectRetentionPolicy(ctx context.Context, actor domain.Actor, id string) error {
	return (retentionFixtureCommands{catalogFixtureCommands: f.catalogFixtureCommands}).AuthorizeVerifyObjectRetentionPolicy(ctx, actor, id)
}

func (f verificationCommandFixture) CreateObjectRetentionPolicy(ctx context.Context, actor domain.Actor, input verificationapp.CreateObjectRetentionPolicyInput) (verificationdomain.ObjectRetentionPolicy, error) {
	return (retentionFixtureCommands{catalogFixtureCommands: f.catalogFixtureCommands}).CreateObjectRetentionPolicy(ctx, actor, input)
}

func (f verificationCommandFixture) VerifyObjectRetentionPolicy(ctx context.Context, actor domain.Actor, id string) (verificationdomain.ObjectRetentionPolicy, error) {
	return (retentionFixtureCommands{catalogFixtureCommands: f.catalogFixtureCommands}).VerifyObjectRetentionPolicy(ctx, actor, id)
}

func (s *Server) bindVerificationCommandFixturePorts(ledger *repositoryFixture) {
	commands := verificationCommandFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	if old, fixture := s.subjectVerification.(verificationCommandFixture); fixture {
		old.ledger = ledger
		s.subjectVerification = old
	} else if s.subjectVerification == nil {
		s.subjectVerification = commands
	}
	if _, fixture := s.releaseBundleVerification.(verificationCommandFixture); s.releaseBundleVerification == nil || fixture {
		s.releaseBundleVerification = commands
	}
	if old, fixture := s.dsseVerification.(verificationCommandFixture); fixture {
		old.ledger = ledger
		s.dsseVerification = old
	} else if s.dsseVerification == nil {
		s.dsseVerification = commands
	}
	if _, fixture := s.cosignVerification.(verificationCommandFixture); s.cosignVerification == nil || fixture {
		s.cosignVerification = commands
	}
	if _, fixture := s.backupGenerationCommands.(verificationCommandFixture); s.backupGenerationCommands == nil || fixture {
		s.backupGenerationCommands = commands
	}
	if old, fixture := s.merkleCreationCommands.(merkleCreationFixtureCommands); fixture {
		old.ledger = ledger
		s.merkleCreationCommands = old
	} else if _, legacy := s.merkleCreationCommands.(verificationCommandFixture); s.merkleCreationCommands == nil || legacy {
		s.merkleCreationCommands = merkleCreationFixtureCommands{catalogFixtureCommands: commands.catalogFixtureCommands}
	}
	if old, fixture := s.transparencyCheckpointCommands.(merkleCreationFixtureCommands); fixture {
		old.ledger = ledger
		s.transparencyCheckpointCommands = old
	} else if _, legacy := s.transparencyCheckpointCommands.(verificationCommandFixture); s.transparencyCheckpointCommands == nil || legacy {
		s.transparencyCheckpointCommands = merkleCreationFixtureCommands{catalogFixtureCommands: commands.catalogFixtureCommands}
	}
	if old, fixture := s.retentionCommands.(retentionFixtureCommands); fixture {
		old.ledger = ledger
		s.retentionCommands = old
	} else if _, legacy := s.retentionCommands.(verificationCommandFixture); s.retentionCommands == nil || legacy {
		s.retentionCommands = retentionFixtureCommands{catalogFixtureCommands: commands.catalogFixtureCommands}
	}
}

var (
	_ SubjectVerification            = verificationCommandFixture{}
	_ ReleaseBundleVerification      = verificationCommandFixture{}
	_ DSSEVerification               = verificationCommandFixture{}
	_ CosignVerification             = verificationCommandFixture{}
	_ BackupGenerationCommands       = verificationCommandFixture{}
	_ MerkleCreationCommands         = verificationCommandFixture{}
	_ TransparencyCheckpointCommands = verificationCommandFixture{}
	_ RetentionCommands              = verificationCommandFixture{}
)
