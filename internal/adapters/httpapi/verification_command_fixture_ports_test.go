package httpapi

import (
	"context"
	"errors"
	"slices"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// These adapters exist only in the test binary. Guards retain the actual
// former policies, while commands run on the fixture's isolated replay clone.
// They do not emulate PostgreSQL ownership locks or its v2 backup commitment.
type verificationCommandFixture struct{ catalogFixtureCommands }

func (f verificationCommandFixture) AuthorizeSubjectVerification(ctx context.Context, actor domain.Actor, kind, id string) error {
	return f.commandLedger(ctx).AuthorizeSubjectVerification(ctx, actor, kind, id)
}

func (f verificationCommandFixture) VerifySubject(ctx context.Context, actor domain.Actor, kind, id string) (verificationdomain.VerificationResult, error) {
	value, err := f.commandLedger(ctx).VerifySubject(ctx, actor, kind, id)
	return fixtureVerificationResult(value, err)
}

func (f verificationCommandFixture) VerifyReleaseBundle(ctx context.Context, actor domain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return f.VerifySubject(ctx, actor, "release_bundle", id)
}

func (f verificationCommandFixture) AuthorizeDSSEVerification(ctx context.Context, actor domain.Actor, id string) error {
	return f.commandLedger(ctx).AuthorizeDSSEVerification(ctx, actor, id)
}

func (f verificationCommandFixture) VerifyDSSEAttestationSignature(ctx context.Context, actor domain.Actor, id string) (verificationdomain.VerificationResult, error) {
	value, err := f.commandLedger(ctx).VerifyDSSEAttestationSignature(ctx, actor, id)
	return fixtureVerificationResult(value, err)
}

func (f verificationCommandFixture) AuthorizeCosignVerification(ctx context.Context, actor domain.Actor, _ verificationapp.VerifyCosignInput) error {
	return application.AuthorizeTenantWideScope(ctx, actor, app.ScopeVerifyRead)
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
	value, err := f.commandLedger(ctx).VerifyCosignSignature(ctx, actor, app.VerifyCosignInput{ArtifactSignatureID: input.ArtifactSignatureID, ExpectedIdentity: input.ExpectedIdentity, ExpectedIssuer: input.ExpectedIssuer, Mode: app.CosignVerificationMode(input.Mode), Offline: input.Offline})
	return fixtureCosignVerification(value, err)
}

func (f verificationCommandFixture) AuthorizeBackupGeneration(ctx context.Context, actor domain.Actor) error {
	return application.AuthorizeTenantWideScope(ctx, actor, app.ScopeAdmin)
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
	value, err := f.commandLedger(ctx).GenerateBackupManifest(ctx, actor)
	if err != nil {
		return verificationdomain.BackupManifest{}, err
	}
	return fixtureBackupManifest(value), nil
}

func (f verificationCommandFixture) AuthorizeMerkleCreation(ctx context.Context, actor domain.Actor) error {
	return application.AuthorizeTenantWideScope(ctx, actor, app.ScopeKeysAdmin)
}

func (f verificationCommandFixture) CreateMerkleBatch(ctx context.Context, actor domain.Actor, input verificationapp.CreateMerkleBatchInput) (verificationdomain.MerkleBatch, error) {
	value, err := f.commandLedger(ctx).CreateMerkleBatch(ctx, actor, app.CreateMerkleBatchInput(input))
	return verificationdomain.MerkleBatch(value), err
}

func (f verificationCommandFixture) AuthorizeTransparencyCheckpoint(ctx context.Context, actor domain.Actor, _ string) error {
	return application.AuthorizeTenantWideScope(ctx, actor, app.ScopeKeysAdmin)
}

func (f verificationCommandFixture) CreateTransparencyCheckpoint(ctx context.Context, actor domain.Actor, input verificationapp.CreateTransparencyCheckpointInput) (verificationdomain.TransparencyCheckpoint, error) {
	value, err := f.commandLedger(ctx).CreateTransparencyCheckpoint(ctx, actor, app.CreateTransparencyCheckpointInput(input))
	return verificationdomain.TransparencyCheckpoint(value), err
}

func (f verificationCommandFixture) AuthorizeCreateObjectRetentionPolicy(ctx context.Context, actor domain.Actor, _ verificationapp.CreateObjectRetentionPolicyInput) error {
	return application.AuthorizeTenantWideScope(ctx, actor, app.ScopeAdmin)
}

func (f verificationCommandFixture) AuthorizeVerifyObjectRetentionPolicy(ctx context.Context, actor domain.Actor, _ string) error {
	return application.AuthorizeTenantWideScope(ctx, actor, app.ScopeVerifyRead)
}

func (f verificationCommandFixture) CreateObjectRetentionPolicy(ctx context.Context, actor domain.Actor, input verificationapp.CreateObjectRetentionPolicyInput) (verificationdomain.ObjectRetentionPolicy, error) {
	value, err := f.commandLedger(ctx).CreateObjectRetentionPolicy(ctx, actor, app.CreateObjectRetentionPolicyInput(input))
	return domain.ObjectRetentionPolicyToContextModel(value), err
}

func (f verificationCommandFixture) VerifyObjectRetentionPolicy(ctx context.Context, actor domain.Actor, id string) (verificationdomain.ObjectRetentionPolicy, error) {
	value, err := f.commandLedger(ctx).VerifyObjectRetentionPolicy(ctx, actor, id)
	return domain.ObjectRetentionPolicyToContextModel(value), err
}

func (s *Server) bindVerificationCommandFixturePorts(ledger *app.Ledger) {
	commands := verificationCommandFixture{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.subjectVerification.(verificationCommandFixture); s.subjectVerification == nil || fixture {
		s.subjectVerification = commands
	}
	if _, fixture := s.releaseBundleVerification.(verificationCommandFixture); s.releaseBundleVerification == nil || fixture {
		s.releaseBundleVerification = commands
	}
	if _, fixture := s.dsseVerification.(verificationCommandFixture); s.dsseVerification == nil || fixture {
		s.dsseVerification = commands
	}
	if _, fixture := s.cosignVerification.(verificationCommandFixture); s.cosignVerification == nil || fixture {
		s.cosignVerification = commands
	}
	if _, fixture := s.backupGenerationCommands.(verificationCommandFixture); s.backupGenerationCommands == nil || fixture {
		s.backupGenerationCommands = commands
	}
	if _, fixture := s.merkleCreationCommands.(verificationCommandFixture); s.merkleCreationCommands == nil || fixture {
		s.merkleCreationCommands = commands
	}
	if _, fixture := s.transparencyCheckpointCommands.(verificationCommandFixture); s.transparencyCheckpointCommands == nil || fixture {
		s.transparencyCheckpointCommands = commands
	}
	if _, fixture := s.retentionCommands.(verificationCommandFixture); s.retentionCommands == nil || fixture {
		s.retentionCommands = commands
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
