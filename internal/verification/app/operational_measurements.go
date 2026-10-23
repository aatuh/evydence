package app

import (
	"context"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	"github.com/aatuh/evydence/internal/platform/telemetry"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// Measurements preserve command/parser results, transaction ownership and context.
func (p *MerkleCreationCommands) CreateMerkleBatch(ctx context.Context, a identitydomain.Actor, in CreateMerkleBatchInput) (verificationdomain.MerkleBatch, error) {
	return telemetry.Measure(ctx, telemetry.OperationSigning, func(callCtx context.Context) (verificationdomain.MerkleBatch, error) {
		return p.createMerkleBatch(callCtx, a, in)
	})
}

func (p *EvidenceVerificationCommands) VerifyEvidence(ctx context.Context, actor identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return telemetry.Measure(ctx, telemetry.OperationVerification, func(callCtx context.Context) (verificationdomain.VerificationResult, error) {
		return p.verifyEvidence(callCtx, actor, id)
	})
}

func (p *ArtifactSignatureVerificationCommands) VerifyArtifactSignature(ctx context.Context, actor identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return telemetry.Measure(ctx, telemetry.OperationVerification, func(callCtx context.Context) (verificationdomain.VerificationResult, error) {
		return p.verifyArtifactSignature(callCtx, actor, id)
	})
}

func (p *ReleaseBundleVerificationCommands) VerifyReleaseBundle(ctx context.Context, actor identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return telemetry.Measure(ctx, telemetry.OperationVerification, func(callCtx context.Context) (verificationdomain.VerificationResult, error) {
		return p.verifyReleaseBundle(callCtx, actor, id)
	})
}

func (p *DSSEVerificationCommands) VerifyDSSEAttestationSignature(ctx context.Context, actor identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return telemetry.Measure(ctx, telemetry.OperationVerification, func(callCtx context.Context) (verificationdomain.VerificationResult, error) {
		return p.verifyDSSEAttestationSignature(callCtx, actor, id)
	})
}

func (p *MerkleVerificationCommands) VerifyMerkleBatch(ctx context.Context, actor identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return telemetry.Measure(ctx, telemetry.OperationVerification, func(callCtx context.Context) (verificationdomain.VerificationResult, error) {
		return p.verifyMerkleBatch(callCtx, actor, id)
	})
}

func (p *MerkleCheckpointVerificationCommands) VerifyMerkleCheckpoint(ctx context.Context, actor identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return telemetry.Measure(ctx, telemetry.OperationVerification, func(callCtx context.Context) (verificationdomain.VerificationResult, error) {
		return p.verifyMerkleCheckpoint(callCtx, actor, id)
	})
}

func (p *BackupVerificationCommands) VerifyBackupManifest(ctx context.Context, actor identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return telemetry.Measure(ctx, telemetry.OperationVerification, func(callCtx context.Context) (verificationdomain.VerificationResult, error) {
		return p.verifyBackupManifest(callCtx, actor, id)
	})
}

func (p *ReleaseManifestCheckpointCommands) VerifyReleaseManifestCheckpoint(ctx context.Context, actor identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return telemetry.Measure(ctx, telemetry.OperationVerification, func(callCtx context.Context) (verificationdomain.VerificationResult, error) {
		return p.verifyReleaseManifestCheckpoint(callCtx, actor, id)
	})
}

func (p *AuditChainVerificationCommands) VerifyAuditChain(ctx context.Context, actor identitydomain.Actor) (verificationdomain.VerificationResult, error) {
	return telemetry.Measure(ctx, telemetry.OperationVerification, func(callCtx context.Context) (verificationdomain.VerificationResult, error) {
		return p.verifyAuditChain(callCtx, actor)
	})
}

func (p *CosignVerificationCommands) VerifyCosign(ctx context.Context, actor identitydomain.Actor, input VerifyCosignInput) (verificationdomain.CosignVerification, error) {
	return telemetry.Measure(ctx, telemetry.OperationVerification, func(callCtx context.Context) (verificationdomain.CosignVerification, error) {
		return p.verifyCosign(callCtx, actor, input)
	})
}

func (p *SigningOperationCommands) CreateSigningOperation(ctx context.Context, a identitydomain.Actor, in SigningOperationInput) (verificationdomain.SigningOperation, error) {
	return telemetry.Measure(ctx, telemetry.OperationSigning, func(callCtx context.Context) (verificationdomain.SigningOperation, error) {
		return p.createSigningOperation(callCtx, a, in)
	})
}
