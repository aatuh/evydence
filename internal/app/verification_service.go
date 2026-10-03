package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

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
