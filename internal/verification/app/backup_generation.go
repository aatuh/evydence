package app

import (
	"context"
	"encoding/hex"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

const (
	BackupStateCommitmentProfile  = "tenant-relational-state.v1"
	MaxBackupStateCommitmentRows  = 32768
	MaxBackupStateCommitmentBytes = 8 << 20
)

// BackupStateCommitment contains only a completed digest and scalar counts.
// A reader must hash the full declared profile in one committed view, exclude
// credential material, and fail rather than truncate at its synchronous bounds.
type BackupStateCommitment struct {
	TenantID, Profile, StateHash string
	ResourceCounts               map[string]int
	RowsRead, BytesRead          int
}
type BackupStateCommitmentReader interface {
	ReadBackupStateCommitment(context.Context, string) (BackupStateCommitment, error)
}
type BackupGenerationTransaction interface {
	BackupStateCommitmentReader
	AuditChainVerificationReader
	application.Authorizer
	application.AuditAppender
	InsertBackupManifest(context.Context, verificationdomain.BackupManifest) error
}
type BackupGenerationTransactions interface {
	ExecuteBackupGeneration(context.Context, func(context.Context, BackupGenerationTransaction) error) error
}
type BackupGenerationConfig struct {
	Transactions BackupGenerationTransactions
	Authorizer   application.Authorizer
	Hasher       CanonicalHasher
	Verifier     PayloadSignatureVerifier
	Clock        application.Clock
	IDs          application.IDGenerator
}
type BackupGenerationCommands struct{ config BackupGenerationConfig }

func NewBackupGenerationCommands(c BackupGenerationConfig) (*BackupGenerationCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Hasher == nil || c.Verifier == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &BackupGenerationCommands{c}, nil
}
func (s *BackupGenerationCommands) GenerateBackupManifest(ctx context.Context, a identitydomain.Actor) (verificationdomain.BackupManifest, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.BackupManifest{}, err
	}
	if err := validateActor(a); err != nil {
		return verificationdomain.BackupManifest{}, err
	}
	request := application.AuthorizationRequest{Scope: ScopeAdmin, TenantWide: true}
	if err := s.config.Authorizer.Authorize(ctx, a, request); err != nil {
		return verificationdomain.BackupManifest{}, err
	}
	var result verificationdomain.BackupManifest
	err := s.config.Transactions.ExecuteBackupGeneration(ctx, func(ctx context.Context, tx BackupGenerationTransaction) error {
		if err := tx.Authorize(ctx, a, request); err != nil {
			return err
		}
		commitment, err := tx.ReadBackupStateCommitment(ctx, a.TenantID)
		if err != nil {
			return err
		}
		if commitment.TenantID != a.TenantID {
			return ErrNotFound
		}
		if !validBackupStateCommitment(commitment) {
			return ErrConflict
		}
		view, err := tx.LockAuditChainVerification(ctx, a.TenantID)
		if err != nil {
			return err
		}
		if int64(commitment.ResourceCounts["audit_chain_entries"]) != view.EntryCount {
			return ErrConflict
		}
		now := s.config.Clock.Now().UTC()
		inspection, err := inspectAuditChainView(ctx, tx, view, a.TenantID, now, s.config.Hasher, s.config.Verifier, nil)
		if err != nil {
			return err
		}
		manifest := verificationdomain.BackupManifest{ID: s.config.IDs.NewID("bak"), TenantID: a.TenantID, StateHash: commitment.StateHash, ResourceCounts: cloneStringIntMap(commitment.ResourceCounts), ConsistencyChecks: append([]verificationdomain.VerifyCheck(nil), inspection.Checks...), SchemaVersion: verificationdomain.BackupManifestTenantSchemaVersion, CreatedAt: now, Limitations: []string{
			"State commitment profile: " + BackupStateCommitmentProfile + "; tenant-owned declared relational metadata only, not the historical whole-instance Ledger snapshot hash.",
			"Credential material and raw object payload bytes are excluded; this manifest is not a restorable backup or proof of a successful restore.",
			"Restore requires database and object-store backups from the same point in time; local audit checks do not prove external anchoring.",
		}}
		if err := tx.InsertBackupManifest(ctx, manifest); err != nil {
			return err
		}
		if _, err := tx.AppendAudit(ctx, application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "backup_manifest.generated", SubjectType: "backup_manifest", SubjectID: manifest.ID, PayloadHash: manifest.StateHash, ActorType: auditActorType(a), ActorID: auditActorID(a), OccurredAt: now}); err != nil {
			return err
		}
		result = cloneBackupManifest(manifest)
		return nil
	})
	if err != nil {
		return verificationdomain.BackupManifest{}, err
	}
	return result, nil
}
func validBackupStateCommitment(c BackupStateCommitment) bool {
	if c.Profile != BackupStateCommitmentProfile || len(c.StateHash) != len("sha256:")+64 || !strings.HasPrefix(c.StateHash, "sha256:") || strings.ToLower(c.StateHash) != c.StateHash || c.RowsRead < 1 || c.RowsRead > MaxBackupStateCommitmentRows || c.BytesRead < 1 || c.BytesRead > MaxBackupStateCommitmentBytes {
		return false
	}
	if _, err := hex.DecodeString(c.StateHash[len("sha256:"):]); err != nil {
		return false
	}
	names := []string{"audit_chain_entries", "artifact_signatures", "cosign_verifications", "evidence", "merkle_batches", "object_retention_policies", "release_bundles", "transparency_checkpoints"}
	if len(c.ResourceCounts) != len(names) {
		return false
	}
	sum := 0
	for _, name := range names {
		count, ok := c.ResourceCounts[name]
		if !ok || count < 0 || count > c.RowsRead {
			return false
		}
		sum += count
	}
	return sum <= c.RowsRead
}
