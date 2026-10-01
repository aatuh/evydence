package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type MerkleCheckpointVerificationTransaction interface {
	AuditChainVerificationTransaction
	MerkleVerificationReader
}
type MerkleCheckpointVerificationTransactions interface {
	ExecuteMerkleCheckpointVerification(context.Context, func(context.Context, MerkleCheckpointVerificationTransaction) error) error
}
type MerkleCheckpointVerificationConfig struct {
	Transactions MerkleCheckpointVerificationTransactions
	Authorizer   application.Authorizer
	Hasher       CanonicalHasher
	Verifier     PayloadSignatureVerifier
	Clock        application.Clock
	IDs          application.IDGenerator
}
type MerkleCheckpointVerificationCommands struct {
	config MerkleCheckpointVerificationConfig
}

func NewMerkleCheckpointVerificationCommands(c MerkleCheckpointVerificationConfig) (*MerkleCheckpointVerificationCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Hasher == nil || c.Verifier == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &MerkleCheckpointVerificationCommands{c}, nil
}
func (s *MerkleCheckpointVerificationCommands) VerifyMerkleCheckpoint(ctx context.Context, actor identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if err := validateActor(actor); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if err := s.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeVerifyRead, ScopeOnly: true}); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	id = strings.TrimSpace(id)
	if !validSigningKeyText(id) || len(id) > 1024 {
		return verificationdomain.VerificationResult{}, ErrValidation
	}
	var result verificationdomain.VerificationResult
	err := s.config.Transactions.ExecuteMerkleCheckpointVerification(ctx, func(ctx context.Context, tx MerkleCheckpointVerificationTransaction) error {
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeVerifyRead, TenantWide: true}); err != nil {
			return err
		}
		// The full-chain fence precedes the batch lock, matching audit writers.
		view, err := tx.LockAuditChainVerification(ctx, actor.TenantID)
		if err != nil {
			return err
		}
		if view.TenantID != actor.TenantID {
			return ErrNotFound
		}
		subject, err := tx.ResolveMerkleVerificationSubject(ctx, actor.TenantID, id)
		if err != nil {
			return err
		}
		if !validSubjectReference(subject, actor.TenantID, "merkle_batch", id) || subject.Resources != (application.ResourceReferences{}) {
			return ErrNotFound
		}
		snapshot, err := tx.ReadMerkleVerification(ctx, subject)
		if err != nil {
			return err
		}
		if snapshot.Subject != subject {
			return ErrConflict
		}
		now := s.config.Clock.Now().UTC()
		merkle, err := InspectMerkleBatch(snapshot, now, s.config.Verifier)
		if err != nil {
			return err
		}
		// Bind the checkpoint to hashes from the very same pages whose
		// canonical contents were inspected, not an independent projection.
		var derived []AuditChainLeaf
		chain, err := inspectAuditChainView(ctx, tx, view, actor.TenantID, now, s.config.Hasher, s.config.Verifier, func(e verificationdomain.AuditChainEntry) {
			if snapshot.Batch.FromSequence >= 1 && snapshot.Batch.ToSequence >= snapshot.Batch.FromSequence && e.Sequence >= snapshot.Batch.FromSequence && e.Sequence <= snapshot.Batch.ToSequence {
				derived = append(derived, AuditChainLeaf{Sequence: e.Sequence, EntryHash: e.EntryHash})
			}
		})
		if err != nil {
			return err
		}
		inspection := inspectMerkleAuditChainCheckpoint(chain, view.EntryCount, snapshot, derived, merkle)
		result, err = persistVerificationReceipt(ctx, tx, actor, SubjectReference{TenantID: actor.TenantID, Type: "audit_chain_checkpoint", ID: id}, inspection, now, s.config.IDs)
		return err
	})
	if err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if verificationReturnsFailure(result.Result) {
		return cloneVerificationResult(result), ErrVerificationFailed
	}
	return cloneVerificationResult(result), nil
}

func inspectMerkleAuditChainCheckpoint(chain SubjectInspection, count int64, snapshot MerkleVerificationSnapshot, derived []AuditChainLeaf, merkle SubjectInspection) SubjectInspection {
	// Reuse the bounded Merkle/signing material validation, not its profile:
	// the audit-chain checkpoint additionally checks every canonical entry.
	b := snapshot.Batch
	bound := len(derived) == len(snapshot.Leaves)
	for i, leaf := range derived {
		if !bound || leaf != snapshot.Leaves[i] {
			bound = false
			break
		}
	}
	checks := append([]verificationdomain.VerifyCheck(nil), chain.Checks...)
	coverage := b.FromSequence >= 1 && b.ToSequence >= b.FromSequence && b.ToSequence <= count
	if !coverage {
		checks = append(checks, verificationdomain.VerifyCheck{Name: "checkpoint_coverage", Result: "failed"})
	} else {
		checks = append(checks, verificationdomain.VerifyCheck{Name: "checkpoint_coverage", Result: "passed"})
		root := "failed"
		if bound && merkle.Checks[0].Result == "passed" && merkle.Checks[1].Result == "passed" {
			root = "passed"
		}
		checks = append(checks, verificationdomain.VerifyCheck{Name: "checkpoint_root", Result: root}, merkle.Checks[2])
	}
	required := append([]string(nil), chain.Profile.RequiredChecks...)
	required = append(required, "checkpoint_coverage")
	if coverage {
		required = append(required, "checkpoint_root", "checkpoint_signature")
	}
	return SubjectInspection{Checks: checks, Profile: verificationdomain.NormalizeVerificationProfile(verificationdomain.VerificationProfile{ID: verificationdomain.VerificationProfileAuditChainMerkleCheckpoint, Version: verificationdomain.VerificationProfileSchemaVersion, RequiredChecks: required, TrustMaterial: []string{"Evydence audit-chain hashes", "tenant signing keys"}, IdentityPolicy: "tenant-scoped verification authorization", TransparencyProof: "not_evaluated", PayloadScope: "tenant audit-chain range and signed Merkle root", Limitations: []string{"This signed checkpoint detects truncation or rewrites within its covered sequence range, but does not prove external publication or third-party log inclusion."}})}
}
