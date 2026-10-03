package app

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type ReleaseManifestCheckpointTransaction interface {
	AuditChainVerificationTransaction
	ReleaseBundleVerificationReader
}
type ReleaseManifestCheckpointTransactions interface {
	ExecuteReleaseManifestCheckpointVerification(context.Context, func(context.Context, ReleaseManifestCheckpointTransaction) error) error
}
type ReleaseManifestCheckpointConfig struct {
	Transactions ReleaseManifestCheckpointTransactions
	Authorizer   application.Authorizer
	Hasher       CanonicalHasher
	Verifier     PayloadSignatureVerifier
	Clock        application.Clock
	IDs          application.IDGenerator
}
type ReleaseManifestCheckpointCommands struct {
	config ReleaseManifestCheckpointConfig
}

func NewReleaseManifestCheckpointCommands(c ReleaseManifestCheckpointConfig) (*ReleaseManifestCheckpointCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Hasher == nil || c.Verifier == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &ReleaseManifestCheckpointCommands{c}, nil
}
func (s *ReleaseManifestCheckpointCommands) VerifyReleaseManifestCheckpoint(ctx context.Context, actor identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
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
	err := s.config.Transactions.ExecuteReleaseManifestCheckpointVerification(ctx, func(ctx context.Context, tx ReleaseManifestCheckpointTransaction) error {
		// The assessment includes every tenant audit entry, not just a release.
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeVerifyRead, TenantWide: true}); err != nil {
			return err
		}
		view, err := tx.LockAuditChainVerification(ctx, actor.TenantID)
		if err != nil {
			return err
		}
		if view.TenantID != actor.TenantID {
			return ErrNotFound
		}
		subject, err := tx.ResolveReleaseBundleVerificationSubject(ctx, actor.TenantID, id)
		if err != nil {
			return err
		}
		if !validSubjectReference(subject, actor.TenantID, "release_bundle", id) {
			return ErrNotFound
		}
		snapshot, err := tx.ReadReleaseBundleVerification(ctx, subject)
		if err != nil {
			return err
		}
		if snapshot.Subject != subject || !releaseManifestCheckpointWithinBudget(snapshot) {
			return ErrConflict
		}
		now := s.config.Clock.Now().UTC()
		bundle, err := InspectReleaseBundle(snapshot, now, s.config.Hasher, s.config.Verifier)
		if err != nil {
			return err
		}
		sequence, head, parsed := ReleaseManifestAuditChainCheckpoint(snapshot.Manifest)
		covered := parsed && sequence == 0
		chain, err := inspectAuditChainView(ctx, tx, view, actor.TenantID, now, s.config.Hasher, s.config.Verifier, func(e verificationdomain.AuditChainEntry) {
			if parsed && sequence > 0 && e.Sequence == sequence && e.EntryHash == head {
				covered = true
			}
		})
		if err != nil {
			return err
		}
		coverage := "failed"
		if covered && sequence >= 0 && sequence <= view.EntryCount {
			coverage = "passed"
		}
		checks := append([]verificationdomain.VerifyCheck(nil), chain.Checks...)
		checks = append(checks, verificationdomain.VerifyCheck{Name: "checkpoint_manifest_hash", Result: bundle.Checks[0].Result}, verificationdomain.VerifyCheck{Name: "checkpoint_signature", Result: bundle.Checks[1].Result}, verificationdomain.VerifyCheck{Name: "checkpoint_coverage", Result: coverage})
		required := append(append([]string(nil), chain.Profile.RequiredChecks...), "checkpoint_manifest_hash", "checkpoint_signature", "checkpoint_coverage")
		inspection := SubjectInspection{Checks: checks, Profile: verificationdomain.NormalizeVerificationProfile(verificationdomain.VerificationProfile{ID: verificationdomain.VerificationProfileAuditChainReleaseManifest, Version: verificationdomain.VerificationProfileSchemaVersion, RequiredChecks: required, TrustMaterial: []string{"release bundle manifest", "tenant signing keys"}, IdentityPolicy: "tenant-scoped verification authorization", TransparencyProof: "not_evaluated", PayloadScope: "signed release manifest audit-chain checkpoint", PayloadDigest: snapshot.ManifestHash, Limitations: []string{"This signed checkpoint detects truncation or rewrites within its covered sequence range, but does not prove external publication or third-party log inclusion."}})}
		result, err = persistVerificationReceipt(ctx, tx, actor, SubjectReference{TenantID: actor.TenantID, Type: "audit_chain_release_manifest", ID: id}, inspection, now, s.config.IDs)
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

// ReleaseManifestAuditChainCheckpoint preserves the historical map and integer
// representations. Coverage and canonical integrity are evaluated separately.
func ReleaseManifestAuditChainCheckpoint(manifest map[string]any) (int64, string, bool) {
	raw, ok := manifest["chain_checkpoint"].(map[string]any)
	if !ok {
		return 0, "", false
	}
	var sequence int64
	switch value := raw["sequence"].(type) {
	case int:
		sequence = int64(value)
	case int64:
		sequence = value
	case float64:
		if math.IsNaN(value) || math.IsInf(value, 0) || value >= float64(1<<63) || value < -float64(1<<63) || value != math.Trunc(value) {
			return 0, "", false
		}
		sequence = int64(value)
	default:
		return 0, "", false
	}
	head, ok := raw["head_hash"].(string)
	return sequence, head, ok
}

func releaseManifestCheckpointWithinBudget(s ReleaseBundleVerificationSnapshot) bool {
	if len(s.SignatureRefs) > MaxBundleVerificationSignatures || len(s.Signatures) > MaxBundleVerificationSignatures || len(s.Keys) > MaxBundleVerificationSignatures {
		return false
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > MaxBundleVerificationBytes {
		return false
	}
	consume := func(text string, limit int) bool {
		return len(text) <= limit && utf8.ValidString(text) && !strings.ContainsRune(text, 0)
	}
	for _, text := range []string{s.Subject.TenantID, s.Subject.ID, s.ManifestHash} {
		if !consume(text, 1024) {
			return false
		}
	}
	for _, ref := range s.SignatureRefs {
		if !consume(ref, 1024) {
			return false
		}
	}
	return publicVerificationMaterialWithinBudget(s.Signatures, s.Keys, consume)
}
