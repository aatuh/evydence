package app

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

const (
	MaxBundleVerificationSignatures = 4096
	MaxBundleVerificationBytes      = 8 << 20
)

// ReleaseBundleVerificationSnapshot contains the one authorized bundle and
// its referenced public signing material. It never contains private keys.
type ReleaseBundleVerificationSnapshot struct {
	Subject       SubjectReference
	Manifest      map[string]any
	ManifestHash  string
	SignatureRefs []string
	Signatures    []verificationdomain.Signature
	Keys          []verificationdomain.SigningKey
}
type PayloadSignatureVerifier interface {
	VerifyPayload(publicKey, signature string, payload []byte) bool
}
type ReleaseBundleVerificationReader interface {
	ResolveReleaseBundleVerificationSubject(context.Context, string, string) (SubjectReference, error)
	ReadReleaseBundleVerification(context.Context, SubjectReference) (ReleaseBundleVerificationSnapshot, error)
}
type ReleaseBundleVerificationTransaction interface {
	ReleaseBundleVerificationReader
	application.Authorizer
	application.AuditAppender
	application.OutboxEnqueuer
	InsertVerificationResult(context.Context, verificationdomain.VerificationResult) error
}
type ReleaseBundleVerificationTransactions interface {
	ExecuteReleaseBundleVerification(context.Context, func(context.Context, ReleaseBundleVerificationTransaction) error) error
}
type ReleaseBundleVerificationConfig struct {
	Transactions ReleaseBundleVerificationTransactions
	Authorizer   application.Authorizer
	Hasher       CanonicalHasher
	Verifier     PayloadSignatureVerifier
	Clock        application.Clock
	IDs          application.IDGenerator
}
type ReleaseBundleVerificationCommands struct {
	config ReleaseBundleVerificationConfig
}

func NewReleaseBundleVerificationCommands(config ReleaseBundleVerificationConfig) (*ReleaseBundleVerificationCommands, error) {
	if config.Transactions == nil || config.Authorizer == nil || config.Hasher == nil || config.Verifier == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &ReleaseBundleVerificationCommands{config}, nil
}

// VerifyReleaseBundle observes authorization, immutable bundle bytes, signing
// key lifecycle and receipt persistence in the same transaction. Readers must
// keep the selected resource and public-key rows stable until commit.
func (s *ReleaseBundleVerificationCommands) VerifyReleaseBundle(ctx context.Context, actor identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
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
	err := s.config.Transactions.ExecuteReleaseBundleVerification(ctx, func(ctx context.Context, tx ReleaseBundleVerificationTransaction) error {
		subject, err := tx.ResolveReleaseBundleVerificationSubject(ctx, actor.TenantID, id)
		if err != nil {
			return err
		}
		if !validSubjectReference(subject, actor.TenantID, "release_bundle", id) {
			return ErrNotFound
		}
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeVerifyRead, Resources: subject.Resources}); err != nil {
			return err
		}
		snapshot, err := tx.ReadReleaseBundleVerification(ctx, subject)
		if err != nil {
			return err
		}
		if snapshot.Subject != subject {
			return ErrConflict
		}
		now := s.config.Clock.Now().UTC()
		inspection, err := InspectReleaseBundle(snapshot, now, s.config.Hasher, s.config.Verifier)
		if err != nil {
			return err
		}
		result, err = persistVerificationReceipt(ctx, tx, actor, subject, inspection, now, s.config.IDs)
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

// InspectReleaseBundle is shared by durable and explicit local-memory
// inspection. The hash format and historical key policy remain authoritative
// in their existing ports/domain methods; cryptography stays in an adapter.
func InspectReleaseBundle(snapshot ReleaseBundleVerificationSnapshot, now time.Time, hasher CanonicalHasher, verifier PayloadSignatureVerifier) (SubjectInspection, error) {
	if hasher == nil || verifier == nil || snapshot.Manifest == nil || now.IsZero() || snapshot.Subject.Type != "release_bundle" || snapshot.Subject.TenantID == "" || snapshot.Subject.ID == "" {
		return SubjectInspection{}, ErrConflict
	}
	if len(snapshot.SignatureRefs) > MaxBundleVerificationSignatures || len(snapshot.Signatures) > MaxBundleVerificationSignatures || len(snapshot.Keys) > MaxBundleVerificationSignatures {
		return SubjectInspection{}, ErrConflict
	}
	hash, err := hasher.Hash(snapshot.Manifest)
	manifestResult := "passed"
	if err != nil || hash != snapshot.ManifestHash {
		manifestResult = "failed"
	}
	signatureResult := "failed"
	refs := make(map[string]bool, len(snapshot.SignatureRefs))
	for _, ref := range snapshot.SignatureRefs {
		refs[ref] = true
	}
	keys := make(map[string]verificationdomain.SigningKey, len(snapshot.Keys))
	for _, key := range snapshot.Keys {
		if key.TenantID == snapshot.Subject.TenantID {
			keys[key.ID] = key
		}
	}
	for _, signature := range snapshot.Signatures {
		if !refs[signature.ID] || signature.TenantID != snapshot.Subject.TenantID || signature.SubjectType != snapshot.Subject.Type || signature.SubjectID != snapshot.Subject.ID {
			continue
		}
		key, ok := keys[signature.KeyID]
		if !ok || key.HistoricalValidityAt(signature.CreatedAt, now) != verificationdomain.SigningKeyHistoricalValidityValid {
			continue
		}
		if verifier.VerifyPayload(key.PublicKey, signature.Value, []byte(snapshot.ManifestHash)) {
			signatureResult = "passed"
			break
		}
	}
	return SubjectInspection{Checks: []verificationdomain.VerifyCheck{{Name: "manifest_hash", Result: manifestResult}, {Name: "bundle_signature", Result: signatureResult}}, Profile: verificationdomain.NormalizeVerificationProfile(verificationdomain.VerificationProfile{ID: verificationdomain.VerificationProfileReleaseBundleSignature, Version: verificationdomain.VerificationProfileSchemaVersion, RequiredChecks: []string{"manifest_hash", "bundle_signature"}, TrustMaterial: []string{"active or historically valid tenant signing keys"}, IdentityPolicy: "tenant-scoped verification authorization", TransparencyProof: "not_evaluated", PayloadScope: "release bundle manifest canonical JSON", PayloadDigest: snapshot.ManifestHash, Limitations: []string{"Bundle verification does not establish external publication, registry provenance, or legal sufficiency."}})}, nil
}
