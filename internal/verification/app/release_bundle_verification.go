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
	if validReferencedPayloadSignature(snapshot.Subject, snapshot.SignatureRefs, snapshot.Signatures, snapshot.Keys, []byte(snapshot.ManifestHash), now, verifier) {
		signatureResult = "passed"
	}
	return SubjectInspection{Checks: []verificationdomain.VerifyCheck{{Name: "manifest_hash", Result: manifestResult}, {Name: "bundle_signature", Result: signatureResult}}, Profile: verificationdomain.NormalizeVerificationProfile(verificationdomain.VerificationProfile{ID: verificationdomain.VerificationProfileReleaseBundleSignature, Version: verificationdomain.VerificationProfileSchemaVersion, RequiredChecks: []string{"manifest_hash", "bundle_signature"}, TrustMaterial: []string{"active or historically valid tenant signing keys"}, IdentityPolicy: "tenant-scoped verification authorization", TransparencyProof: "not_evaluated", PayloadScope: "release bundle manifest canonical JSON", PayloadDigest: snapshot.ManifestHash, Limitations: []string{"Bundle verification does not establish external publication, registry provenance, or legal sufficiency."}})}, nil
}

// validReferencedPayloadSignature preserves subject binding and historical
// key policy for each signed ledger object, independently of its payload format.
func validReferencedPayloadSignature(subject SubjectReference, signatureRefs []string, signatures []verificationdomain.Signature, publicKeys []verificationdomain.SigningKey, payload []byte, now time.Time, verifier PayloadSignatureVerifier) bool {
	refs := make(map[string]bool, len(signatureRefs))
	for _, ref := range signatureRefs {
		refs[ref] = true
	}
	keys := make(map[string]verificationdomain.SigningKey, len(publicKeys))
	for _, key := range publicKeys {
		if key.TenantID == subject.TenantID {
			keys[key.ID] = key
		}
	}
	for _, signature := range signatures {
		if !refs[signature.ID] || signature.TenantID != subject.TenantID || signature.SubjectType != subject.Type || signature.SubjectID != subject.ID {
			continue
		}
		key, ok := keys[signature.KeyID]
		if !ok || key.HistoricalValidityAt(signature.CreatedAt, now) != verificationdomain.SigningKeyHistoricalValidityValid {
			continue
		}
		if verifier.VerifyPayload(key.PublicKey, signature.Value, payload) {
			return true
		}
	}
	return false
}
