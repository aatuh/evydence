package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

const (
	MaxDSSEVerificationRecords = 4096
	MaxDSSEVerificationBytes   = 8 << 20
	MaxDSSEPayloadBytes        = 8 << 20
)

// The transaction reader owns the selected attestation, finalized payload
// metadata, immutable tenant root policies and registered release outputs.
// No parsed attestation claim grants trust or adds an expected subject digest.
type DSSEVerificationSnapshot struct {
	Subject                SubjectReference
	EvidenceID             string
	PayloadRef             string
	PayloadHash            string
	PayloadSize            int64
	PayloadMediaType       string
	PayloadFinalized       bool
	Roots                  []verificationdomain.DSSETrustRoot
	ExpectedSubjectDigests []string
}
type DSSEVerificationFacts struct {
	Checks          []verificationdomain.VerifyCheck
	AcceptedRootIDs []string
}
type DSSEVerificationReader interface {
	ResolveDSSEVerificationSubject(context.Context, string, string) (SubjectReference, error)
	ReadDSSEVerification(context.Context, SubjectReference) (DSSEVerificationSnapshot, error)
}
type DSSEVerificationTransaction interface {
	DSSEVerificationReader
	application.Authorizer
	verificationReceiptTransaction
}
type DSSEVerificationTransactions interface {
	ExecuteDSSEVerification(context.Context, func(context.Context, DSSEVerificationTransaction) error) error
}

// The adapter must use bounded object reads, verify finalized tenant/key/size/
// media/digest bindings and verify PAE under each root's own complete policy.
type DSSEVerifier interface {
	VerifyDSSE(context.Context, DSSEVerificationSnapshot) (DSSEVerificationFacts, error)
}
type DSSEVerificationConfig struct {
	Transactions DSSEVerificationTransactions
	Authorizer   application.Authorizer
	Verifier     DSSEVerifier
	Clock        application.Clock
	IDs          application.IDGenerator
}
type DSSEVerificationCommands struct{ config DSSEVerificationConfig }

func NewDSSEVerificationCommands(config DSSEVerificationConfig) (*DSSEVerificationCommands, error) {
	if config.Transactions == nil || config.Authorizer == nil || config.Verifier == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &DSSEVerificationCommands{config}, nil
}
func (s *DSSEVerificationCommands) VerifyDSSEAttestationSignature(ctx context.Context, actor identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
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
	err := s.config.Transactions.ExecuteDSSEVerification(ctx, func(ctx context.Context, tx DSSEVerificationTransaction) error {
		subject, err := tx.ResolveDSSEVerificationSubject(ctx, actor.TenantID, id)
		if err != nil {
			return err
		}
		if !validSubjectReference(subject, actor.TenantID, "build_attestation", id) {
			return ErrNotFound
		}
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeVerifyRead, Resources: subject.Resources, TenantWide: emptyResources(subject.Resources)}); err != nil {
			return err
		}
		snapshot, err := tx.ReadDSSEVerification(ctx, subject)
		if err != nil {
			return err
		}
		if snapshot.Subject != subject || !validDSSEVerificationSnapshot(snapshot) {
			return ErrConflict
		}
		facts, err := s.config.Verifier.VerifyDSSE(ctx, snapshot)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		result, err = persistVerificationReceipt(ctx, tx, actor, subject, DSSEInspection(facts, snapshot.PayloadHash), s.config.Clock.Now().UTC(), s.config.IDs)
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

func validDSSEVerificationSnapshot(s DSSEVerificationSnapshot) bool {
	if !s.PayloadFinalized || s.PayloadSize < 1 || s.PayloadSize > MaxDSSEPayloadBytes || !validRetentionText(s.EvidenceID, 1024) || !validRetentionText(s.PayloadRef, 4096) || !validRetentionText(s.PayloadHash, 1024) || !validRetentionText(s.PayloadMediaType, 4096) {
		return false
	}
	count := len(s.ExpectedSubjectDigests)
	if count > MaxDSSEVerificationRecords || len(s.Roots) > MaxDSSEVerificationRecords-count {
		return false
	}
	count += len(s.Roots)
	bytes := len(s.EvidenceID) + len(s.PayloadRef) + len(s.PayloadHash) + len(s.PayloadMediaType)
	for _, value := range s.ExpectedSubjectDigests {
		if !validRetentionText(value, 1024) {
			return false
		}
		bytes += len(value)
	}
	for _, root := range s.Roots {
		if root.TenantID != s.Subject.TenantID {
			return false
		}
		for _, value := range []string{root.ID, root.TenantID, root.Name, root.KeyID, root.Algorithm, root.PublicKey, root.Status, root.SchemaVersion} {
			if len(value) > 4096 {
				return false
			}
			bytes += len(value)
		}
		for _, list := range [][]string{root.AllowedPredicateTypes, root.ExpectedBuilderIDs, root.RequiredClaims} {
			if len(list) > MaxDSSEVerificationRecords-count {
				return false
			}
			count += len(list)
			for _, value := range list {
				if len(value) > 4096 {
					return false
				}
				bytes += len(value)
			}
		}
	}
	return bytes <= MaxDSSEVerificationBytes
}

var dsseRequiredChecks = []string{"dsse_pae_signature", "trusted_root", "payload_type", "predicate_type", "subject_digest", "builder_identity", "policy_required_claims"}

// DSSEInspection preserves one profile and conservative aggregation for both
// the durable command and the explicit local-memory compatibility inspector.
func DSSEInspection(facts DSSEVerificationFacts, payloadHash string) SubjectInspection {
	checks := append([]verificationdomain.VerifyCheck(nil), facts.Checks...)
	profile := verificationdomain.NormalizeVerificationProfile(verificationdomain.VerificationProfile{
		ID: verificationdomain.VerificationProfileDSSEAttestationSignature, Version: verificationdomain.VerificationProfileSchemaVersion,
		RequiredChecks: append([]string(nil), dsseRequiredChecks...), TrustMaterial: append([]string{"configured tenant Ed25519 DSSE trust root", "go-securesystemslib/dsse.v0.11.0", "in-toto/attestation.v1.2.0"}, facts.AcceptedRootIDs...),
		IdentityPolicy: "signature key, SLSA builder identity, and required claims must match one immutable configured tenant root policy", TransparencyProof: "not_evaluated", PayloadScope: "raw DSSE envelope and signed in-toto Statement v1", PayloadDigest: payloadHash,
		Limitations: []string{"This offline profile does not establish certificate-chain trust, revocation, transparency-log inclusion, provenance completeness, or CI-provider runtime integrity."},
	})
	inspection := SubjectInspection{Checks: checks, Profile: profile}
	allUnavailable := true
	for _, name := range dsseRequiredChecks {
		found := false
		for _, check := range checks {
			if check.Name == name {
				found = true
				if check.Result != "not_verified" {
					allUnavailable = false
				}
			}
		}
		if !found {
			allUnavailable = false
		}
	}
	if allUnavailable {
		inspection.StateOverride, _ = verificationdomain.ParseVerificationState(verificationdomain.VerificationStateNotVerified)
	}
	return inspection
}

func ValidDSSETrustRoot(root verificationdomain.DSSETrustRoot) bool {
	for _, builder := range root.ExpectedBuilderIDs {
		if strings.TrimSpace(builder) == "" {
			return false
		}
	}
	input := CreateDSSETrustRootInput{Name: root.Name, KeyID: root.KeyID, Algorithm: root.Algorithm, PublicKey: root.PublicKey, AllowedPredicateTypes: root.AllowedPredicateTypes, ExpectedBuilderIDs: root.ExpectedBuilderIDs, RequiredClaims: root.RequiredClaims}
	return validRetentionText(root.ID, 1024) && validRetentionText(root.TenantID, 1024) && root.Status == "active" && root.SchemaVersion == verificationdomain.DSSETrustRootSchemaVersion && !root.CreatedAt.IsZero() && boundedTrustPolicy(input) && validDSSETrustRootInput(input)
}
