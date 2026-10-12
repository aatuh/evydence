package dsse

import (
	"context"
	"strings"

	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// PolicyVerifier adapts the offline cryptographic implementation to the inward
// policy port. It never combines key, builder or claim allowances across roots.
type PolicyVerifier struct{}

var _ verificationapp.DSSEPolicyVerifier = PolicyVerifier{}

func (PolicyVerifier) VerifyDSSEPolicies(ctx context.Context, input verificationapp.DSSEPolicyVerification) (verificationapp.DSSEVerificationFacts, error) {
	if ctx == nil {
		return verificationapp.DSSEVerificationFacts{}, verificationapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return verificationapp.DSSEVerificationFacts{}, err
	}
	if strings.TrimSpace(input.TenantID) == "" {
		return verificationapp.DSSEVerificationFacts{}, verificationapp.ErrValidation
	}
	policies := make([]Policy, 0, len(input.Roots))
	for _, root := range input.Roots {
		if root.TenantID != input.TenantID {
			return verificationapp.DSSEVerificationFacts{}, verificationapp.ErrConflict
		}
		if !verificationapp.ValidDSSETrustRoot(root) {
			continue
		}
		policies = append(policies, Policy{Roots: []TrustRoot{{ID: root.ID, KeyID: root.KeyID, Algorithm: root.Algorithm, PublicKey: root.PublicKey}}, AllowedPredicateTypes: root.AllowedPredicateTypes, ExpectedBuilderIDs: root.ExpectedBuilderIDs, RequiredClaims: root.RequiredClaims, ExpectedSubjectDigests: input.ExpectedSubjectDigests})
	}
	result, err := VerifyConfiguredPolicies(ctx, input.Envelope, policies)
	if err != nil {
		if ctx.Err() != nil {
			return verificationapp.DSSEVerificationFacts{}, ctx.Err()
		}
		return verificationapp.DSSEVerificationFacts{}, verificationapp.ErrValidation
	}
	facts := verificationapp.DSSEVerificationFacts{AcceptedRootIDs: append([]string(nil), result.AcceptedRootIDs...)}
	for _, check := range result.Checks {
		facts.Checks = append(facts.Checks, verificationdomain.VerifyCheck{Name: check.Name, Result: check.Result, Detail: check.Detail})
	}
	return facts, nil
}
