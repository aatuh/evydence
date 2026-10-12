package app

import (
	"context"

	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// DSSEPolicyVerification contains caller-bounded bytes and tenant-owned public
// root policies. Object binding and read authorization belong to the caller;
// the offline adapter owns cryptographic parsing and each complete root policy.
type DSSEPolicyVerification struct {
	TenantID               string
	Envelope               []byte
	Roots                  []verificationdomain.DSSETrustRoot
	ExpectedSubjectDigests []string
}

type DSSEPolicyVerifier interface {
	VerifyDSSEPolicies(context.Context, DSSEPolicyVerification) (DSSEVerificationFacts, error)
}
