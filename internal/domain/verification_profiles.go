package domain

import verificationdomain "github.com/aatuh/evydence/internal/verification/domain"

// VerificationProfileDefinition is retained as a compatibility alias while
// callers move to the verification context.
type VerificationProfileDefinition = verificationdomain.VerificationProfileDefinition

// VerificationProfileDefinitions delegates to the verification context and
// returns its defensive copy.
func VerificationProfileDefinitions() []VerificationProfileDefinition {
	return verificationdomain.VerificationProfileDefinitions()
}

// VerificationProfileDefinitionFor delegates to the verification context.
func VerificationProfileDefinitionFor(id string) (VerificationProfileDefinition, bool) {
	return verificationdomain.VerificationProfileDefinitionFor(id)
}
