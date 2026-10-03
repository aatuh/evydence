package domain

import verificationdomain "github.com/aatuh/evydence/internal/verification/domain"

func DSSETrustRootFromContextModel(value verificationdomain.DSSETrustRoot) DSSETrustRoot {
	result := DSSETrustRoot(value)
	result.AllowedPredicateTypes = append([]string(nil), value.AllowedPredicateTypes...)
	result.ExpectedBuilderIDs = append([]string(nil), value.ExpectedBuilderIDs...)
	result.RequiredClaims = append([]string(nil), value.RequiredClaims...)
	return result
}

func DSSETrustRootToContextModel(value DSSETrustRoot) verificationdomain.DSSETrustRoot {
	result := verificationdomain.DSSETrustRoot(value)
	result.AllowedPredicateTypes = append([]string(nil), value.AllowedPredicateTypes...)
	result.ExpectedBuilderIDs = append([]string(nil), value.ExpectedBuilderIDs...)
	result.RequiredClaims = append([]string(nil), value.RequiredClaims...)
	return result
}
