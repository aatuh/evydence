package query

import "github.com/aatuh/evydence/internal/application"

func NewReleaseBundleVerificationAuthorizer() application.Authorizer {
	return verificationAuthorizer{family: bundleVerificationFamily}
}
