package query

import "github.com/aatuh/evydence/internal/application"

// Artifact verification retains tenant-grant authority for humans, not
// product/project/release association authority. Credentials need capability.
func NewCosignVerificationAuthorizer() application.Authorizer {
	return verificationAuthorizer{family: artifactVerificationFamily}
}
