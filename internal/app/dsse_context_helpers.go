package app

import (
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

// Existing compatibility DSSE readers remain until the Verification
// aggregate adapter is retired. No Package metadata construction lives here.
func validDSSETrustRoot(root domain.DSSETrustRoot) bool {
	return verificationapp.ValidDSSETrustRoot(domain.DSSETrustRootToContextModel(root))
}
