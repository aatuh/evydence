package azurekeyvault

import "github.com/Azure/azure-sdk-for-go/sdk/azcore/log"

// The pinned SDK installs an environment-enabled raw stderr listener during
// initialization. Evydence owns this process policy: application diagnostics
// use its structured logger, never raw SDK request/response/authentication text.
// SetListener is unsynchronized in this SDK version, so apply the policy once
// during package initialization, before application/provider goroutines start.
func init() {
	log.SetListener(nil)
}
