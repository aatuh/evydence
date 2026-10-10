package app

import (
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

// Existing compatibility inputs and DSSE readers remain until the Verification
// aggregate adapter is retired. No Package metadata construction lives here.
type CreateDSSETrustRootInput struct {
	Name                  string
	KeyID                 string
	Algorithm             string
	PublicKey             string
	AllowedPredicateTypes []string
	ExpectedBuilderIDs    []string
	RequiredClaims        []string
}

func validDSSETrustRoot(root domain.DSSETrustRoot) bool {
	return verificationapp.ValidDSSETrustRoot(domain.DSSETrustRootToContextModel(root))
}

func (l *Ledger) registeredReleaseBuildOutputDigestsLocked(tenantID string, build domain.BuildRun) []string {
	releaseDigests := l.releaseArtifactDigestsLocked(tenantID, build.ReleaseID)
	digests := []string{}
	for _, output := range build.Outputs {
		artifact, ok := l.artifacts[output.ArtifactID]
		if !ok || artifact.TenantID != tenantID || artifact.Digest != output.Digest {
			continue
		}
		if _, ok := releaseDigests[output.Digest]; ok {
			digests = append(digests, output.Digest)
		}
	}
	return sortedStrings(digests)
}
