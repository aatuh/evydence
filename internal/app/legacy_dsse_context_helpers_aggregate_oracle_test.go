package app

import (
	"github.com/aatuh/evydence/internal/domain"
)

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
