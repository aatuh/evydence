package app

import "github.com/aatuh/evydence/internal/domain"

// Historical release policy checks are no longer production map readers.
const (
	buildStatusPassed = "passed"
)

func (l *Ledger) checkReleaseHasPassedBuildLocked(tenantID, releaseID string) domain.PolicyCheck {
	releaseDigests := l.releaseArtifactDigestsLocked(tenantID, releaseID)
	for _, build := range l.buildRuns {
		if build.TenantID != tenantID || build.ReleaseID != releaseID || build.Status != buildStatusPassed {
			continue
		}
		for _, output := range build.Outputs {
			if _, ok := releaseDigests[output.Digest]; ok {
				return domain.PolicyCheck{Name: "release_requires_passed_build", Result: "passed", Severity: "high", Explanation: "passed build is linked to a release artifact digest"}
			}
		}
	}
	return domain.PolicyCheck{Name: "release_requires_passed_build", Result: "failed", Severity: "high", Missing: []string{"passed_build"}, Explanation: "no passed build with output digest linked to the release was found", Remediation: "Upload a passed build run whose output digest matches a release artifact digest."}
}

func (l *Ledger) checkReleaseHasBuildAttestationLocked(tenantID, releaseID string) domain.PolicyCheck {
	releaseDigests := l.releaseArtifactDigestsLocked(tenantID, releaseID)
	for _, attestation := range l.attestations {
		if attestation.TenantID != tenantID {
			continue
		}
		build, ok := l.buildRuns[attestation.BuildID]
		if !ok || build.TenantID != tenantID || build.ReleaseID != releaseID {
			continue
		}
		if !l.hasPassedDSSEAttestationReceiptLocked(tenantID, attestation.ID) {
			continue
		}
		for _, digest := range attestation.SubjectDigests {
			if _, ok := releaseDigests[digest]; ok {
				return domain.PolicyCheck{Name: "release_requires_build_attestation", Result: "passed", Severity: "high", Explanation: "verified build attestation receipt and subject match a release artifact digest"}
			}
		}
	}
	return domain.PolicyCheck{Name: "release_requires_build_attestation", Result: "failed", Severity: "high", Missing: []string{"build_attestation"}, Explanation: "no attestation has a passed DSSE/in-toto receipt and a subject matching a release artifact digest", Remediation: "Upload a supported DSSE/in-toto attestation, verify it with a configured root policy, and ensure its subject digest matches a release artifact digest."}
}
