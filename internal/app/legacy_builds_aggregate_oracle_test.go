package app

import (
	"github.com/aatuh/evydence/internal/domain"
)

func (l *Ledger) hasPassedDSSEAttestationReceiptLocked(tenantID, attestationID string) bool {
	for _, verification := range l.verifications {
		if verification.TenantID != tenantID || verification.SubjectType != "build_attestation" || verification.SubjectID != attestationID || verification.Result != string(domain.VerificationStatePassed) {
			continue
		}
		if verification.Profile.ID == domain.VerificationProfileDSSEAttestationSignature && verification.SchemaVersion == domain.VerificationResultSchemaVersion {
			return true
		}
	}
	return false
}

func (l *Ledger) releaseArtifactDigestsLocked(tenantID, releaseID string) map[string]struct{} {
	digests := map[string]struct{}{}
	for _, item := range l.evidence {
		if item.TenantID != tenantID || item.ReleaseID != releaseID {
			continue
		}
		for _, ref := range item.SubjectRefs {
			if ref.Type != "artifact" {
				continue
			}
			// SubjectRef.Digest remains an opaque compatibility field. Only a
			// tenant-owned registered artifact can contribute a trusted digest.
			if ref.ID != "" {
				if artifact, ok := l.artifacts[ref.ID]; ok && artifact.TenantID == tenantID && validDigest(artifact.Digest) {
					digests[artifact.Digest] = struct{}{}
				}
			}
		}
	}
	return digests
}
