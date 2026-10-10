package app

import (
	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
)

func validCollectorScopes(scopes []string) bool {
	_, err := integrationapp.NormalizeCollectorScopes(scopes)
	return err == nil
}

func validCollectorType(typ string) bool {
	return integrationapp.ValidCollectorType(typ)
}

func actorType(actor domain.Actor) string {
	if actor.CollectorID != "" {
		return "collector"
	}
	if actor.UserID != "" {
		return "human_user"
	}
	return "api_key"
}

func actorID(actor domain.Actor) string {
	if actor.CollectorID != "" {
		return actor.CollectorID
	}
	if actor.UserID != "" {
		return actor.UserID
	}
	return actor.KeyID
}

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
