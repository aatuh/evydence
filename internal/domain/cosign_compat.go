package domain

import verificationdomain "github.com/aatuh/evydence/internal/verification/domain"

// CosignVerificationFromContextModel copies the owned receipt into the legacy
// JSON/persistence boundary; no mutable profile/check slice is shared.
func CosignVerificationFromContextModel(r verificationdomain.CosignVerification) CosignVerification {
	checks := make([]VerifyCheck, 0, len(r.Checks))
	for _, c := range r.Checks {
		checks = append(checks, VerifyCheck{Name: c.Name, Result: c.Result, Detail: c.Detail})
	}
	return CosignVerification{ID: r.ID, TenantID: r.TenantID, ArtifactID: r.ArtifactID, ContainerImageID: r.ContainerImageID, ArtifactSignatureID: r.ArtifactSignatureID, SubjectDigest: r.SubjectDigest, RekorUUID: r.RekorUUID, RekorLogIndex: r.RekorLogIndex, CertificateIdentity: r.CertificateIdentity, CertificateIssuer: r.CertificateIssuer, VerifierLibraryVersion: r.VerifierLibraryVersion, TrustRootVersion: r.TrustRootVersion, VerificationMode: r.VerificationMode, Result: r.Result, Checks: checks, Profile: verificationProfileFromContext(r.Profile), Limitations: append([]string(nil), r.Limitations...), SchemaVersion: r.SchemaVersion, CreatedAt: r.CreatedAt}
}
