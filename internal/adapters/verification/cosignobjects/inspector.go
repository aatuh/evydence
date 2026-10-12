// Package cosignobjects binds finalized, bounded payload reads to an explicit
// offline verifier. No trust material is taken from the stored bundle metadata.
package cosignobjects

import (
	"context"
	"errors"
	"strings"

	"github.com/aatuh/evydence/internal/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type Inspector struct {
	Objects  app.BoundedObjectReader
	Verifier app.CosignPolicyVerifier
}

func (i Inspector) InspectCosignSnapshot(ctx context.Context, s verificationapp.CosignSnapshot, input verificationapp.VerifyCosignInput) (verificationapp.CosignInspection, error) {
	if ctx == nil {
		return verificationapp.CosignInspection{}, verificationapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return verificationapp.CosignInspection{}, err
	}
	result := verificationapp.CosignInspection{Profile: verificationapp.CosignFullProfile(input.Mode, s.Subject.SubjectDigest)}
	fail := func(name, detail, outcome string) (verificationapp.CosignInspection, error) {
		result.Checks = []verificationdomain.VerifyCheck{{Name: name, Result: "failed", Detail: detail}}
		result.Outcome = outcome
		return result, nil
	}
	if i.Verifier == nil {
		return fail("verification_configuration", "no Sigstore verifier and trust policy are configured", verificationapp.CosignOutcomeUnavailable)
	}
	if s.Algorithm != "cosign" {
		return fail("signature_algorithm", "artifact signature is not recorded as a Cosign bundle", verificationapp.CosignOutcomeVerificationFailed)
	}
	if s.ArtifactDigest != s.Subject.SubjectDigest || !verificationapp.ValidCosignSubjectDigest(s.ArtifactDigest) {
		return fail("subject_digest", "stored artifact and signature digest binding does not match", verificationapp.CosignOutcomeVerificationFailed)
	}
	_, key, keyErr := app.CanonicalObjectPayloadKeys(s.Subject.TenantID, s.PayloadHash)
	if i.Objects == nil || !s.PayloadFinalized || s.PayloadSize < 1 || s.PayloadSize > verificationapp.MaxCosignPayloadBytes || keyErr != nil || s.PayloadRef != "object://"+key {
		return fail("sigstore_bundle", "stored Sigstore bundle is unavailable, not finalized, or does not match its recorded digest", verificationapp.CosignOutcomeVerificationFailed)
	}
	object, err := i.Objects.GetBounded(ctx, key, s.PayloadSize)
	if err != nil || object.Key != key || object.TenantID != s.Subject.TenantID || object.Digest != s.PayloadHash || int64(len(object.Bytes)) != s.PayloadSize || !app.ObjectMediaTypesMatch(object.MediaType, s.PayloadMediaType) || app.VerifyObjectDigestBytes(s.PayloadHash, object.Bytes) != nil {
		if ctx.Err() != nil {
			return verificationapp.CosignInspection{}, ctx.Err()
		}
		return fail("sigstore_bundle", "stored Sigstore bundle is unavailable, not finalized, or does not match its recorded digest", verificationapp.CosignOutcomeVerificationFailed)
	}
	receipt, err := i.Verifier.VerifyCosign(ctx, app.CosignVerificationRequest{Bundle: object.Bytes, ArtifactDigest: s.ArtifactDigest, ExpectedIdentity: input.ExpectedIdentity, ExpectedIssuer: input.ExpectedIssuer, Mode: app.CosignVerificationMode(input.Mode), Offline: input.Offline})
	if ctx.Err() != nil {
		return verificationapp.CosignInspection{}, ctx.Err()
	}
	result.LibraryVersion, result.TrustRootVersion = strings.TrimSpace(receipt.LibraryVersion), strings.TrimSpace(receipt.TrustRootVersion)
	result.Limitations = append([]string(nil), receipt.Limitations...)
	if err != nil {
		outcome := verificationapp.CosignOutcomeVerificationFailed
		if errors.Is(err, app.ErrFullVerificationUnavailable) || errors.Is(err, verificationapp.ErrFullVerificationUnavailable) {
			outcome = verificationapp.CosignOutcomeUnavailable
		}
		// Even a misbehaving configured adapter cannot publish successful checks
		// alongside an error, or leak its raw provider error into a receipt.
		return fail("cryptographic_signature", "signature, trust, identity, certificate, digest, or transparency verification failed", outcome)
	}
	for _, c := range receipt.Checks {
		result.Checks = append(result.Checks, verificationdomain.VerifyCheck{Name: c.Name, Result: c.Result, Detail: c.Detail})
	}
	if len(result.Checks) == 0 {
		return fail("cryptographic_signature", "Sigstore verification produced no receipt", verificationapp.CosignOutcomeVerificationFailed)
	}
	result.CertificateIdentity, result.CertificateIssuer = strings.TrimSpace(receipt.CertificateIdentity), strings.TrimSpace(receipt.CertificateIssuer)
	return result, nil
}
