package app

import (
	"context"
	"strings"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type CosignVerificationMode string

const (
	CosignVerificationModeKeyless CosignVerificationMode = "keyless"
	CosignVerificationModeKey     CosignVerificationMode = "key"

	CosignOutcomeVerificationFailed = "verification_failed"
	CosignOutcomeUnavailable        = "unavailable"
)

type VerifyCosignInput struct {
	ArtifactSignatureID string
	ExpectedIdentity    string
	ExpectedIssuer      string
	Mode                CosignVerificationMode
	Offline             bool
}

type CosignSubject struct {
	TenantID            string
	ArtifactID          string
	ContainerImageID    string
	ArtifactSignatureID string
	SubjectDigest       string
	Resources           application.ResourceReferences
}

type CosignInspection struct {
	Profile             verificationdomain.VerificationProfile
	Checks              []verificationdomain.VerifyCheck
	CertificateIdentity string
	CertificateIssuer   string
	LibraryVersion      string
	TrustRootVersion    string
	Limitations         []string
	Outcome             string
}

func (s *Service) VerifyCosign(ctx context.Context, actor identitydomain.Actor, input VerifyCosignInput) (verificationdomain.CosignVerification, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.CosignVerification{}, err
	}
	if err := validateActor(actor); err != nil {
		return verificationdomain.CosignVerification{}, err
	}
	if err := s.authorize(ctx, actor, ScopeVerifyRead, application.ResourceReferences{}, true, false); err != nil {
		return verificationdomain.CosignVerification{}, err
	}
	input.ArtifactSignatureID = strings.TrimSpace(input.ArtifactSignatureID)
	input.ExpectedIdentity = strings.TrimSpace(input.ExpectedIdentity)
	input.ExpectedIssuer = strings.TrimSpace(input.ExpectedIssuer)
	subject, err := s.cosignSubjects.ResolveCosignSubject(ctx, actor.TenantID, input.ArtifactSignatureID)
	if err != nil {
		return verificationdomain.CosignVerification{}, err
	}
	if !validCosignSubject(subject, actor.TenantID, input.ArtifactSignatureID) {
		return verificationdomain.CosignVerification{}, ErrNotFound
	}
	if err := s.authorize(ctx, actor, ScopeVerifyRead, subject.Resources, false, emptyResources(subject.Resources)); err != nil {
		return verificationdomain.CosignVerification{}, err
	}
	if !validCosignInput(input) {
		return verificationdomain.CosignVerification{}, ErrValidation
	}
	inspection, err := s.cosignInspector.InspectCosign(ctx, subject, input)
	if err != nil {
		return verificationdomain.CosignVerification{}, err
	}
	var record verificationdomain.CosignVerification
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Authorization().Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeVerifyRead, Resources: subject.Resources, TenantWide: emptyResources(subject.Resources)}); err != nil {
			return err
		}
		record, err = persistCosignReceipt(ctx, cosignServiceReceiptWriter{tx}, actor, subject, inspection, input.Mode, s.clock.Now().UTC(), s.ids)
		return err
	})
	if err != nil {
		return verificationdomain.CosignVerification{}, err
	}
	return cloneCosignVerification(record), cosignOutcomeError(inspection.Outcome, record.Result)
}

type cosignServiceReceiptWriter struct{ Transaction }

func (w cosignServiceReceiptWriter) InsertCosignVerification(ctx context.Context, r verificationdomain.CosignVerification) error {
	return w.Verification().InsertCosignVerification(ctx, r)
}
func (w cosignServiceReceiptWriter) InsertVerificationResult(ctx context.Context, r verificationdomain.VerificationResult) error {
	return w.Verification().InsertVerificationResult(ctx, r)
}
func (w cosignServiceReceiptWriter) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return w.Audit().AppendAudit(ctx, e)
}

func validCosignInput(input VerifyCosignInput) bool {
	if input.ArtifactSignatureID == "" || !input.Offline {
		return false
	}
	switch input.Mode {
	case CosignVerificationModeKeyless:
		return input.ExpectedIdentity != "" && input.ExpectedIssuer != ""
	case CosignVerificationModeKey:
		return input.ExpectedIdentity == "" && input.ExpectedIssuer == ""
	default:
		return false
	}
}

func validCosignSubject(subject CosignSubject, tenantID, signatureID string) bool {
	return subject.TenantID == tenantID && subject.ArtifactID != "" && subject.ArtifactSignatureID == signatureID && subject.SubjectDigest != ""
}

func validCosignInspection(inspection CosignInspection) bool {
	if !validInspection(SubjectInspection{Profile: inspection.Profile, Checks: inspection.Checks}) {
		return false
	}
	switch inspection.Outcome {
	case "", CosignOutcomeVerificationFailed, CosignOutcomeUnavailable:
		return true
	default:
		return false
	}
}

func cloneCosignInspection(value CosignInspection) CosignInspection {
	value.Profile = cloneVerificationProfile(value.Profile)
	value.Checks = append([]verificationdomain.VerifyCheck(nil), value.Checks...)
	value.Limitations = append([]string(nil), value.Limitations...)
	return value
}

func cloneCosignVerification(value verificationdomain.CosignVerification) verificationdomain.CosignVerification {
	value.Checks = append([]verificationdomain.VerifyCheck(nil), value.Checks...)
	value.Profile = cloneVerificationProfile(value.Profile)
	value.Limitations = append([]string(nil), value.Limitations...)
	return value
}
