package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type cosignCommandFake struct {
	bundleVerificationFake
	selected    CosignSnapshot
	inspection  CosignInspection
	cosign      []verificationdomain.CosignVerification
	inspections int
}

func (f *cosignCommandFake) ExecuteCosignVerification(ctx context.Context, fn func(context.Context, CosignVerificationTransaction) error) error {
	copy := *f
	copy.results, copy.audits, copy.cosign = nil, nil, nil
	err := fn(ctx, &copy)
	f.payloadReads = copy.payloadReads
	if err != nil {
		return err
	}
	if f.fail == "commit" {
		return errVerificationTestFailure
	}
	f.results, f.audits, f.cosign = copy.results, copy.audits, copy.cosign
	return nil
}
func (f *cosignCommandFake) ResolveCosignSubject(context.Context, string, string) (CosignSubject, error) {
	return f.selected.Subject, nil
}
func (f *cosignCommandFake) ReadCosignSnapshot(context.Context, CosignSubject) (CosignSnapshot, error) {
	f.payloadReads++
	if f.fail == "read" {
		return CosignSnapshot{}, errVerificationTestFailure
	}
	return f.selected, nil
}
func (f *cosignCommandFake) InspectCosignSnapshot(context.Context, CosignSnapshot, VerifyCosignInput) (CosignInspection, error) {
	f.inspections++
	if f.fail == "inspect" {
		return CosignInspection{}, errVerificationTestFailure
	}
	return f.inspection, nil
}
func (f *cosignCommandFake) InsertCosignVerification(_ context.Context, r verificationdomain.CosignVerification) error {
	if f.fail == "cosign" {
		return errVerificationTestFailure
	}
	f.cosign = append(f.cosign, r)
	return nil
}
func cosignCommandFixture(t *testing.T) (*CosignVerificationCommands, *cosignCommandFake, VerifyCosignInput) {
	t.Helper()
	bundle, base := bundleVerificationFixture(t)
	subject := CosignSubject{TenantID: "tenant", ArtifactID: "artifact", ArtifactSignatureID: "sig", SubjectDigest: "sha256:" + strings.Repeat("a", 64), Resources: application.ResourceReferences{ArtifactID: "artifact"}}
	f := &cosignCommandFake{bundleVerificationFake: *base, selected: CosignSnapshot{Subject: subject, ArtifactDigest: subject.SubjectDigest, Algorithm: "cosign", PayloadHash: "sha256:" + strings.Repeat("b", 64), PayloadRef: "object://key", PayloadSize: 1, PayloadFinalized: true, PayloadMediaType: "application/json"}}
	f.inspection.Profile = CosignFullProfile(CosignVerificationModeKey, subject.SubjectDigest)
	for _, n := range f.inspection.Profile.RequiredChecks {
		f.inspection.Checks = append(f.inspection.Checks, verificationdomain.VerifyCheck{Name: n, Result: "passed"})
	}
	f.inspection.LibraryVersion, f.inspection.TrustRootVersion = "library", "root"
	c, err := NewCosignVerificationCommands(CosignVerificationConfig{Transactions: f, Authorizer: f, Inspector: f, Clock: bundle.config.Clock, IDs: bundle.config.IDs})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, VerifyCosignInput{ArtifactSignatureID: "sig", Mode: CosignVerificationModeKey, Offline: true}
}
func TestCosignCommandsCommitBothReceiptsAndAuditAtomically(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}
	c, f, input := cosignCommandFixture(t)
	got, err := c.VerifyCosign(t.Context(), actor, input)
	if err != nil || got.Result != "passed" || got.VerifierLibraryVersion != "library" || len(f.cosign) != 1 || len(f.results) != 1 || len(f.audits) != 1 || len(f.jobs) != 0 || f.results[0].ID != got.ID || f.audits[0].SubjectID != "sig" || f.audits[0].EntryType != "cosign_signature.verified" {
		t.Fatal(got, err, f)
	}
	for _, fail := range []string{"read", "inspect", "cosign", "result", "audit", "commit"} {
		c, f, input = cosignCommandFixture(t)
		f.fail = fail
		got, err = c.VerifyCosign(t.Context(), actor, input)
		if !errors.Is(err, errVerificationTestFailure) || got.ID != "" || len(f.cosign)+len(f.results)+len(f.audits) != 0 {
			t.Fatal("partial receipt", fail, got, err)
		}
	}
	c, f, input = cosignCommandFixture(t)
	f.fail = "auth"
	if _, err := c.VerifyCosign(t.Context(), actor, input); !errors.Is(err, application.ErrForbidden) || f.payloadReads+f.inspections != 0 {
		t.Fatal("unauthorized inspection", err)
	}
	c, f, input = cosignCommandFixture(t)
	f.selected.Subject.TenantID = "foreign"
	if _, err := c.VerifyCosign(t.Context(), actor, input); !errors.Is(err, ErrNotFound) || f.payloadReads+f.inspections != 0 {
		t.Fatal("foreign inspection", err)
	}
}
func TestCosignCommandsRejectInvalidInputBeforeReadingPayload(t *testing.T) {
	for _, mutate := range []func(*VerifyCosignInput){
		func(i *VerifyCosignInput) { i.ArtifactSignatureID = "" }, func(i *VerifyCosignInput) { i.ArtifactSignatureID = "x\x00" }, func(i *VerifyCosignInput) { i.ArtifactSignatureID = strings.Repeat("x", 1025) },
		func(i *VerifyCosignInput) { i.Offline = false }, func(i *VerifyCosignInput) { i.Mode = "unknown" }, func(i *VerifyCosignInput) { i.ExpectedIssuer = "issuer" }, func(i *VerifyCosignInput) { i.Mode = CosignVerificationModeKeyless }, func(i *VerifyCosignInput) {
			i.Mode = CosignVerificationModeKeyless
			i.ExpectedIdentity = strings.Repeat("x", 4097)
			i.ExpectedIssuer = "issuer"
		},
	} {
		c, f, input := cosignCommandFixture(t)
		mutate(&input)
		if _, err := c.VerifyCosign(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, input); !errors.Is(err, ErrValidation) || f.payloadReads+f.inspections != 0 {
			t.Fatal(err)
		}
	}
}
func TestCosignCommandsPersistFailureAndUnavailableWithoutPassing(t *testing.T) {
	for _, outcome := range []string{CosignOutcomeVerificationFailed, CosignOutcomeUnavailable} {
		c, f, input := cosignCommandFixture(t)
		f.inspection.Outcome = outcome
		f.inspection.Checks = []verificationdomain.VerifyCheck{{Name: "cryptographic_signature", Result: "failed"}}
		got, err := c.VerifyCosign(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, input)
		expected := ErrVerificationFailed
		if outcome == CosignOutcomeUnavailable {
			expected = ErrFullVerificationUnavailable
		}
		if !errors.Is(err, expected) || got.Result == "passed" || len(f.cosign) != 1 || len(f.results) != 1 || len(f.audits) != 1 {
			t.Fatal(got, err)
		}
	}
}

func TestCosignCommandsCannotDowngradeFullProfileOrPersistContradictoryPass(t *testing.T) {
	c, f, input := cosignCommandFixture(t)
	f.inspection.Profile.RequiredChecks = []string{"metadata_present"}
	f.inspection.Checks = []verificationdomain.VerifyCheck{{Name: "metadata_present", Result: "passed"}}
	got, err := c.VerifyCosign(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, input)
	if !errors.Is(err, ErrVerificationFailed) || got.Result == "passed" || got.Profile.ID != verificationdomain.VerificationProfileCosignFull {
		t.Fatal("adapter downgraded verification policy", got, err)
	}
	c, f, input = cosignCommandFixture(t)
	f.inspection.Outcome = CosignOutcomeUnavailable
	got, err = c.VerifyCosign(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, input)
	if !errors.Is(err, ErrValidation) || got.ID != "" || len(f.cosign)+len(f.results)+len(f.audits) != 0 {
		t.Fatal("unavailable inspector persisted passed receipt", got, err)
	}
}
