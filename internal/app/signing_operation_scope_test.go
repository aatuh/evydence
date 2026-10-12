package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type signingOperationHookExecutor struct{ hook func() }

func (f signingOperationHookExecutor) Sign(ctx context.Context, r SigningRequest) (SigningResult, error) {
	if f.hook != nil {
		f.hook()
	}
	v, err := (&fakeSigningExecutor{}).Sign(ctx, r)
	v.KeyID = "password=key-canary"
	v.ProviderRequestID = "token=receipt-canary"
	v.Checks = []domain.VerifyCheck{{Name: "executor", Result: "passed", Detail: "secret=detail-canary"}}
	return v, err
}
func TestSigningOperationLocalRedactsProviderDiagnosticMetadata(t *testing.T) {
	l := newLegacyLedgerFixture(Config{APIKeyPepper: "test", Now: fixedNow, Signer: signingOperationHookExecutor{}})
	a, release, _ := setupReleaseRiskFixture(t, l)
	p, err := l.CreateSigningProvider(t.Context(), a, CreateSigningProviderInput{Name: "KMS", Type: "aws_kms", KeyRef: "key", Encrypted: true})
	if err != nil {
		t.Fatal(err)
	}
	v, err := l.CreateSigningOperation(t.Context(), a, CreateSigningOperationInput{ProviderID: p.ID, SubjectType: "release", SubjectID: release.ID, PayloadHash: sampleDigest("payload")})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(v.ProviderRequestID, "receipt-canary") || strings.Contains(v.Checks[2].Detail, "detail-canary") || strings.Contains(v.Checks[len(v.Checks)-1].Detail, "key-canary") {
		t.Fatal("provider diagnostics reached stored operation")
	}
}
func TestSigningOperationLocalRechecksProviderAfterSigner(t *testing.T) {
	l := newLegacyLedgerFixture(Config{APIKeyPepper: "test", Now: fixedNow})
	a, release, _ := setupReleaseRiskFixture(t, l)
	p, err := l.CreateSigningProvider(t.Context(), a, CreateSigningProviderInput{Name: "KMS", Type: "aws_kms", KeyRef: "key", Encrypted: true})
	if err != nil {
		t.Fatal(err)
	}
	l.signer = signingOperationHookExecutor{hook: func() { l.mu.Lock(); defer l.mu.Unlock(); p.Status = "revoked"; l.signingProviders[p.ID] = p }}
	v, err := l.CreateSigningOperation(t.Context(), a, CreateSigningOperationInput{ProviderID: p.ID, SubjectType: "release", SubjectID: release.ID, PayloadHash: sampleDigest("payload")})
	if !errors.Is(err, ErrVerificationFailed) || v.ID != "" || len(l.signingOperations) != 0 || len(l.signatures) != 0 {
		t.Fatal("revoked provider published a receipt", err)
	}
}

func TestSigningOperationLocalRequiresTenantAdminGrantBeforeSigner(t *testing.T) {
	f := &fakeSigningExecutor{}
	l := newLegacyLedgerFixture(Config{APIKeyPepper: "test", Now: fixedNow, Signer: f})
	a, release, _ := setupReleaseRiskFixture(t, l)
	p, err := l.CreateSigningProvider(t.Context(), a, CreateSigningProviderInput{Name: "KMS", Type: "aws_kms", KeyRef: "key", Encrypted: true})
	if err != nil {
		t.Fatal(err)
	}
	a.KeyID, a.UserID, a.ResourceGrants = "", "user", nil
	if v, err := l.CreateSigningOperation(t.Context(), a, CreateSigningOperationInput{ProviderID: p.ID, SubjectType: "release", SubjectID: release.ID, PayloadHash: sampleDigest("payload")}); !errors.Is(err, ErrForbidden) || v.ID != "" || f.request.Profile != "" {
		t.Fatal("unscoped human invoked signing executor", v.ID, err)
	}
}

func TestSigningOperationLocalBoundsRawIDsBeforeSigner(t *testing.T) {
	f := &fakeSigningExecutor{}
	l := newLegacyLedgerFixture(Config{APIKeyPepper: "test", Now: fixedNow, Signer: f})
	a, release, _ := setupReleaseRiskFixture(t, l)
	p, err := l.CreateSigningProvider(t.Context(), a, CreateSigningProviderInput{Name: "KMS", Type: "aws_kms", KeyRef: "key", Encrypted: true})
	if err != nil {
		t.Fatal(err)
	}
	if v, err := l.CreateSigningOperation(t.Context(), a, CreateSigningOperationInput{ProviderID: strings.Repeat(" ", 1025) + p.ID, SubjectType: "release", SubjectID: release.ID, PayloadHash: sampleDigest("payload")}); !errors.Is(err, ErrValidation) || v.ID != "" || f.request.Profile != "" {
		t.Fatal("raw oversized provider ID reached signer", v.ID, err)
	}
}

func TestSigningOperationLocalReturnedChecksAreImmutable(t *testing.T) {
	l := newLegacyLedgerFixture(Config{APIKeyPepper: "test", Now: fixedNow, Signer: &fakeSigningExecutor{}})
	a, release, _ := setupReleaseRiskFixture(t, l)
	p, err := l.CreateSigningProvider(t.Context(), a, CreateSigningProviderInput{Name: "KMS", Type: "aws_kms", KeyRef: "key", Encrypted: true})
	if err != nil {
		t.Fatal(err)
	}
	v, err := l.CreateSigningOperation(t.Context(), a, CreateSigningOperationInput{ProviderID: p.ID, SubjectType: "release", SubjectID: release.ID, PayloadHash: sampleDigest("payload")})
	if err != nil {
		t.Fatal(err)
	}
	v.Checks[0].Result = "changed"
	if l.signingOperations[v.ID].Checks[0].Result == "changed" {
		t.Fatal("returned checks changed immutable stored receipt")
	}
}
