package cosignobjects

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

type readerFake struct {
	object app.Object
	calls  int
	limit  int64
	err    error
}

func (f *readerFake) GetBounded(_ context.Context, _ string, n int64) (app.Object, error) {
	f.calls++
	f.limit = n
	return f.object, f.err
}

type providerFake struct {
	calls   int
	request app.CosignVerificationRequest
	err     error
}

func (f *providerFake) VerifyCosign(_ context.Context, r app.CosignVerificationRequest) (app.CosignVerificationReceipt, error) {
	f.calls++
	f.request = r
	return app.CosignVerificationReceipt{LibraryVersion: "library", TrustRootVersion: "root", Checks: []domain.VerifyCheck{{Name: "cryptographic_signature", Result: "passed"}}}, f.err
}
func fixture(t *testing.T) (Inspector, *readerFake, *providerFake, verificationapp.CosignSnapshot, verificationapp.VerifyCosignInput) {
	t.Helper()
	raw := []byte(`{"bundle":"signed"}`)
	sum := sha256.Sum256(raw)
	hash := "sha256:" + hex.EncodeToString(sum[:])
	_, key, err := app.CanonicalObjectPayloadKeys("tenant", hash)
	if err != nil {
		t.Fatal(err)
	}
	reader := &readerFake{object: app.Object{Key: key, TenantID: "tenant", Digest: hash, MediaType: "application/json", Bytes: raw}}
	provider := &providerFake{}
	snapshot := verificationapp.CosignSnapshot{Subject: verificationapp.CosignSubject{TenantID: "tenant", SubjectDigest: "sha256:" + strings.Repeat("a", 64)}, ArtifactDigest: "sha256:" + strings.Repeat("a", 64), Algorithm: "cosign", PayloadHash: hash, PayloadRef: "object://" + key, PayloadMediaType: "application/json", PayloadSize: int64(len(raw)), PayloadFinalized: true}
	return Inspector{Objects: reader, Verifier: provider}, reader, provider, snapshot, verificationapp.VerifyCosignInput{Mode: verificationapp.CosignVerificationModeKey, Offline: true}
}
func TestCosignInspectorUsesOnlyBoundedIntegrityCheckedBytes(t *testing.T) {
	inspector, reader, provider, snapshot, input := fixture(t)
	facts, err := inspector.InspectCosignSnapshot(t.Context(), snapshot, input)
	if err != nil || facts.Outcome != "" || reader.limit != snapshot.PayloadSize || provider.calls != 1 || string(provider.request.Bundle) != string(reader.object.Bytes) || provider.request.ArtifactDigest != snapshot.ArtifactDigest || facts.Profile.ID != "cosign-full-verification.v1" {
		t.Fatal(facts, err, reader, provider)
	}
	for _, mutate := range []func(*app.Object){func(o *app.Object) { o.TenantID = "foreign" }, func(o *app.Object) { o.Key = "elsewhere" }, func(o *app.Object) { o.Digest = "bad" }, func(o *app.Object) { o.Bytes = append(o.Bytes, byte(0)) }, func(o *app.Object) { o.Bytes = []byte("tampered") }, func(o *app.Object) { o.MediaType = "text/plain" }} {
		inspector, reader, provider, snapshot, input = fixture(t)
		mutate(&reader.object)
		facts, err = inspector.InspectCosignSnapshot(t.Context(), snapshot, input)
		if err != nil || facts.Outcome != verificationapp.CosignOutcomeVerificationFailed || provider.calls != 0 {
			t.Fatal("untrusted bytes verified", facts, err)
		}
	}
}

func TestCosignInspectorPreservesUppercaseArtifactDigestCompatibility(t *testing.T) {
	i, _, p, s, input := fixture(t)
	s.Subject.SubjectDigest = "sha256:" + strings.Repeat("A", 64)
	s.ArtifactDigest = s.Subject.SubjectDigest
	facts, err := i.InspectCosignSnapshot(t.Context(), s, input)
	if err != nil || facts.Outcome != "" || p.calls != 1 || p.request.ArtifactDigest != s.ArtifactDigest {
		t.Fatal("valid historical artifact digest rejected", facts, err)
	}
}
func TestCosignInspectorFailsBeforeReadAndNeverLeaksProviderErrors(t *testing.T) {
	for _, mutate := range []func(*verificationapp.CosignSnapshot){func(s *verificationapp.CosignSnapshot) { s.PayloadRef = "object://tenants/foreign/key" }, func(s *verificationapp.CosignSnapshot) { s.PayloadFinalized = false }, func(s *verificationapp.CosignSnapshot) { s.PayloadSize = verificationapp.MaxCosignPayloadBytes + 1 }, func(s *verificationapp.CosignSnapshot) { s.Algorithm = "metadata" }, func(s *verificationapp.CosignSnapshot) { s.ArtifactDigest = "sha256:" + strings.Repeat("b", 64) }} {
		inspector, reader, provider, snapshot, input := fixture(t)
		mutate(&snapshot)
		facts, err := inspector.InspectCosignSnapshot(t.Context(), snapshot, input)
		if err != nil || facts.Outcome != verificationapp.CosignOutcomeVerificationFailed || reader.calls+provider.calls != 0 {
			t.Fatal(facts, err)
		}
	}
	inspector, reader, _, snapshot, input := fixture(t)
	inspector.Verifier = nil
	facts, err := inspector.InspectCosignSnapshot(t.Context(), snapshot, input)
	if err != nil || facts.Outcome != verificationapp.CosignOutcomeUnavailable || reader.calls != 0 {
		t.Fatal(facts, err)
	}
	inspector, _, provider, snapshot, input := fixture(t)
	provider.err = errors.New("private provider secrets")
	facts, err = inspector.InspectCosignSnapshot(t.Context(), snapshot, input)
	if err != nil || facts.Outcome != verificationapp.CosignOutcomeVerificationFailed || strings.Contains(facts.Checks[0].Detail, "private") {
		t.Fatal(facts, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	inspector, reader, provider, snapshot, input = fixture(t)
	if _, err := inspector.InspectCosignSnapshot(ctx, snapshot, input); !errors.Is(err, context.Canceled) || reader.calls+provider.calls != 0 {
		t.Fatal(err)
	}
}
