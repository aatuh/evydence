package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type signatureMetadataFake struct {
	bundleVerificationFake
	point ArtifactSignatureVerificationSnapshot
}

func (f *signatureMetadataFake) ExecuteArtifactSignatureVerification(ctx context.Context, fn func(context.Context, ArtifactSignatureVerificationTransaction) error) error {
	copy := *f
	copy.results, copy.audits, copy.jobs = nil, nil, nil
	err := fn(ctx, &copy)
	f.payloadReads = copy.payloadReads
	if err != nil {
		return err
	}
	if f.fail == "commit" {
		return errVerificationTestFailure
	}
	f.results, f.audits, f.jobs = copy.results, copy.audits, copy.jobs
	return nil
}
func (f *signatureMetadataFake) ResolveArtifactSignatureVerificationSubject(context.Context, string, string) (SubjectReference, error) {
	return f.subject, nil
}
func (f *signatureMetadataFake) ReadArtifactSignatureVerification(context.Context, SubjectReference) (ArtifactSignatureVerificationSnapshot, error) {
	f.payloadReads++
	if f.fail == "read" {
		return ArtifactSignatureVerificationSnapshot{}, errVerificationTestFailure
	}
	return f.point, nil
}
func signatureMetadataFixture(t *testing.T) (*ArtifactSignatureVerificationCommands, *signatureMetadataFake) {
	t.Helper()
	b, base := bundleVerificationFixture(t)
	base.subject = SubjectReference{TenantID: "tenant", Type: "artifact_signature", ID: "signature", Resources: application.ResourceReferences{ArtifactID: "artifact"}}
	f := &signatureMetadataFake{bundleVerificationFake: *base, point: ArtifactSignatureVerificationSnapshot{Subject: base.subject, SignatureDigest: "sha256:" + strings.Repeat("a", 64), ArtifactDigest: "sha256:" + strings.Repeat("a", 64), AlgorithmPresent: true, SignaturePresent: true}}
	c, err := NewArtifactSignatureVerificationCommands(ArtifactSignatureVerificationConfig{Transactions: f, Authorizer: f, Clock: b.config.Clock, IDs: b.config.IDs})
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}
func TestArtifactSignatureVerificationIsMetadataOnlyAndAtomic(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}
	c, f := signatureMetadataFixture(t)
	r, err := c.VerifyArtifactSignature(t.Context(), actor, "signature")
	if err != nil || r.Result.String() != "limited" || r.Profile.ID != "artifact-signature-metadata.v1" || len(r.Checks) != 2 || len(r.Profile.RequiredChecks) != 5 || len(f.results) != 1 || len(f.audits) != 1 || len(f.jobs) != 1 || f.jobs[0].Payload["result_id"] != r.ID {
		t.Fatal(r, err, f)
	}
	for _, failure := range []string{"read", "result", "audit", "outbox", "commit"} {
		c, f = signatureMetadataFixture(t)
		f.fail = failure
		r, err = c.VerifyArtifactSignature(t.Context(), actor, "signature")
		if !errors.Is(err, errVerificationTestFailure) || r.ID != "" || len(f.results)+len(f.audits)+len(f.jobs) != 0 {
			t.Fatal("partial effects", failure, r, err)
		}
	}
	c, f = signatureMetadataFixture(t)
	f.fail = "auth"
	if _, err := c.VerifyArtifactSignature(t.Context(), actor, "signature"); !errors.Is(err, application.ErrForbidden) || f.payloadReads != 0 {
		t.Fatal("unauthorized metadata read", err)
	}
	c, f = signatureMetadataFixture(t)
	f.subject.TenantID = "foreign"
	if _, err := c.VerifyArtifactSignature(t.Context(), actor, "signature"); !errors.Is(err, ErrNotFound) || f.payloadReads != 0 {
		t.Fatal("foreign metadata read", err)
	}
}
func TestArtifactSignatureVerificationRejectsBadInputsAndCommitsNegativeFacts(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}
	for _, id := range []string{"", " ", "bad\x00id", string([]byte{0xff}), strings.Repeat("x", 1025)} {
		c, f := signatureMetadataFixture(t)
		if _, err := c.VerifyArtifactSignature(t.Context(), actor, id); !errors.Is(err, ErrValidation) || f.payloadReads != 0 {
			t.Fatal(err)
		}
	}
	for _, mutate := range []func(*ArtifactSignatureVerificationSnapshot){func(s *ArtifactSignatureVerificationSnapshot) { s.ArtifactDigest = "different" }, func(s *ArtifactSignatureVerificationSnapshot) { s.SignaturePresent = false }, func(s *ArtifactSignatureVerificationSnapshot) { s.AlgorithmPresent = false }} {
		c, f := signatureMetadataFixture(t)
		mutate(&f.point)
		r, err := c.VerifyArtifactSignature(t.Context(), actor, "signature")
		if !errors.Is(err, ErrVerificationFailed) || r.Result.String() != "failed" || len(f.results) != 1 || len(f.audits) != 1 || len(f.jobs) != 1 {
			t.Fatal(r, err)
		}
	}
	for _, mutate := range []func(*ArtifactSignatureVerificationSnapshot){func(s *ArtifactSignatureVerificationSnapshot) { s.Subject.TenantID = "foreign" }, func(s *ArtifactSignatureVerificationSnapshot) { s.SignatureDigest = strings.Repeat("x", 1025) }, func(s *ArtifactSignatureVerificationSnapshot) { s.ArtifactDigest = "bad\x00" }} {
		c, f := signatureMetadataFixture(t)
		mutate(&f.point)
		if r, err := c.VerifyArtifactSignature(t.Context(), actor, "signature"); !errors.Is(err, ErrConflict) || r.ID != "" || len(f.results) != 0 {
			t.Fatal(r, err)
		}
	}
}
