package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type bundleVerificationFake struct {
	subject      SubjectReference
	snapshot     ReleaseBundleVerificationSnapshot
	payloadReads int
	fail         string
	results      []verificationdomain.VerificationResult
	audits       []application.AuditEvent
	jobs         []application.OutboxEvent
}

func (f *bundleVerificationFake) ExecuteReleaseBundleVerification(ctx context.Context, command func(context.Context, ReleaseBundleVerificationTransaction) error) error {
	copy := *f
	copy.results, copy.audits, copy.jobs = nil, nil, nil
	err := command(ctx, &copy)
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
func (f *bundleVerificationFake) ResolveReleaseBundleVerificationSubject(context.Context, string, string) (SubjectReference, error) {
	return f.subject, nil
}
func (f *bundleVerificationFake) ReadReleaseBundleVerification(context.Context, SubjectReference) (ReleaseBundleVerificationSnapshot, error) {
	f.payloadReads++
	if f.fail == "read" {
		return ReleaseBundleVerificationSnapshot{}, errVerificationTestFailure
	}
	return f.snapshot, nil
}
func (f *bundleVerificationFake) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	if !r.ScopeOnly && f.fail == "auth" {
		return application.ErrForbidden
	}
	return nil
}
func (f *bundleVerificationFake) InsertVerificationResult(_ context.Context, result verificationdomain.VerificationResult) error {
	if f.fail == "result" {
		return errVerificationTestFailure
	}
	f.results = append(f.results, result)
	return nil
}
func (f *bundleVerificationFake) AppendAudit(_ context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	if f.fail == "audit" {
		return application.AuditReceipt{}, errVerificationTestFailure
	}
	f.audits = append(f.audits, event)
	return application.AuditReceipt{ID: event.ID}, nil
}
func (f *bundleVerificationFake) EnqueueOutbox(_ context.Context, event application.OutboxEvent) error {
	if f.fail == "outbox" {
		return errVerificationTestFailure
	}
	f.jobs = append(f.jobs, event)
	return nil
}

type bundleVerifierFake struct{}

func (bundleVerifierFake) VerifyPayload(public, signature string, payload []byte) bool {
	return public == "public" && signature == "valid" && string(payload) == "hash"
}

type bundleHashFake struct{}

func (bundleHashFake) Hash(any) (string, error) { return "hash", nil }

func bundleVerificationFixture(t *testing.T) (*ReleaseBundleVerificationCommands, *bundleVerificationFake) {
	t.Helper()
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	status, _ := verificationdomain.ParseSigningKeyStatus("active")
	subject := SubjectReference{TenantID: "tenant", Type: "release_bundle", ID: "bundle", Resources: application.ResourceReferences{ProductID: "product", ReleaseID: "release"}}
	f := &bundleVerificationFake{subject: subject, snapshot: ReleaseBundleVerificationSnapshot{Subject: subject, Manifest: map[string]any{"version": 1}, ManifestHash: "hash", SignatureRefs: []string{"signature"}, Signatures: []verificationdomain.Signature{{ID: "signature", TenantID: "tenant", SubjectType: "release_bundle", SubjectID: "bundle", KeyID: "key", Algorithm: "Ed25519", Value: "valid", CreatedAt: now.Add(-time.Minute)}}, Keys: []verificationdomain.SigningKey{{ID: "key", TenantID: "tenant", Status: status, Algorithm: "Ed25519", PublicKey: "public", CreatedAt: now.Add(-time.Hour), ValidFrom: now.Add(-time.Hour)}}}}
	c, err := NewReleaseBundleVerificationCommands(ReleaseBundleVerificationConfig{Transactions: f, Authorizer: f, Hasher: bundleHashFake{}, Verifier: bundleVerifierFake{}, Clock: application.ClockFunc(func() time.Time { return now }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_receipt" })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}
func TestReleaseBundleVerificationCommitsReceiptAuditAndJobAtomically(t *testing.T) {
	c, f := bundleVerificationFixture(t)
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"verify:read"}}
	result, err := c.VerifyReleaseBundle(t.Context(), actor, "bundle")
	if err != nil || result.Result.String() != "passed" || len(f.results) != 1 || len(f.audits) != 1 || len(f.jobs) != 1 {
		t.Fatalf("result=%#v err=%v effects=%#v", result, err, f)
	}
	if f.audits[0].EntryType != "subject.verified" || f.audits[0].SubjectID != result.ID || f.jobs[0].Kind != "verify_subject" || f.jobs[0].Payload["result_id"] != result.ID {
		t.Fatal("receipt links changed")
	}
	for _, fail := range []string{"read", "result", "audit", "outbox", "commit"} {
		t.Run(fail, func(t *testing.T) {
			c, f := bundleVerificationFixture(t)
			f.fail = fail
			result, err := c.VerifyReleaseBundle(t.Context(), actor, "bundle")
			if !errors.Is(err, errVerificationTestFailure) || result.ID != "" || len(f.results)+len(f.audits)+len(f.jobs) != 0 {
				t.Fatalf("partial receipt=%#v err=%v effects=%#v", result, err, f)
			}
		})
	}
}
func TestReleaseBundleVerificationFailsClosedForTamperingAndRevocation(t *testing.T) {
	for _, change := range []struct {
		name   string
		mutate func(*ReleaseBundleVerificationSnapshot)
	}{
		{"hash", func(s *ReleaseBundleVerificationSnapshot) { s.ManifestHash = "tampered" }},
		{"signature", func(s *ReleaseBundleVerificationSnapshot) { s.Signatures[0].Value = "invalid" }},
		{"subject", func(s *ReleaseBundleVerificationSnapshot) { s.Signatures[0].SubjectID = "another" }},
		{"signature tenant", func(s *ReleaseBundleVerificationSnapshot) { s.Signatures[0].TenantID = "foreign" }},
		{"key tenant", func(s *ReleaseBundleVerificationSnapshot) { s.Keys[0].TenantID = "foreign" }},
		{"missing key", func(s *ReleaseBundleVerificationSnapshot) { s.Keys = nil }},
		{"missing signature", func(s *ReleaseBundleVerificationSnapshot) { s.Signatures = nil }},
		{"future signature", func(s *ReleaseBundleVerificationSnapshot) {
			s.Signatures[0].CreatedAt = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
		}},
		{"compromise", func(s *ReleaseBundleVerificationSnapshot) {
			s.Keys[0].RevocationSemantics = "compromised"
			s.Keys[0].HistoricalValidityPolicy = "invalidate_all"
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			c, f := bundleVerificationFixture(t)
			change.mutate(&f.snapshot)
			result, err := c.VerifyReleaseBundle(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, "bundle")
			if !errors.Is(err, ErrVerificationFailed) || result.Result.String() != "failed" || len(f.results) != 1 || len(f.audits) != 1 || len(f.jobs) != 1 {
				t.Fatalf("result=%#v err=%v effects=%#v", result, err, f)
			}
		})
	}
}
func TestReleaseBundleVerificationAuthorizesBeforePayloadAndRejectsBadCoordinates(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}
	c, f := bundleVerificationFixture(t)
	f.fail = "auth"
	if _, err := c.VerifyReleaseBundle(t.Context(), actor, "bundle"); !errors.Is(err, application.ErrForbidden) || f.payloadReads != 0 {
		t.Fatal("unauthorized payload read", err)
	}
	c, f = bundleVerificationFixture(t)
	f.subject.TenantID = "foreign"
	if _, err := c.VerifyReleaseBundle(t.Context(), actor, "bundle"); !errors.Is(err, ErrNotFound) || f.payloadReads != 0 {
		t.Fatal("foreign payload read", err)
	}
	for _, id := range []string{"", " ", "bad\x00id", string([]byte{0xff})} {
		c, f = bundleVerificationFixture(t)
		if _, err := c.VerifyReleaseBundle(t.Context(), actor, id); !errors.Is(err, ErrValidation) || f.payloadReads != 0 {
			t.Fatal("invalid coordinate reached read", err)
		}
	}
	c, f = bundleVerificationFixture(t)
	f.snapshot.Subject.Resources.ReleaseID = "changed"
	if _, err := c.VerifyReleaseBundle(t.Context(), actor, "bundle"); !errors.Is(err, ErrConflict) || len(f.results) != 0 {
		t.Fatal("snapshot subject mismatch", err)
	}
}

func TestReleaseBundleVerificationPreservesHistoricalValidityPolicies(t *testing.T) {
	for _, tc := range []struct {
		name, semantics, policy            string
		compromisedBeforeSignature, passed bool
	}{
		{"ordinary revoke", "ordinary", "preserve", false, true},
		{"preserved compromise", "compromised", "preserve", true, true},
		{"before compromise", "compromised", "invalidate_from_compromise", false, true},
		{"after compromise", "compromised", "invalidate_from_compromise", true, false},
		{"all invalidated", "compromised", "invalidate_all", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, f := bundleVerificationFixture(t)
			key := &f.snapshot.Keys[0]
			key.Status, _ = verificationdomain.ParseSigningKeyStatus("revoked")
			key.RevocationSemantics, key.HistoricalValidityPolicy = tc.semantics, tc.policy
			at := f.snapshot.Signatures[0].CreatedAt.Add(time.Second)
			key.RevokedAt, key.ValidUntil = &at, &at
			compromise := at
			if tc.compromisedBeforeSignature {
				compromise = at.Add(-2 * time.Second)
			}
			key.CompromisedAt = &compromise
			result, err := c.VerifyReleaseBundle(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "key"}, "bundle")
			if (err == nil) != tc.passed || (result.Result.String() == "passed") != tc.passed {
				t.Fatalf("result=%#v err=%v", result, err)
			}
		})
	}
	c, f := bundleVerificationFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.VerifyReleaseBundle(ctx, identitydomain.Actor{TenantID: "tenant", KeyID: "key"}, "bundle"); !errors.Is(err, context.Canceled) || f.payloadReads != 0 {
		t.Fatal("cancelled command read state", err)
	}
}
