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

type dsseVerificationFake struct {
	bundleVerificationFake
	dsseSnapshot DSSEVerificationSnapshot
	facts        DSSEVerificationFacts
	inspections  int
}

func (f *dsseVerificationFake) ExecuteDSSEVerification(ctx context.Context, command func(context.Context, DSSEVerificationTransaction) error) error {
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
func (f *dsseVerificationFake) ResolveDSSEVerificationSubject(context.Context, string, string) (SubjectReference, error) {
	return f.subject, nil
}
func (f *dsseVerificationFake) ReadDSSEVerification(context.Context, SubjectReference) (DSSEVerificationSnapshot, error) {
	f.payloadReads++
	if f.fail == "read" {
		return DSSEVerificationSnapshot{}, errVerificationTestFailure
	}
	return f.dsseSnapshot, nil
}
func (f *dsseVerificationFake) VerifyDSSE(context.Context, DSSEVerificationSnapshot) (DSSEVerificationFacts, error) {
	f.inspections++
	if f.fail == "inspect" {
		return DSSEVerificationFacts{}, errVerificationTestFailure
	}
	return f.facts, nil
}
func dsseVerificationFixture(t *testing.T) (*DSSEVerificationCommands, *dsseVerificationFake) {
	t.Helper()
	bundle, base := bundleVerificationFixture(t)
	base.subject.Type, base.subject.ID, base.subject.Resources.BuildID = "build_attestation", "attestation", "build"
	f := &dsseVerificationFake{bundleVerificationFake: *base, dsseSnapshot: DSSEVerificationSnapshot{Subject: base.subject, EvidenceID: "evidence", PayloadRef: "object://key", PayloadHash: "sha256:" + strings.Repeat("a", 64), PayloadSize: 1, PayloadMediaType: "application/vnd.dsse.envelope+json", PayloadFinalized: true}}
	for _, name := range dsseRequiredChecks {
		f.facts.Checks = append(f.facts.Checks, verificationdomain.VerifyCheck{Name: name, Result: "passed"})
	}
	c, err := NewDSSEVerificationCommands(DSSEVerificationConfig{Transactions: f, Authorizer: f, Verifier: f, Clock: bundle.config.Clock, IDs: bundle.config.IDs})
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}
func TestDSSEVerificationAuthorizesBeforeStoredPayloadAndCommitsAtomically(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}
	c, f := dsseVerificationFixture(t)
	result, err := c.VerifyDSSEAttestationSignature(t.Context(), actor, "attestation")
	if err != nil || result.Result.String() != "passed" || result.SubjectType != "build_attestation" || result.Profile.ID != verificationdomain.VerificationProfileDSSEAttestationSignature || len(f.results) != 1 || len(f.audits) != 1 || len(f.jobs) != 1 || f.jobs[0].SubjectID != "attestation" || f.audits[0].SubjectID != result.ID {
		t.Fatal(result, err, f)
	}
	for _, fail := range []string{"read", "inspect", "result", "audit", "outbox", "commit"} {
		c, f = dsseVerificationFixture(t)
		f.fail = fail
		got, err := c.VerifyDSSEAttestationSignature(t.Context(), actor, "attestation")
		if !errors.Is(err, errVerificationTestFailure) || got.ID != "" || len(f.results)+len(f.audits)+len(f.jobs) != 0 {
			t.Fatal("partial receipt", fail, got, err)
		}
	}
	c, f = dsseVerificationFixture(t)
	f.fail = "auth"
	if _, err := c.VerifyDSSEAttestationSignature(t.Context(), actor, "attestation"); !errors.Is(err, application.ErrForbidden) || f.payloadReads+f.inspections != 0 {
		t.Fatal("unauthorized payload access", err)
	}
	c, f = dsseVerificationFixture(t)
	f.subject.TenantID = "foreign"
	if _, err := c.VerifyDSSEAttestationSignature(t.Context(), actor, "attestation"); !errors.Is(err, ErrNotFound) || f.payloadReads+f.inspections != 0 {
		t.Fatal("foreign payload access", err)
	}
}
func TestDSSEVerificationRejectsInconsistentAndOverBudgetSnapshots(t *testing.T) {
	for _, mutate := range []func(*DSSEVerificationSnapshot){
		func(s *DSSEVerificationSnapshot) { s.Subject.Resources.ReleaseID = "changed" },
		func(s *DSSEVerificationSnapshot) { s.PayloadFinalized = false },
		func(s *DSSEVerificationSnapshot) { s.PayloadSize = MaxDSSEPayloadBytes + 1 },
		func(s *DSSEVerificationSnapshot) { s.PayloadSize = -1 },
		func(s *DSSEVerificationSnapshot) { s.EvidenceID = "" },
		func(s *DSSEVerificationSnapshot) { s.Roots = []verificationdomain.DSSETrustRoot{{TenantID: "foreign"}} },
		func(s *DSSEVerificationSnapshot) {
			s.ExpectedSubjectDigests = make([]string, MaxDSSEVerificationRecords+1)
		},
	} {
		c, f := dsseVerificationFixture(t)
		mutate(&f.dsseSnapshot)
		if _, err := c.VerifyDSSEAttestationSignature(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, "attestation"); !errors.Is(err, ErrConflict) || f.inspections != 0 || len(f.results) != 0 {
			t.Fatal("invalid snapshot inspected", err)
		}
	}
	for _, id := range []string{"", " ", "bad\x00id", string([]byte{0xff}), strings.Repeat("x", 1025)} {
		c, f := dsseVerificationFixture(t)
		if _, err := c.VerifyDSSEAttestationSignature(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, id); !errors.Is(err, ErrValidation) || f.payloadReads+f.inspections != 0 {
			t.Fatal("invalid id inspected", err)
		}
	}
}
func TestDSSEVerificationPersistsConservativeAndFailedReceipts(t *testing.T) {
	for _, state := range []string{"not_verified", "failed"} {
		c, f := dsseVerificationFixture(t)
		for i := range f.facts.Checks {
			f.facts.Checks[i].Result = state
		}
		got, err := c.VerifyDSSEAttestationSignature(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, "attestation")
		if got.Result.String() != state || len(f.results) != 1 || len(f.audits) != 1 || len(f.jobs) != 1 || (state == "failed" && !errors.Is(err, ErrVerificationFailed)) || (state == "not_verified" && err != nil) {
			t.Fatal(got, err)
		}
	}
}
