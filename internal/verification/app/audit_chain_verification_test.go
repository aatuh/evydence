package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type auditVerificationFake struct {
	bundleVerificationFake
	view      AuditChainVerificationView
	pages     []AuditChainVerificationPage
	pageReads int
	budgets   []int
}

func (f *auditVerificationFake) ExecuteAuditChainVerification(ctx context.Context, fn func(context.Context, AuditChainVerificationTransaction) error) error {
	copy := *f
	copy.results, copy.audits, copy.jobs = nil, nil, nil
	copy.pageReads, copy.budgets = 0, nil
	err := fn(ctx, &copy)
	f.payloadReads, f.pageReads, f.budgets = copy.payloadReads, copy.pageReads, copy.budgets
	if err != nil {
		return err
	}
	if f.fail == "commit" {
		return errVerificationTestFailure
	}
	f.results, f.audits, f.jobs = copy.results, copy.audits, copy.jobs
	return nil
}
func (f *auditVerificationFake) LockAuditChainVerification(context.Context, string) (AuditChainVerificationView, error) {
	f.payloadReads++
	if f.fail == "read" {
		return AuditChainVerificationView{}, errVerificationTestFailure
	}
	return f.view, nil
}
func (f *auditVerificationFake) ReadAuditChainVerificationPage(_ context.Context, _ AuditChainVerificationView, _ *int64, budget int) (AuditChainVerificationPage, error) {
	f.budgets = append(f.budgets, budget)
	n := f.pageReads
	f.pageReads++
	if n >= len(f.pages) {
		return AuditChainVerificationPage{}, nil
	}
	return f.pages[n], nil
}

type auditHashTestAdapter struct{}

func (auditHashTestAdapter) Hash(value any) (string, error) {
	return application.NormalizedJSONHash(value)
}

func TestAuditChainVerificationBindsReferencedSignaturesToRecordedSubjects(t *testing.T) {
	for _, subjectType := range []string{"release_bundle", "evidence_bundle", "merkle_batch", "signing_operation"} {
		t.Run(subjectType, func(t *testing.T) {
			c, f := auditVerificationFixture(t)
			e := &f.pages[0].Entries[0]
			e.SubjectType, e.SubjectID, e.SignatureRef = subjectType, "signed", "signature"
			if err := RehashAuditChainEntry(e, auditHashTestAdapter{}); err != nil {
				t.Fatal(err)
			}
			f.view.HeadHash = e.EntryHash
			sig := f.snapshot.Signatures[0]
			sig.SubjectType, sig.SubjectID = subjectType, "signed"
			if subjectType == "signing_operation" {
				sig.SubjectType, sig.SubjectID = "custom_subject", "target"
			}
			f.pages[0].Signatures = []verificationdomain.Signature{sig}
			f.pages[0].Keys = f.snapshot.Keys
			binding := AuditSignatureBinding{Subject: SubjectReference{TenantID: "tenant", Type: sig.SubjectType, ID: sig.SubjectID}, Payload: "hash"}
			f.pages[0].Bindings = map[string]AuditSignatureBinding{e.ID: binding}
			f.pages[0].BytesRead = 4096
			if r, err := c.VerifyAuditChain(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}); err != nil || r.Result.String() != "passed" {
				t.Fatal(r, err)
			}
			// A payload-compatible signature for another object must not be
			// accepted merely because a reader supplies that object's binding.
			if subjectType != "signing_operation" {
				binding.Subject.ID = "another"
				f.pages[0].Signatures[0].SubjectID = "another"
				f.pages[0].Bindings[e.ID] = binding
				r, err := c.VerifyAuditChain(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"})
				if !errors.Is(err, ErrVerificationFailed) || r.Checks[6].Result != "failed" {
					t.Fatal("signature borrowed from another subject", r, err)
				}
			}
		})
	}
}
func auditVerificationFixture(t *testing.T) (*AuditChainVerificationCommands, *auditVerificationFake) {
	t.Helper()
	base, bf := bundleVerificationFixture(t)
	entry := verificationdomain.AuditChainEntry{ID: "entry", TenantID: "tenant", Sequence: 1, EntryType: "test", SubjectType: "test", SubjectID: "test", ActorType: "api_key", ActorID: "caller", OccurredAt: base.config.Clock.Now().Add(-time.Minute), Metadata: map[string]any{"safe": "value"}, SchemaVersion: verificationdomain.AuditChainEntrySchemaVersion}
	if err := RehashAuditChainEntry(&entry, auditHashTestAdapter{}); err != nil {
		t.Fatal(err)
	}
	f := &auditVerificationFake{bundleVerificationFake: *bf, view: AuditChainVerificationView{TenantID: "tenant", HeadSequence: 1, HeadHash: entry.EntryHash, EntryCount: 1}, pages: []AuditChainVerificationPage{{Entries: []verificationdomain.AuditChainEntry{entry}, BytesRead: 1024}}}
	c, err := NewAuditChainVerificationCommands(AuditChainVerificationConfig{Transactions: f, Authorizer: f, Hasher: auditHashTestAdapter{}, Verifier: bundleVerifierFake{}, Clock: base.config.Clock, IDs: base.config.IDs})
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}
func TestAuditChainVerificationIsAtomicAndAuthorizesBeforeReading(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}
	c, f := auditVerificationFixture(t)
	r, err := c.VerifyAuditChain(t.Context(), actor)
	if err != nil || r.Result.String() != "passed" || r.SubjectType != "audit_chain" || r.SubjectID != "" || r.Profile.ID != verificationdomain.VerificationProfileAuditChainIntegrity || len(r.Checks) != 8 || len(f.results) != 1 || len(f.audits) != 1 || len(f.jobs) != 1 || f.jobs[0].Payload["result_id"] != r.ID {
		t.Fatal(r, err, f)
	}
	for _, failure := range []string{"read", "result", "audit", "outbox", "commit"} {
		c, f = auditVerificationFixture(t)
		f.fail = failure
		r, err = c.VerifyAuditChain(t.Context(), actor)
		if !errors.Is(err, errVerificationTestFailure) || r.ID != "" || len(f.results)+len(f.audits)+len(f.jobs) != 0 {
			t.Fatal("partial effects", failure, r, err)
		}
	}
	c, f = auditVerificationFixture(t)
	f.fail = "auth"
	if _, err := c.VerifyAuditChain(t.Context(), actor); !errors.Is(err, application.ErrForbidden) || f.payloadReads != 0 || f.pageReads != 0 {
		t.Fatal("read before authorization", err)
	}
	c, f = auditVerificationFixture(t)
	f.view.TenantID = "foreign"
	if _, err := c.VerifyAuditChain(t.Context(), actor); !errors.Is(err, ErrNotFound) || f.pageReads != 0 {
		t.Fatal("foreign page", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	c, f = auditVerificationFixture(t)
	if _, err := c.VerifyAuditChain(ctx, actor); !errors.Is(err, context.Canceled) || f.payloadReads != 0 {
		t.Fatal(err)
	}
}
func TestAuditChainVerificationPreservesCanonicalFieldsAndLegacyPrecision(t *testing.T) {
	for name, mutate := range map[string]func(*verificationdomain.AuditChainEntry){
		"tenant":      func(e *verificationdomain.AuditChainEntry) { e.TenantID = "foreign" },
		"sequence":    func(e *verificationdomain.AuditChainEntry) { e.Sequence = 2 },
		"previous":    func(e *verificationdomain.AuditChainEntry) { e.PreviousEntryHash = "other" },
		"id":          func(e *verificationdomain.AuditChainEntry) { e.ID = "other" },
		"actor":       func(e *verificationdomain.AuditChainEntry) { e.ActorID = "other" },
		"metadata":    func(e *verificationdomain.AuditChainEntry) { e.Metadata = map[string]any{"changed": true} },
		"schema":      func(e *verificationdomain.AuditChainEntry) { e.SchemaVersion = "unknown" },
		"request":     func(e *verificationdomain.AuditChainEntry) { e.RequestID = "changed" },
		"idempotency": func(e *verificationdomain.AuditChainEntry) { e.IdempotencyKey = "changed" },
		"payload":     func(e *verificationdomain.AuditChainEntry) { e.PayloadHash = "changed" },
	} {
		t.Run(name, func(t *testing.T) {
			c, f := auditVerificationFixture(t)
			mutate(&f.pages[0].Entries[0])
			f.view.HeadSequence = f.pages[0].Entries[0].Sequence
			r, err := c.VerifyAuditChain(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"})
			if !errors.Is(err, ErrVerificationFailed) || r.Result.String() != "failed" || len(f.results) != 1 {
				t.Fatal(r, err)
			}
		})
	}
	c, f := auditVerificationFixture(t)
	e := &f.pages[0].Entries[0]
	e.SchemaVersion = AuditChainEntryLegacySchemaVersion
	e.OccurredAt = e.OccurredAt.Truncate(time.Microsecond).Add(777 * time.Nanosecond)
	if err := RehashAuditChainEntry(e, auditHashTestAdapter{}); err != nil {
		t.Fatal(err)
	}
	f.view.HeadHash = e.EntryHash
	e.OccurredAt = e.OccurredAt.Truncate(time.Microsecond)
	if r, err := c.VerifyAuditChain(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}); err != nil || r.Result.String() != "passed" {
		t.Fatal("legacy precision lost", r, err)
	}
}
func TestAuditChainVerificationChecksEveryPageAndRejectsTruncation(t *testing.T) {
	c, f := auditVerificationFixture(t)
	first := f.pages[0].Entries[0]
	second := first
	second.ID = "second"
	second.Sequence = 2
	second.PreviousEntryHash = first.EntryHash
	if err := RehashAuditChainEntry(&second, auditHashTestAdapter{}); err != nil {
		t.Fatal(err)
	}
	f.view.EntryCount, f.view.HeadSequence, f.view.HeadHash = 2, 2, second.EntryHash
	f.pages = append(f.pages, AuditChainVerificationPage{Entries: []verificationdomain.AuditChainEntry{second}, BytesRead: 1024})
	r, err := c.VerifyAuditChain(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"})
	if err != nil || r.Result.String() != "passed" || len(r.Checks) != 15 || f.pageReads != 3 || f.budgets[1] >= f.budgets[0] {
		t.Fatal(r, err, f)
	}
	for name, mutate := range map[string]func(*auditVerificationFake){
		"missing page":   func(f *auditVerificationFake) { f.view.EntryCount = 2; f.view.HeadSequence = 2 },
		"repeating page": func(f *auditVerificationFake) { f.pages = append(f.pages, f.pages[0]) },
		"unbounded page": func(f *auditVerificationFake) {
			f.pages[0].Entries = make([]verificationdomain.AuditChainEntry, MaxAuditChainVerificationPageEntries+1)
		},
		"unbounded bytes":    func(f *auditVerificationFake) { f.pages[0].BytesRead = MaxAuditChainVerificationBytes + 1 },
		"missing byte count": func(f *auditVerificationFake) { f.pages[0].BytesRead = 0 },
		"wrong head":         func(f *auditVerificationFake) { f.view.HeadHash = "other" },
		"oversized ID":       func(f *auditVerificationFake) { f.pages[0].Entries[0].ID = strings.Repeat("x", 1025) },
	} {
		t.Run(name, func(t *testing.T) {
			c, f := auditVerificationFixture(t)
			mutate(f)
			r, err := c.VerifyAuditChain(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"})
			if !errors.Is(err, ErrConflict) || r.ID != "" || len(f.results) != 0 {
				t.Fatal(r, err)
			}
		})
	}
}
