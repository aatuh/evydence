package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type evidenceVerificationFake struct {
	bundleVerificationFake
	snapshot EvidenceVerificationSnapshot
}

func TestCanonicalOriginDecodingPreservesLegacyWirePolicy(t *testing.T) {
	item := evidencedomain.EvidenceItem{ID: "evidence", TenantID: "tenant", ReleaseID: "current", Canonicalization: evidencedomain.LegacyEvidenceCanonicalizationProfileVersion}
	event := evidencedomain.EvidenceLifecycleEvent{TenantID: "tenant", EvidenceID: "evidence", SchemaVersion: evidencedomain.EvidenceRelationshipLifecycleSchemaVersion}
	for _, raw := range []any{7, map[string]any{"release_id": 7}, map[string]any{"related_evidence_refs": 7}} {
		event.Details = map[string]any{evidencedomain.LegacyCanonicalOriginDetailKey: raw}
		if _, err := evidenceWithCanonicalOrigin(item, []evidencedomain.EvidenceLifecycleEvent{event}); err == nil {
			t.Fatal("malformed origin accepted", raw)
		}
		foreign := event
		foreign.TenantID = "foreign"
		if got, err := evidenceWithCanonicalOrigin(item, []evidencedomain.EvidenceLifecycleEvent{foreign}); err != nil || got.ReleaseID != "current" {
			t.Fatal("foreign malformed origin evaluated", err)
		}
	}
	event.Details = map[string]any{evidencedomain.LegacyCanonicalOriginDetailKey: map[string]any{"RELEASE_ID": "original", "related_evidence_refs": []any{map[string]any{"type": "evidence_item", "id": "related", "relationship": "links"}}}}
	got, err := evidenceWithCanonicalOrigin(item, []evidencedomain.EvidenceLifecycleEvent{event})
	if err != nil || got.ReleaseID != "original" || len(got.RelatedEvidenceRefs) != 1 || got.RelatedEvidenceRefs[0].Relationship != "links" {
		t.Fatal("legacy JSON changed", got, err)
	}
	event.Details = map[string]any{evidencedomain.LegacyCanonicalOriginDetailKey: map[string]any{}}
	other := event
	other.Details = map[string]any{evidencedomain.LegacyCanonicalOriginDetailKey: map[string]any{"related_evidence_refs": []any{}}}
	if _, err := evidenceWithCanonicalOrigin(item, []evidencedomain.EvidenceLifecycleEvent{event, other}); err == nil {
		t.Fatal("legacy nil/empty conflicting origins accepted")
	}
}

func TestEvidenceVerificationRejectsInvalidIdentifiersBeforePayloadRead(t *testing.T) {
	for _, id := range []string{"", " ", "bad\x00id", string([]byte{0xff}), strings.Repeat("x", 1025)} {
		commands, fake := evidenceVerificationFixture(t)
		if _, err := commands.VerifyEvidence(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, id); !errors.Is(err, ErrValidation) || fake.payloadReads != 0 {
			t.Fatal("invalid identifier read payload", err)
		}
	}
}

func (f *evidenceVerificationFake) ExecuteEvidenceVerification(ctx context.Context, command func(context.Context, EvidenceVerificationTransaction) error) error {
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
func (f *evidenceVerificationFake) ResolveEvidenceVerificationSubject(context.Context, string, string) (SubjectReference, error) {
	return f.subject, nil
}
func (f *evidenceVerificationFake) ReadEvidenceVerification(context.Context, SubjectReference) (EvidenceVerificationSnapshot, error) {
	f.payloadReads++
	if f.fail == "read" {
		return EvidenceVerificationSnapshot{}, errVerificationTestFailure
	}
	return f.snapshot, nil
}

type evidenceHashFake struct{}

func (evidenceHashFake) HashEvidence(context.Context, evidencedomain.EvidenceItem) (string, error) {
	return "hash", nil
}
func evidenceVerificationFixture(t *testing.T) (*EvidenceVerificationCommands, *evidenceVerificationFake) {
	t.Helper()
	bundle, f := bundleVerificationFixture(t)
	f.subject.Type = "evidence_item"
	f.subject.ID = "evidence"
	state := &evidenceVerificationFake{bundleVerificationFake: *f, snapshot: EvidenceVerificationSnapshot{Subject: f.subject, Item: evidencedomain.EvidenceItem{ID: "evidence", TenantID: "tenant", CanonicalHash: "hash", Canonicalization: evidencedomain.EvidenceCanonicalizationProfileVersion}}}
	c, err := NewEvidenceVerificationCommands(EvidenceVerificationConfig{Transactions: state, Authorizer: state, Hasher: evidenceHashFake{}, Clock: bundle.config.Clock, IDs: bundle.config.IDs})
	if err != nil {
		t.Fatal(err)
	}
	return c, state
}
func TestEvidenceVerificationReceiptIsAtomicAndAuthorizedBeforeHashInputs(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}
	c, f := evidenceVerificationFixture(t)
	result, err := c.VerifyEvidence(t.Context(), actor, "evidence")
	if err != nil || result.Result.String() != "passed" || len(f.results) != 1 || len(f.audits) != 1 || len(f.jobs) != 1 || f.jobs[0].SubjectType != "evidence_item" {
		t.Fatal("receipt contract", result, err)
	}
	for _, failure := range []string{"read", "result", "audit", "outbox", "commit"} {
		c, f = evidenceVerificationFixture(t)
		f.fail = failure
		result, err := c.VerifyEvidence(t.Context(), actor, "evidence")
		if !errors.Is(err, errVerificationTestFailure) || result.ID != "" || len(f.results)+len(f.audits)+len(f.jobs) != 0 {
			t.Fatal("partial receipt", failure, err)
		}
	}
	c, f = evidenceVerificationFixture(t)
	f.fail = "auth"
	if _, err := c.VerifyEvidence(t.Context(), actor, "evidence"); !errors.Is(err, application.ErrForbidden) || f.payloadReads != 0 {
		t.Fatal("unauthorized hash inputs read", err)
	}
	c, f = evidenceVerificationFixture(t)
	f.subject.TenantID = "foreign"
	if _, err := c.VerifyEvidence(t.Context(), actor, "evidence"); !errors.Is(err, ErrNotFound) || f.payloadReads != 0 {
		t.Fatal("foreign hash inputs read", err)
	}
	c, f = evidenceVerificationFixture(t)
	f.snapshot.Item.TenantID = "foreign"
	if _, err := c.VerifyEvidence(t.Context(), actor, "evidence"); !errors.Is(err, ErrConflict) || len(f.results) != 0 {
		t.Fatal("poisoned snapshot accepted", err)
	}
	c, f = evidenceVerificationFixture(t)
	f.snapshot.Item.CanonicalHash = "tampered"
	result, err = c.VerifyEvidence(t.Context(), actor, "evidence")
	if !errors.Is(err, ErrVerificationFailed) || result.Result.String() != "failed" || len(f.results) != 1 {
		t.Fatal("tampering not recorded", err)
	}
}
