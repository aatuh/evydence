package app

import (
	"errors"
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func TestEvidenceCollectorAttributionRejectsUnboundOrConflictingClaimsBeforeEffectsAndReplay(t *testing.T) {
	for _, tc := range []struct {
		name, bound, claimed string
		identity             map[string]any
	}{
		{"different top-level collector", "collector", "other", nil},
		{"different source collector", "collector", "", map[string]any{"collector_id": "other"}},
		{"conflicting source collector", "collector", "collector", map[string]any{"collector_id": "other"}},
		{"unbound top-level collector", "", "collector", nil},
		{"unbound source collector", "", "", map[string]any{"collector_id": "collector"}},
		{"padded collector", "collector", " collector ", nil},
		{"nonstring source collector", "collector", "", map[string]any{"collector_id": 42}},
		{"null source collector", "collector", "", map[string]any{"collector_id": nil}},
		{"empty source collector", "collector", "", map[string]any{"collector_id": ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newEvidenceServiceFixture(t)
			f.actor.CollectorID = tc.bound
			in := CreateEvidenceInput{Type: "manual", Title: "Note", PayloadHash: testDigest('a'), CollectorID: tc.claimed, SourceIdentity: tc.identity}
			c, err := NewEvidenceCreationCommands(creationConfig(f))
			if err != nil {
				t.Fatal(err)
			}
			v, err := c.CreateEvidence(t.Context(), f.actor, in)
			if !errors.Is(err, application.ErrForbidden) || !reflect.DeepEqual(v, evidencedomain.EvidenceItem{}) || f.canonicalizer.calls != 0 || len(f.reader.scopes) != 0 || f.transactions.commits != 0 || f.transactions.rollbacks != 0 || len(f.transactions.state.evidence) != 0 || len(f.transactions.state.audit) != 0 || len(f.transactions.state.outbox) != 0 || len(f.transactions.state.payloads) != 0 {
				t.Errorf("forged attribution reached preparation or effects: err=%v", err)
			}
			guard := &creationGuardTransaction{}
			config := creationConfig(f)
			config.Transactions = guard
			c, err = NewEvidenceCreationCommands(config)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.AuthorizeEvidenceCreation(t.Context(), f.actor, in); !errors.Is(err, application.ErrForbidden) || len(guard.scopes) != 0 || len(guard.authorizations) != 0 {
				t.Errorf("forged attribution reached replay ownership lookups: err=%v", err)
			}
		})
	}
}

func TestEvidenceCollectorAttributionPreservesAuthenticatedIdentityAndUnrelatedMetadata(t *testing.T) {
	for _, tc := range []struct{ name, bound, claimed string }{
		{"ordinary API key", "", ""},
		{"collector with omitted claim", "collector", ""},
		{"collector with matching claim", "collector", "collector"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newEvidenceServiceFixture(t)
			f.actor.CollectorID = tc.bound
			identity := map[string]any{"job": "job", "nested": map[string]any{"value": "original"}}
			if tc.claimed != "" {
				identity["collector_id"] = tc.claimed
			}
			in := CreateEvidenceInput{Type: "manual", Title: "Note", PayloadHash: testDigest('a'), CollectorID: tc.claimed, SourceIdentity: identity}
			before := cloneMap(identity)
			c, err := NewEvidenceCreationCommands(creationConfig(f))
			if err != nil {
				t.Fatal(err)
			}
			v, err := c.CreateEvidence(t.Context(), f.actor, in)
			if err != nil || v.ID == "" || v.CollectorID != tc.bound || v.UploadedBy != f.actor.KeyID || !reflect.DeepEqual(v.SourceIdentity, before) || !reflect.DeepEqual(identity, before) || f.transactions.commits != 1 || len(f.transactions.state.audit) != 1 {
				t.Fatal("matching or omitted attribution changed canonical fields or effects", err)
			}
			v.SourceIdentity["nested"].(map[string]any)["value"] = "changed"
			if stored := f.transactions.state.evidence[v.ID]; stored.CollectorID != tc.bound || !reflect.DeepEqual(stored.SourceIdentity, before) {
				t.Fatal("response mutation changed immutable attribution")
			}
			guard := &creationGuardTransaction{}
			config := creationConfig(f)
			config.Transactions = guard
			c, err = NewEvidenceCreationCommands(config)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.AuthorizeEvidenceCreation(t.Context(), f.actor, in); err != nil || len(guard.scopes) != 1 || len(guard.authorizations) != 1 {
				t.Fatal("matching attribution did not pass current replay policy", err)
			}
		})
	}
}
