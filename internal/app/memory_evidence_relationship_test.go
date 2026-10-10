package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

type memoryRelationshipTestFacts interface {
	evidenceapp.RelationshipScopeTransaction
	ReadRelationshipEvidence(context.Context, string, string) (evidencedomain.EvidenceItem, error)
	ReadRelationshipOrigins(context.Context, string, string) ([]evidencedomain.EvidenceLifecycleEvent, error)
}

func TestMemoryEvidenceRelationshipFactsUseCurrentOwnedIdentityAndBoundedDetachedOrigins(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	facts, ok := tx.Repositories().Evidence.(memoryRelationshipTestFacts)
	if !ok {
		t.Fatal("memory evidence lacks focused relationship facts")
	}
	e := domain.EvidenceItem{ID: "e", TenantID: "tenant", ProductID: "tenant-product", Metadata: map[string]any{"invalid": make(chan int)}}
	tx.state.Evidence[e.ID] = e
	refs, err := facts.LockRelationshipEvidence(t.Context(), "tenant", e.ID)
	if err != nil || refs != (application.ResourceReferences{ProductID: "tenant-product"}) {
		t.Fatal("identity preflight inspected descriptive metadata", err)
	}
	if v, err := facts.ReadRelationshipEvidence(t.Context(), "tenant", e.ID); err == nil || !reflect.DeepEqual(v, evidencedomain.EvidenceItem{}) {
		t.Fatal("fresh read accepted malformed canonical metadata", err)
	}
	e.Metadata = map[string]any{"number": json.Number("9007199254740993")}
	tx.state.Evidence[e.ID] = e
	event := domain.EvidenceLifecycleEvent{ID: "origin", TenantID: "tenant", EvidenceID: e.ID, Action: "amendment", SchemaVersion: evidencedomain.EvidenceRelationshipLifecycleSchemaVersion, Reason: "private reason", Details: map[string]any{evidencedomain.LegacyCanonicalOriginDetailKey: map[string]any{"number": json.Number("9007199254740993")}, "private": "not selected"}}
	tx.state.EvidenceLifecycle[event.ID] = event
	tx.state.EvidenceLifecycle["unrelated"] = domain.EvidenceLifecycleEvent{ID: "unrelated", TenantID: "foreign", EvidenceID: e.ID, Details: map[string]any{"invalid": make(chan int)}}
	origins, err := facts.ReadRelationshipOrigins(t.Context(), "tenant", e.ID)
	if err != nil || len(origins) != 1 || origins[0].ID != event.ID || origins[0].Reason != "" || len(origins[0].Details) != 1 || !reflect.DeepEqual(origins[0].Details[evidencedomain.LegacyCanonicalOriginDetailKey], event.Details[evidencedomain.LegacyCanonicalOriginDetailKey]) {
		t.Fatal("relationship origin projection lost precision or exposed unrelated fields", err)
	}
	origins[0].Details[evidencedomain.LegacyCanonicalOriginDetailKey].(map[string]any)["number"] = "changed"
	if event.Details[evidencedomain.LegacyCanonicalOriginDetailKey].(map[string]any)["number"] != json.Number("9007199254740993") {
		t.Fatal("returned origin shared storage maps")
	}
	if _, err := facts.LockRelationshipEvidence(t.Context(), "foreign", e.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("relationship origin crossed tenant boundary", err)
	}
	if _, err := facts.LockRelationshipTarget(t.Context(), "tenant", "release", "foreign-release"); !errors.Is(err, ErrNotFound) {
		t.Fatal("relationship target crossed tenant boundary", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := facts.ReadRelationshipOrigins(ctx, "tenant", e.ID); !errors.Is(err, context.Canceled) || v != nil {
		t.Fatal("cancelled relationship read returned origins", err)
	}
	// The selected DTO, including its framing, is exactly the byte budget.
	selected := domain.EvidenceLifecycleEvent{ID: event.ID, TenantID: event.TenantID, EvidenceID: event.EvidenceID, Action: event.Action, SchemaVersion: event.SchemaVersion, Details: map[string]any{evidencedomain.LegacyCanonicalOriginDetailKey: ""}}
	raw, err := json.Marshal(selected)
	if err != nil {
		t.Fatal(err)
	}
	event.Details[evidencedomain.LegacyCanonicalOriginDetailKey] = strings.Repeat("x", (8<<20)-len(raw))
	tx.state.EvidenceLifecycle[event.ID] = event
	if v, err := facts.ReadRelationshipOrigins(t.Context(), "tenant", e.ID); err != nil || len(v) != 1 {
		t.Fatal("exact relationship origin byte budget rejected", err)
	}
	event.Details[evidencedomain.LegacyCanonicalOriginDetailKey] = strings.Repeat("x", (8<<20)-len(raw)+1)
	tx.state.EvidenceLifecycle[event.ID] = event
	if v, err := facts.ReadRelationshipOrigins(t.Context(), "tenant", e.ID); !errors.Is(err, ErrConflict) || v != nil {
		t.Fatal("oversized relationship origins were returned", err)
	}
}

func TestMemoryEvidenceRelationshipOriginsEnforceExactRowBudgetAndStableOrder(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	facts, ok := tx.Repositories().Evidence.(memoryRelationshipTestFacts)
	if !ok {
		t.Fatal("focused relationship facts missing")
	}
	tx.state.Evidence["e"] = domain.EvidenceItem{ID: "e", TenantID: "tenant", ProductID: "tenant-product"}
	for i := range 4096 {
		id := fmt.Sprintf("origin-%04d", i)
		tx.state.EvidenceLifecycle[id] = domain.EvidenceLifecycleEvent{ID: id, TenantID: "tenant", EvidenceID: "e", Action: "amendment", SchemaVersion: evidencedomain.EvidenceRelationshipLifecycleSchemaVersion, Details: map[string]any{evidencedomain.LegacyCanonicalOriginDetailKey: map[string]any{"product_id": "tenant-product"}}}
	}
	v, err := facts.ReadRelationshipOrigins(t.Context(), "tenant", "e")
	if err != nil || len(v) != 4096 {
		t.Fatal("exact origin row budget rejected", err)
	}
	for i, origin := range v {
		if origin.ID != fmt.Sprintf("origin-%04d", i) {
			t.Fatal("origins were not deterministically ordered")
		}
	}
	extra := tx.state.EvidenceLifecycle["origin-0000"]
	extra.ID = "extra"
	tx.state.EvidenceLifecycle[extra.ID] = extra
	if v, err := facts.ReadRelationshipOrigins(t.Context(), "tenant", "e"); !errors.Is(err, ErrConflict) || v != nil {
		t.Fatal("origin row overflow exposed a partial result", err)
	}
}
