package app

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func TestMemoryEvidenceCanonicalFieldsSurviveInsertCommitSnapshotReadAndLinkCopy(t *testing.T) {
	factory, tx := memoryMembershipReadFixture(t)
	e := domain.EvidenceItem{ID: "exact-evidence", TenantID: "tenant", ProductID: "tenant-product", Type: "manual", Title: "Recorded", PayloadHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CreatedAt: fixedNow(), ObservedAt: fixedNow(), SourceIdentity: map[string]any{"run": json.Number("9007199254740993")}, Metadata: map[string]any{"number": json.Number("9007199254740993")}, Canonicalization: evidencedomain.EvidenceCanonicalizationProfileVersion, EvidenceVersion: 1, SchemaVersion: domain.EvidenceItemSchemaVersion}
	hash, err := application.NormalizedJSONHash(domain.EvidenceFromContextModel(evidencedomain.CanonicalEvidenceFields(domain.EvidenceToContextModel(e))))
	if err != nil {
		t.Fatal(err)
	}
	e.CanonicalHash = hash
	if err := tx.Repositories().Evidence.InsertEvidence(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(snapshot.Evidence[e.ID], e) {
		t.Fatal("insert/commit/snapshot rounded canonical evidence metadata", err)
	}
	unit, err := factory.BeginUnitOfWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unit.Rollback(t.Context()) }()
	r := unit.Repositories().Evidence
	read, err := r.GetEvidence(t.Context(), e.TenantID, e.ID)
	if err != nil || !reflect.DeepEqual(read, e) {
		t.Fatal("reopened evidence read changed canonical inputs", err)
	}
	linked := read
	linked.ReleaseID = "tenant-release"
	if err := r.CompareAndSwapEvidenceLinks(t.Context(), read, linked); err != nil {
		t.Fatal(err)
	}
	stored, err := r.GetEvidence(t.Context(), e.TenantID, e.ID)
	if err != nil || !reflect.DeepEqual(stored, linked) {
		t.Fatal("link projection changed immutable canonical inputs", err)
	}
	event := domain.EvidenceLifecycleEvent{ID: "exact-lifecycle", TenantID: e.TenantID, EvidenceID: e.ID, Action: "amendment", Reason: "reviewed", CreatedAt: fixedNow(), SchemaVersion: domain.EvidenceLifecycleSchemaVersion, Details: map[string]any{"sequence": json.Number("9007199254740993")}}
	if err := r.AppendLifecycle(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	if err := unit.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	snapshot, err = factory.Snapshot()
	if err != nil || !reflect.DeepEqual(snapshot.EvidenceLifecycle[event.ID], event) {
		t.Fatal("lifecycle commit/snapshot changed exact details", err)
	}
	event.Details["sequence"] = "changed"
	linked.Metadata["number"] = "changed"
	snapshot.Evidence[e.ID].SourceIdentity["run"] = "changed"
	detached, err := factory.Snapshot()
	if err != nil || detached.Evidence[e.ID].SourceIdentity["run"] != json.Number("9007199254740993") || detached.Evidence[e.ID].Metadata["number"] != json.Number("9007199254740993") || detached.EvidenceLifecycle[event.ID].Details["sequence"] != json.Number("9007199254740993") {
		t.Fatal("evidence/lifecycle results shared storage maps", err)
	}
}

func TestMemoryEvidenceClonesStillRejectNonJSONValuesAndInvalidTimesWithoutPartialResults(t *testing.T) {
	cycle := map[string]any{}
	cycle["self"] = cycle
	for _, metadata := range []map[string]any{{"bad": make(chan int)}, {"bad": json.Number("invalid")}, cycle} {
		if v, err := cloneMemoryCanonicalRecord(domain.EvidenceItem{ID: "e", Metadata: metadata}); err == nil || !reflect.DeepEqual(v, domain.EvidenceItem{}) {
			t.Fatal("evidence clone accepted invalid JSON or returned partial fields", err)
		}
		if v, err := cloneMemoryCanonicalRecord(domain.EvidenceLifecycleEvent{ID: "event", Details: metadata}); err == nil || !reflect.DeepEqual(v, domain.EvidenceLifecycleEvent{}) {
			t.Fatal("lifecycle clone accepted invalid JSON or returned partial fields", err)
		}
	}
	invalidTime := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	if v, err := cloneMemoryCanonicalRecord(domain.EvidenceItem{ID: "e", CreatedAt: invalidTime}); err == nil || !reflect.DeepEqual(v, domain.EvidenceItem{}) {
		t.Fatal("evidence clone bypassed stored time validation", err)
	}
	if v, err := cloneMemoryCanonicalRecord(domain.EvidenceLifecycleEvent{ID: "event", CreatedAt: invalidTime}); err == nil || !reflect.DeepEqual(v, domain.EvidenceLifecycleEvent{}) {
		t.Fatal("lifecycle clone bypassed stored time validation", err)
	}
}
