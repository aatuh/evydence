package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

func memoryLifecycleFixture(t *testing.T) (*memoryUnitOfWork, evidencequery.LifecycleEventReader, *evidencequery.LifecycleEvents, domain.Actor) {
	t.Helper()
	tx, _ := memoryParsedPointFixture(t)
	reader, ok := tx.Repositories().Evidence.(evidencequery.LifecycleEventReader)
	if !ok {
		t.Fatal("memory Evidence repository lacks native lifecycle paging")
	}
	query, err := evidencequery.NewLifecycleEvents(reader)
	if err != nil {
		t.Fatal(err)
	}
	e := tx.state.Evidence["tenant-evidence"]
	e.Type = "document"
	e.Metadata = map[string]any{"note": "original"}
	tx.state.Evidence[e.ID] = e
	tx.state.EvidenceLifecycle = map[string]domain.EvidenceLifecycleEvent{}
	for i := range 8 {
		id := fmt.Sprintf("life-%02d", 7-i)
		tx.state.EvidenceLifecycle[id] = domain.EvidenceLifecycleEvent{ID: id, TenantID: "tenant", EvidenceID: e.ID, Action: "amendment", Reason: "reviewed", Details: map[string]any{"nested": map[string]any{"value": "original"}, "secret": "private-fixture"}, ActorID: "reviewer", SchemaVersion: "evidence-lifecycle.v1", CreatedAt: fixedNow().Add(time.Duration(i/2) * time.Microsecond)}
	}
	actor := domain.Actor{TenantID: "tenant", UserID: "reader", Scopes: []string{ScopeEvidenceRead}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "release", ResourceID: "tenant-release", Scopes: []string{ScopeEvidenceRead}}}}
	return tx, reader, query, actor
}

func TestMemoryLifecyclePagesUseCurrentRowsAndBothStableSorts(t *testing.T) {
	tx, _, query, actor := memoryLifecycleFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []appquery.Sort{appquery.SortID, appquery.SortCreatedAt} {
		for _, direction := range []appquery.Direction{appquery.Ascending, appquery.Descending} {
			want := []domain.EvidenceLifecycleEvent{}
			for _, event := range tx.state.EvidenceLifecycle {
				want = append(want, event)
			}
			sort.Slice(want, func(i, j int) bool {
				if field == appquery.SortCreatedAt && !want[i].CreatedAt.Equal(want[j].CreatedAt) {
					return want[i].CreatedAt.Before(want[j].CreatedAt)
				}
				return want[i].ID < want[j].ID
			})
			if direction == appquery.Descending {
				slices.Reverse(want)
			}
			request := appquery.PageRequest{PageSize: 3, Sort: field, Direction: direction}
			var after *appquery.SortKey
			ids := []string{}
			for n := 0; n < 4; n++ {
				result, err := query.ListPage(t.Context(), actor, " tenant-evidence ", request, after)
				if err != nil || len(result.Items) > request.PageSize {
					t.Fatal("lifecycle page lost bounded current metadata", result, err)
				}
				for _, event := range result.Items {
					stored := tx.state.EvidenceLifecycle[event.ID]
					if event.TenantID != stored.TenantID || event.EvidenceID != stored.EvidenceID || event.Action.String() != stored.Action || event.Reason != stored.Reason || event.ReplacementID != stored.ReplacementID || event.ActorID != stored.ActorID || event.SchemaVersion != stored.SchemaVersion || !event.CreatedAt.Equal(stored.CreatedAt) || !reflect.DeepEqual(event.Details, stored.Details) {
						t.Fatal("lifecycle page lost recorded public fields", event)
					}
					ids = append(ids, event.ID)
					event.Details["nested"].(map[string]any)["value"] = "caller-mutated"
				}
				after = result.Next
				if after == nil {
					break
				}
			}
			wantIDs := []string{}
			for _, event := range want {
				wantIDs = append(wantIDs, event.ID)
			}
			if !reflect.DeepEqual(ids, wantIDs) || after != nil {
				t.Fatal("lifecycle keysets omitted, repeated or misordered events", ids, wantIDs)
			}
		}
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("lifecycle reads or caller mutations changed recorded rows")
	}
}

func TestMemoryLifecycleGuardsPrecedePrivateDataAndDiscardFailures(t *testing.T) {
	tx, reader, query, actor := memoryLifecycleFixture(t)
	request := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	e := tx.state.Evidence["tenant-evidence"]
	e.Metadata["invalid-private"] = func() {}
	tx.state.Evidence[e.ID] = e
	actor.ResourceGrants = nil
	if _, err := query.ListPage(t.Context(), actor, e.ID, request, nil); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("private metadata was selected before authorization", err)
	}
	actor.ResourceGrants = []domain.ResourceGrant{{ResourceType: "release", ResourceID: "tenant-release", Scopes: []string{ScopeEvidenceRead}}}
	if value, err := query.ListPage(t.Context(), actor, e.ID, request, nil); !errors.Is(err, evidencequery.ErrConflict) || len(value.Items) != 0 || value.Next != nil {
		t.Fatal("invalid selected metadata returned a partial page", value, err)
	}
	delete(e.Metadata, "invalid-private")
	tx.state.Evidence[e.ID] = e
	for _, id := range []string{"missing", "foreign-evidence"} {
		if _, err := query.ListPage(t.Context(), actor, id, request, nil); !errors.Is(err, evidencequery.ErrNotFound) {
			t.Fatal("foreign or missing evidence revealed history", id, err)
		}
	}
	foreign := tx.state.EvidenceLifecycle["life-00"]
	foreign.ID, foreign.TenantID = "aaa-foreign", "foreign"
	tx.state.EvidenceLifecycle[foreign.ID] = foreign
	base, cancel := context.WithCancel(t.Context())
	guard := func(application.ResourceReferences) error { cancel(); return nil }
	page, err := reader.PageLifecycleEvents(base, actor.TenantID, e.ID, request, nil, guard)
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(page, evidencequery.LifecyclePage{}) {
		t.Fatal("cancellation returned a partial evidence/history projection", page, err)
	}
	if _, err := query.ListPage(t.Context(), actor, e.ID, request, nil); err != nil {
		t.Fatal("canceled history read retained transaction lock", err)
	}
	for _, key := range []*appquery.SortKey{{Value: "different", ID: "life-00"}, {Value: "", ID: "life-00"}} {
		if _, err := query.ListPage(t.Context(), actor, e.ID, request, key); !errors.Is(err, evidencequery.ErrValidation) {
			t.Fatal("malformed lifecycle keyset accepted", err)
		}
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	page, err = reader.PageLifecycleEvents(t.Context(), actor.TenantID, e.ID, request, nil, func(application.ResourceReferences) error { return nil })
	if !errors.Is(err, ErrConflict) || !reflect.DeepEqual(page, evidencequery.LifecyclePage{}) {
		t.Fatal("closed transaction exposed lifecycle data", page, err)
	}
}

func TestMemoryLifecycleBudgetIncludesLookaheadAndEverySelectedField(t *testing.T) {
	tx, _, query, actor := memoryLifecycleFixture(t)
	tx.state.EvidenceLifecycle = map[string]domain.EvidenceLifecycleEvent{}
	request := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	for _, id := range []string{"first", "second"} {
		tx.state.EvidenceLifecycle[id] = domain.EvidenceLifecycleEvent{ID: id, TenantID: "tenant", EvidenceID: "tenant-evidence", Action: "amendment", Reason: strings.Repeat("x", 5<<20), ActorID: "reviewer", SchemaVersion: "v1", CreatedAt: fixedNow()}
	}
	result, err := query.ListPage(t.Context(), actor, "tenant-evidence", request, nil)
	if !errors.Is(err, evidencequery.ErrConflict) || len(result.Items) != 0 || result.Next != nil {
		t.Fatal("lookahead overflow returned a truncated successful page", result, err)
	}
	delete(tx.state.EvidenceLifecycle, "second")
	event := tx.state.EvidenceLifecycle["first"]
	event.Reason = ""
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	event.Reason = strings.Repeat("x", evidencequery.MaxLifecyclePageBytes-len(raw))
	tx.state.EvidenceLifecycle[event.ID] = event
	if result, err := query.ListPage(t.Context(), actor, "tenant-evidence", request, nil); err != nil || len(result.Items) != 1 || len(result.Items[0].Reason) != len(event.Reason) {
		t.Fatal("exact typed projection budget was rejected", err)
	}
	event.Reason += "x"
	tx.state.EvidenceLifecycle[event.ID] = event
	if result, err := query.ListPage(t.Context(), actor, "tenant-evidence", request, nil); !errors.Is(err, evidencequery.ErrConflict) || len(result.Items) != 0 || result.Next != nil {
		t.Fatal("oversized selected text returned a partial page", err)
	}
}

func TestMemoryLifecycleValidatesSelectedWorkerAndReplayProvenance(t *testing.T) {
	for _, tc := range []struct{ kind, id string }{{"sbom", "sbom"}, {"vulnerability_scan", "scan"}, {"openapi_contract", "contract"}, {"vex", "vex"}, {"build_attestation", "attestation"}} {
		t.Run(tc.kind, func(t *testing.T) {
			tx, reader, _, _ := memoryLifecycleFixture(t)
			sourceID := tc.kind + "-source"
			if tc.kind == "vex" {
				e := tx.state.Evidence["sbom-source"]
				e.ID, e.Type = sourceID, tc.kind
				tx.state.Evidence[e.ID] = e
				tx.state.VEXDocuments[tc.id] = domain.VEXDocument{ID: tc.id, TenantID: "tenant", EvidenceID: sourceID, ReleaseID: "tenant-release", ArtifactID: "artifact", Format: "openvex", SchemaVersion: "vex.v1", CreatedAt: fixedNow()}
			}
			if tc.kind == "build_attestation" {
				e := tx.state.Evidence["attestation-source"]
				e.ID = sourceID
				tx.state.Evidence[e.ID] = e
				v := tx.state.BuildAttestations[tc.id]
				v.EvidenceID, v.SchemaVersion, v.VerificationStatus = sourceID, "attestation.v1", "accepted"
				v.SubjectDigests, v.CreatedAt = nil, fixedNow()
				tx.state.BuildAttestations[v.ID] = v
			}
			request := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
			guard := func(application.ResourceReferences) error { return nil }
			point, err := reader.PageLifecycleEvents(t.Context(), "tenant", sourceID, request, nil, guard)
			if err != nil || point.Point.Item.ID != sourceID || !point.Point.WorkerProjectionValidated || point.Point.ProductID != "tenant-product" || len(point.Page.Items) != 0 {
				t.Fatal("valid selected worker provenance was not checked", point, err)
			}
			switch tc.kind {
			case "sbom":
				v := tx.state.SBOMs[tc.id]
				v.ComponentCount++
				tx.state.SBOMs[v.ID] = v
			case "vulnerability_scan":
				v := tx.state.VulnerabilityScans[tc.id]
				v.Findings = append(v.Findings, v.Findings[0])
				tx.state.VulnerabilityScans[v.ID] = v
			case "openapi_contract":
				v := tx.state.OpenAPIContracts[tc.id]
				v.ProductID = "foreign-product"
				tx.state.OpenAPIContracts[v.ID] = v
			case "vex":
				v := tx.state.VEXDocuments[tc.id]
				v.StatementCount = -1
				tx.state.VEXDocuments[v.ID] = v
			case "build_attestation":
				v := tx.state.BuildAttestations[tc.id]
				v.VerificationStatus = "passed"
				tx.state.BuildAttestations[v.ID] = v
			}
			point, err = reader.PageLifecycleEvents(t.Context(), "tenant", sourceID, request, nil, guard)
			if !errors.Is(err, evidencequery.ErrConflict) || !reflect.DeepEqual(point, evidencequery.LifecyclePage{}) {
				t.Fatal("corrupt worker fact produced validated provenance", point, err)
			}
			delete(tx.state.SBOMs, tc.id)
			delete(tx.state.VulnerabilityScans, tc.id)
			delete(tx.state.OpenAPIContracts, tc.id)
			delete(tx.state.VEXDocuments, tc.id)
			delete(tx.state.BuildAttestations, tc.id)
			if point, err := reader.PageLifecycleEvents(t.Context(), "tenant", sourceID, request, nil, guard); err != nil || !point.Point.WorkerProjectionValidated {
				t.Fatal("queued source with no parsed fact was rejected", err)
			}
		})
	}
	tx, reader, _, _ := memoryLifecycleFixture(t)
	initial, projection, id := parserNormalizationProjectionFixture(t, "tenant")
	tx.state.Products["prod_parser"] = initial.Products["prod_parser"]
	tx.state.Releases["rel_test"] = initial.Releases["rel_test"]
	tx.state.Evidence["ev_source"] = initial.Evidence["ev_source"]
	tx.state.Evidence[id] = projection.ParserNormalizations[0]
	tx.state.AuditEntries["tenant"] = projection.AuditChainEntries
	request := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	guard := func(application.ResourceReferences) error { return nil }
	point, err := reader.PageLifecycleEvents(t.Context(), "tenant", id, request, nil, guard)
	if err != nil || point.Point.Item.ID != id || !point.Point.WorkerProjectionValidated || point.Point.ProductID != "prod_parser" {
		t.Fatal("validated replay source and audit were not selected", point, err)
	}
	previous := tx.state.AuditEntries["tenant"][0]
	previous.ID, previous.EntryType, previous.SubjectID = "previous", "evidence.created", "ev_source"
	if err := RehashAuditChainEntry(&previous); err != nil {
		t.Fatal(err)
	}
	entry := tx.state.AuditEntries["tenant"][0]
	entry.Sequence, entry.PreviousEntryHash = 2, previous.EntryHash
	if err := RehashAuditChainEntry(&entry); err != nil {
		t.Fatal(err)
	}
	tx.state.AuditEntries["tenant"] = []domain.AuditChainEntry{previous, entry}
	if _, err := reader.PageLifecycleEvents(t.Context(), "tenant", id, request, nil, guard); err != nil {
		t.Fatal("valid adjacent replay audit was rejected", err)
	}
	tx.state.AuditEntries["tenant"][0].EntryHash = "tampered"
	point, err = reader.PageLifecycleEvents(t.Context(), "tenant", id, request, nil, guard)
	if !errors.Is(err, evidencequery.ErrConflict) || !reflect.DeepEqual(point, evidencequery.LifecyclePage{}) {
		t.Fatal("tampered replay audit produced a validated point", point, err)
	}
}

func TestMemoryLifecycleSelectedProvenanceLimitsAndDetachedNumbers(t *testing.T) {
	tx, reader, query, actor := memoryLifecycleFixture(t)
	request := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	guard := func(application.ResourceReferences) error { return nil }
	e := tx.state.Evidence["tenant-evidence"]
	e.Metadata["nested"] = map[string]any{"number": json.Number("9007199254740993")}
	tx.state.Evidence[e.ID] = e
	point, err := reader.PageLifecycleEvents(t.Context(), "tenant", e.ID, request, nil, guard)
	if err != nil || point.Point.Item.Metadata["nested"].(map[string]any)["number"] != json.Number("9007199254740993") {
		t.Fatal("selected evidence JSON numbers were rounded", err)
	}
	point.Point.Item.Metadata["nested"].(map[string]any)["number"] = "changed"
	if tx.state.Evidence[e.ID].Metadata["nested"].(map[string]any)["number"] != json.Number("9007199254740993") {
		t.Fatal("selected evidence metadata shared current rows")
	}
	base := tx.state.SBOMs["sbom"]
	for i := range 4097 {
		v := base
		v.ID = fmt.Sprintf("selected-%04d", i)
		tx.state.SBOMs[v.ID] = v
	}
	result, err := query.ListPage(t.Context(), actor, "sbom-source", request, nil)
	if !errors.Is(err, evidencequery.ErrConflict) || len(result.Items) != 0 || result.Next != nil {
		t.Fatal("excess selected worker facts produced a successful history page", result, err)
	}
	delete(tx.state.SBOMs, "sbom")
	delete(tx.state.SBOMs, "selected-4096")
	if _, err := query.ListPage(t.Context(), actor, "sbom-source", request, nil); err != nil {
		t.Fatal("exact selected worker fact limit was rejected", err)
	}
	for _, id := range []string{"bad\x00id", string([]byte{0xff}), strings.Repeat("x", 1025)} {
		if _, err := reader.PageLifecycleEvents(t.Context(), "tenant", id, request, nil, guard); !errors.Is(err, evidencequery.ErrValidation) {
			t.Fatal("malformed lifecycle ID reached storage", err)
		}
	}
	var absent context.Context
	if _, err := reader.PageLifecycleEvents(absent, "tenant", e.ID, request, nil, guard); !errors.Is(err, evidencequery.ErrValidation) {
		t.Fatal("nil lifecycle context accepted", err)
	}
	if _, err := reader.PageLifecycleEvents(t.Context(), "tenant", e.ID, request, nil, nil); !errors.Is(err, evidencequery.ErrValidation) {
		t.Fatal("nil lifecycle authorization guard accepted", err)
	}
}

func TestMemoryLifecycleKeysetsDoNotRequireExistingCursorRows(t *testing.T) {
	_, _, query, actor := memoryLifecycleFixture(t)
	for _, tc := range []struct {
		sort appquery.Sort
		key  appquery.SortKey
		want string
	}{
		{appquery.SortID, appquery.SortKey{Value: "life-03a", ID: "life-03a"}, "life-04"},
		{appquery.SortCreatedAt, appquery.SortKey{Value: fixedNow().Add(time.Microsecond).UTC().Format(time.RFC3339Nano), ID: "life-04a"}, "life-05"},
	} {
		page := appquery.PageRequest{PageSize: 1, Sort: tc.sort, Direction: appquery.Ascending}
		result, err := query.ListPage(t.Context(), actor, "tenant-evidence", page, &tc.key)
		if err != nil || len(result.Items) != 1 || result.Items[0].ID != tc.want {
			t.Fatal("native lifecycle keyset required an existing cursor row", result, err)
		}
	}
}
