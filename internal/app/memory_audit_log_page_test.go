package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func memoryAuditLogPageFixture(t *testing.T) (*memoryUnitOfWork, verificationquery.AuditLogReader) {
	t.Helper()
	_, tx := memoryGovernanceReadFixture(t)
	reader, ok := tx.Repositories().Audit.(verificationquery.AuditLogReader)
	if !ok {
		t.Fatal("memory audit lacks native bounded page reader")
	}
	return tx, reader
}

func memoryAuditLogPageRecord(id string) domain.AuditChainEntry {
	return domain.AuditChainEntry{ID: id, TenantID: "tenant", Sequence: 7, EntryType: "fixture.created", SubjectType: "release", SubjectID: "release", ActorType: "api_key", ActorID: "key", OccurredAt: fixedNow(), RequestID: "request", IdempotencyKey: "request-key", PayloadHash: "payload", CanonicalEntryHash: "canonical", PreviousEntryHash: "previous", EntryHash: "hash", SignatureRef: "signature", Metadata: map[string]any{"nested": map[string]any{"items": []any{"original", true}}}, SchemaVersion: "1"}
}

func TestMemoryAuditLogPagesPreserveFieldsFiltersAndDetachedMetadata(t *testing.T) {
	tx, reader := memoryAuditLogPageFixture(t)
	for _, id := range []string{"a", "b", "c"} {
		tx.state.AuditEntries["tenant"] = append(tx.state.AuditEntries["tenant"], memoryAuditLogPageRecord(id))
	}
	foreign := memoryAuditLogPageRecord("foreign")
	foreign.TenantID = "foreign"
	foreign.Metadata = map[string]any{"invalid": func() {}}
	tx.state.AuditEntries["tenant"] = append(tx.state.AuditEntries["tenant"], foreign)
	filtered := memoryAuditLogPageRecord("filtered")
	filtered.SubjectID = "other"
	filtered.Metadata = foreign.Metadata
	tx.state.AuditEntries["tenant"] = append(tx.state.AuditEntries["tenant"], filtered)
	before := memoryAuditLogPageRecord("a")
	req := verificationquery.AuditPageRequest{TenantID: "tenant", Filter: verificationquery.AuditFilter{SubjectType: "release", SubjectID: "release", Since: ptrTime(fixedNow())}, Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}}
	page, err := reader.PageAuditLog(t.Context(), req)
	if err != nil || len(page.Items) != 1 || !reflect.DeepEqual(page.Items[0], verificationdomain.AuditChainEntry(before)) || page.Next == nil || page.Next.ID != "a" {
		t.Fatal("audit page lost fields, filters or keyset", page, err)
	}
	page.Items[0].Metadata["nested"].(map[string]any)["items"].([]any)[0] = "mutated"
	if !reflect.DeepEqual(tx.state.AuditEntries["tenant"][0], before) {
		t.Fatal("public audit metadata aliases or mutates immutable state")
	}
	req.Filter.Since = ptrTime(fixedNow().Add(time.Nanosecond))
	page, err = reader.PageAuditLog(t.Context(), req)
	if err != nil || len(page.Items) != 0 || page.Next != nil {
		t.Fatal("since boundary was not inclusive or filtered rows leaked", page, err)
	}
}

func TestMemoryAuditLogPagesTraverseAllRowsWithTimeTiesAndFourOrders(t *testing.T) {
	tx, reader := memoryAuditLogPageFixture(t)
	for i := range 501 {
		v := memoryAuditLogPageRecord(fmt.Sprintf("entry-%03d", i))
		v.OccurredAt = v.OccurredAt.Add(time.Duration((501-i)/3) * time.Minute)
		tx.state.AuditEntries["tenant"] = append(tx.state.AuditEntries["tenant"], v)
	}
	for _, sortBy := range []appquery.Sort{appquery.SortID, appquery.SortCreatedAt} {
		for _, direction := range []appquery.Direction{appquery.Ascending, appquery.Descending} {
			t.Run(string(sortBy)+"/"+string(direction), func(t *testing.T) {
				req := verificationquery.AuditPageRequest{TenantID: "tenant", Page: appquery.PageRequest{PageSize: 7, Sort: sortBy, Direction: direction}}
				var got []string
				for count := 0; count < 80; count++ {
					page, err := reader.PageAuditLog(t.Context(), req)
					if err != nil || len(page.Items) > 7 {
						t.Fatal("audit page failed", err)
					}
					for _, v := range page.Items {
						got = append(got, v.ID)
						if v.TenantID != "tenant" {
							t.Fatal("foreign audit row leaked")
						}
					}
					if page.Next == nil {
						break
					}
					last := page.Items[len(page.Items)-1]
					if *page.Next != appquery.RecordSortKey(last.ID, last.OccurredAt, sortBy) {
						t.Fatal("cursor lost occurrence-time identity")
					}
					req.After = page.Next
				}
				want := slices.Clone(tx.state.AuditEntries["tenant"])
				slices.SortFunc(want, func(a, b domain.AuditChainEntry) int {
					comparison := 0
					if sortBy == appquery.SortCreatedAt {
						comparison = a.OccurredAt.Compare(b.OccurredAt)
					}
					if comparison == 0 {
						comparison = strings.Compare(a.ID, b.ID)
					}
					return comparison
				})
				if direction == appquery.Descending {
					slices.Reverse(want)
				}
				ids := make([]string, len(want))
				for i, v := range want {
					ids[i] = v.ID
				}
				if !slices.Equal(got, ids) {
					t.Fatal("audit traversal omitted, duplicated or misordered rows", len(got))
				}
			})
		}
	}
}

func TestMemoryAuditLogPageBoundsSelectedMetadataIncludingLookahead(t *testing.T) {
	tx, reader := memoryAuditLogPageFixture(t)
	a, b, c := memoryAuditLogPageRecord("a"), memoryAuditLogPageRecord("b"), memoryAuditLogPageRecord("c")
	a.Metadata = map[string]any{"x": strings.Repeat("x", (1<<20)-8)}
	c.Metadata = map[string]any{"invalid": func() {}}
	tx.state.AuditEntries["tenant"] = []domain.AuditChainEntry{a, b, c}
	req := verificationquery.AuditPageRequest{TenantID: "tenant", Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}}
	if _, err := reader.PageAuditLog(t.Context(), req); err != nil {
		t.Fatal("exact metadata limit or unselected corrupt row was rejected", err)
	}
	tx.state.AuditEntries["tenant"][1].Metadata = map[string]any{"x": strings.Repeat("x", (1<<20)-7)}
	if v, err := reader.PageAuditLog(t.Context(), req); !errors.Is(err, verificationquery.ErrInvalidProjection) || !reflect.DeepEqual(v, appquery.Result[verificationdomain.AuditChainEntry]{}) {
		t.Fatal("oversized lookahead exposed a partial audit page", err)
	}
	tx.state.AuditEntries["tenant"][1].Metadata = c.Metadata
	if _, err := reader.PageAuditLog(t.Context(), req); !errors.Is(err, verificationquery.ErrInvalidProjection) {
		t.Fatal("unserializable selected metadata was accepted", err)
	}
	var missingContext context.Context
	if _, err := reader.PageAuditLog(missingContext, req); err == nil {
		t.Fatal("nil context was accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reader.PageAuditLog(ctx, req); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation was not propagated", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.PageAuditLog(t.Context(), req); err == nil {
		t.Fatal("closed transaction returned audit rows")
	}
}

func TestMemoryAuditLogPageRejectsInvalidNativeCursorAndMissingTenant(t *testing.T) {
	_, reader := memoryAuditLogPageFixture(t)
	base := verificationquery.AuditPageRequest{TenantID: "tenant", Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}}
	for _, tc := range []struct {
		name   string
		modify func(*verificationquery.AuditPageRequest)
		want   error
	}{
		{"page", func(r *verificationquery.AuditPageRequest) { r.Page.PageSize = 0 }, appquery.ErrInvalidPage},
		{"ID cursor", func(r *verificationquery.AuditPageRequest) { r.After = &appquery.SortKey{ID: "a", Value: "b"} }, appquery.ErrInvalidCursor},
		{"time cursor", func(r *verificationquery.AuditPageRequest) {
			r.Page.Sort = appquery.SortCreatedAt
			r.After = &appquery.SortKey{ID: "a", Value: "not-time"}
		}, appquery.ErrInvalidCursor},
		{"noncanonical time", func(r *verificationquery.AuditPageRequest) {
			r.Page.Sort = appquery.SortCreatedAt
			r.After = &appquery.SortKey{ID: "a", Value: "2026-10-09T12:00:00+00:00"}
		}, appquery.ErrInvalidCursor},
		{"missing tenant", func(r *verificationquery.AuditPageRequest) { r.TenantID = "missing" }, ErrNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			tc.modify(&req)
			v, err := reader.PageAuditLog(t.Context(), req)
			if !errors.Is(err, tc.want) || !reflect.DeepEqual(v, appquery.Result[verificationdomain.AuditChainEntry]{}) {
				t.Fatal("invalid request exposed audit data or wrong error", err)
			}
		})
	}
}
