package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

func TestMemoryExceptionQueryFiltersGrantsBeforeKeysetAndDetachesSelectedMetadata(t *testing.T) {
	_, tx := memoryGovernanceReadFixture(t)
	reader, ok := tx.Repositories().Decisions.(riskquery.ExceptionReader)
	if !ok {
		t.Fatal("memory Risk lacks focused exception page reader")
	}
	next := tx.state.Exceptions["tenant-exception"]
	next.ID += "-z"
	next.Reason = strings.Repeat("private", 10000)
	tx.state.Exceptions[next.ID] = next
	foreign := tx.state.Exceptions["foreign-exception"]
	foreign.Reason = strings.Repeat("private", 10000)
	tx.state.Exceptions[foreign.ID] = foreign
	request := riskquery.ExceptionPageRequest{TenantID: "tenant", ReleaseID: "tenant-release", AllowedProductIDs: []string{"tenant-product"}, Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}}
	value, err := reader.PageExceptions(t.Context(), request)
	if err != nil || value.FilterRelease != (riskquery.ReleaseScope{ID: "tenant-release", ProductID: "tenant-product"}) || len(value.Page.Items) != 1 || value.Page.Items[0].Exception.ID != "tenant-exception" || value.Page.Next == nil {
		t.Fatal("exception page lost owned grant/keyset filtering", value, err)
	}
	*value.Page.Items[0].Exception.ApprovedAt = fixedNow().AddDate(1, 0, 0)
	if tx.state.Exceptions["tenant-exception"].ApprovedAt.Year() == fixedNow().AddDate(1, 0, 0).Year() {
		t.Fatal("exception page exposed stored timestamp pointer")
	}
	request.After = value.Page.Next
	if value, err := reader.PageExceptions(t.Context(), request); !errors.Is(err, riskquery.ErrInvalidProjection) || !reflect.DeepEqual(value, riskquery.ExceptionPage{}) {
		t.Fatal("oversized selected exception returned partial data", err)
	}
	request.After, request.AllowedProductIDs = nil, []string{"foreign-product"}
	value, err = reader.PageExceptions(t.Context(), request)
	if err != nil || len(value.Page.Items) != 0 || value.Page.Next != nil {
		t.Fatal("denied exception rows consumed cursor or disclosed data", value, err)
	}
	request.ReleaseID = "foreign-release"
	if _, err := reader.PageExceptions(t.Context(), request); !errors.Is(err, riskquery.ErrNotFound) {
		t.Fatal("foreign exception filter accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reader.PageExceptions(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatal("exception page ignored cancellation", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.PageExceptions(t.Context(), request); !errors.Is(err, ErrConflict) {
		t.Fatal("closed exception page returned data", err)
	}
}

func TestMemoryExceptionQueryPreservesCompleteRowsOrderingAndReadOnlyState(t *testing.T) {
	factory, tx := memoryGovernanceReadFixture(t)
	reader, ok := tx.Repositories().Decisions.(riskquery.ExceptionReader)
	if !ok {
		t.Fatal("memory Risk lacks focused exception page reader")
	}
	base := tx.state.Exceptions["tenant-exception"]
	base.ID = "a"
	base.Reason, base.Owner = "reviewed risk", "security team"
	base.CreatedAt = fixedNow()
	delete(tx.state.Exceptions, "tenant-exception")
	for i, id := range []string{"a", "b", "c"} {
		value := base
		value.ID = id
		// Equal timestamps exercise the ID tie-breaker, not just time ordering.
		if i == 2 {
			value.CreatedAt = fixedNow().AddDate(0, 0, 1)
		}
		tx.state.Exceptions[id] = value
	}
	// Another product in this tenant must be filtered before the page limit.
	tx.state.Products["other-product"] = domain.Product{ID: "other-product", TenantID: "tenant"}
	tx.state.Releases["other-release"] = domain.Release{ID: "other-release", TenantID: "tenant", ProductID: "other-product"}
	ungranted := base
	ungranted.ID, ungranted.ReleaseID, ungranted.Reason = "0", "other-release", strings.Repeat("private", 10000)
	tx.state.Exceptions[ungranted.ID] = ungranted
	committedBefore, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	pendingBefore, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, sort := range []appquery.Sort{appquery.SortID, appquery.SortCreatedAt} {
		for _, direction := range []appquery.Direction{appquery.Ascending, appquery.Descending} {
			t.Run(fmt.Sprintf("%s-%s", sort, direction), func(t *testing.T) {
				request := riskquery.ExceptionPageRequest{TenantID: "tenant", AllowedReleaseIDs: []string{"tenant-release"}, Page: appquery.PageRequest{PageSize: 1, Sort: sort, Direction: direction}}
				wantIDs := []string{"a", "b", "c"}
				if direction == appquery.Descending {
					slices.Reverse(wantIDs)
				}
				for i, id := range wantIDs {
					value, err := reader.PageExceptions(t.Context(), request)
					if err != nil || len(value.Page.Items) != 1 || value.FilterRelease != (riskquery.ReleaseScope{}) || value.Page.Items[0].ProductID != "tenant-product" {
						t.Fatal("page lost scoped complete row", value, err)
					}
					item := value.Page.Items[0].Exception
					if !reflect.DeepEqual(domain.Exception(item), tx.state.Exceptions[id]) {
						t.Fatal("page changed persisted exception metadata", item, tx.state.Exceptions[id])
					}
					if (value.Page.Next != nil) != (i < len(wantIDs)-1) {
						t.Fatal("page lost exact continuation boundary", value.Page.Next)
					}
					if value.Page.Next != nil && *value.Page.Next != appquery.RecordSortKey(id, item.CreatedAt, sort) {
						t.Fatal("cursor did not identify the last returned row")
					}
					*item.ApprovedAt = fixedNow().AddDate(1, 0, 0)
					request.After = value.Page.Next
				}
			})
		}
	}
	// Broken tenant-owned parent coordinates cannot make a foreign row visible.
	broken := base
	broken.ID, broken.ReleaseID = "broken", "foreign-release"
	tx.state.Exceptions[broken.ID] = broken
	value, err := reader.PageExceptions(t.Context(), riskquery.ExceptionPageRequest{TenantID: "tenant", TenantWide: true, ReleaseID: "tenant-release", Page: appquery.PageRequest{PageSize: 10, Sort: appquery.SortID, Direction: appquery.Ascending}})
	delete(tx.state.Exceptions, broken.ID)
	if err != nil || len(value.Page.Items) != 3 || value.Page.Next != nil {
		t.Fatal("tenant-wide filtered page leaked foreign parent or lost rows", value, err)
	}
	if !reflect.DeepEqual(pendingBefore, tx.state) {
		t.Fatal("paging or response mutation changed pending repository state")
	}
	committedAfter, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(committedBefore, committedAfter) {
		t.Fatal("paging changed committed repository state", err)
	}
}

func TestMemoryExceptionQueryRejectsInvalidRequestsWithoutPartialResults(t *testing.T) {
	_, tx := memoryGovernanceReadFixture(t)
	reader, ok := tx.Repositories().Decisions.(riskquery.ExceptionReader)
	if !ok {
		t.Fatal("memory Risk lacks focused exception page reader")
	}
	valid := riskquery.ExceptionPageRequest{TenantID: "tenant", TenantWide: true, Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}}
	for _, change := range []string{"page", "cursor", "ambiguous-products", "ambiguous-releases", "tenant", "release"} {
		t.Run(change, func(t *testing.T) {
			request := valid
			switch change {
			case "page":
				request.Page.PageSize = 0
			case "cursor":
				request.After = &appquery.SortKey{}
			case "ambiguous-products":
				request.AllowedProductIDs = []string{"tenant-product"}
			case "ambiguous-releases":
				request.AllowedReleaseIDs = []string{"tenant-release"}
			case "tenant":
				request.TenantID = " tenant "
			case "release":
				request.ReleaseID = "bad\x00release"
			}
			value, err := reader.PageExceptions(t.Context(), request)
			if !errors.Is(err, riskquery.ErrValidation) || !reflect.DeepEqual(value, riskquery.ExceptionPage{}) {
				t.Fatal("invalid request returned partial exception metadata", value, err)
			}
		})
	}
	var absent context.Context
	if value, err := reader.PageExceptions(absent, valid); !errors.Is(err, riskquery.ErrValidation) || !reflect.DeepEqual(value, riskquery.ExceptionPage{}) {
		t.Fatal("nil context returned exception metadata", value, err)
	}
}
