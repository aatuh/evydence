package app

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

func TestMemoryControlEvidencePagesFilterCurrentSubjectGrantsBeforeKeysetLimit(t *testing.T) {
	tx, _, _ := memoryControlEvidenceFixture(t)
	reader, ok := tx.Repositories().Controls.(riskquery.ControlEvidenceReader)
	if !ok {
		t.Fatal("memory controls lack focused link pages")
	}
	base := domain.ControlEvidence{ID: "a", TenantID: "tenant", ControlID: "tenant-control", EvidenceType: "build", SubjectType: "evidence", SubjectID: "tenant-evidence", ProductID: "tenant-product", ReleaseID: "tenant-release", Confidence: "high", Notes: "Review", SchemaVersion: domain.ControlEvidenceSchemaVersion, CreatedAt: fixedNow()}
	for _, id := range []string{"a", "b", "c"} {
		v := base
		v.ID = id
		tx.state.ControlEvidence[id] = v
	}
	tx.state.Products["private"] = domain.Product{ID: "private", TenantID: "tenant"}
	tx.state.Evidence["private"] = domain.EvidenceItem{ID: "private", TenantID: "tenant", ProductID: "private"}
	private := base
	private.ID, private.SubjectID, private.ProductID, private.ReleaseID = "0-private", "private", "private", ""
	tx.state.ControlEvidence[private.ID] = private
	foreign := base
	foreign.ID, foreign.TenantID = "0-foreign", "foreign"
	tx.state.ControlEvidence[foreign.ID] = foreign
	bad := base
	bad.ID, bad.SubjectID = "0-missing", "missing"
	tx.state.ControlEvidence[bad.ID] = bad
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	req := riskquery.ControlEvidencePageRequest{TenantID: "tenant", AllowedProductIDs: []string{"tenant-product"}, Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}}
	var got []string
	for range 4 {
		page, err := reader.PageControlEvidence(t.Context(), req)
		if err != nil || len(page.Items) != 1 {
			t.Fatal("filtered page lost row", err)
		}
		p := page.Items[0]
		if p.ProductID != "tenant-product" || p.ReleaseID != "tenant-release" || p.Link.SubjectID != base.SubjectID || p.Link.Notes != base.Notes {
			t.Fatal("page lost current coordinates/metadata")
		}
		got = append(got, p.Link.ID)
		if page.Next == nil {
			break
		}
		req.After = page.Next
	}
	if !slices.Equal(got, []string{"a", "b", "c"}) || !reflect.DeepEqual(before, tx.state) {
		t.Fatal("page limit preceded grants or traversal mutated state")
	}
	req.After = nil
	req.Filter.ProductID = "private"
	if v, err := reader.PageControlEvidence(t.Context(), req); err != nil || len(v.Items) != 0 || v.Next != nil {
		t.Fatal("filter supplied scope authority", err)
	}
	req.Filter = riskquery.ControlEvidenceFilter{}
	req.TenantWide = true
	req.AllowedProductIDs = nil
	delete(tx.state.ControlFrameworks, "tenant-framework")
	if v, err := reader.PageControlEvidence(t.Context(), req); err != nil || len(v.Items) != 0 {
		t.Fatal("missing current framework exposed links", err)
	}
}

func TestMemoryControlEvidencePagesTraverseFiveHundredLinksInAllOrders(t *testing.T) {
	tx, _, _ := memoryControlEvidenceFixture(t)
	reader, ok := tx.Repositories().Controls.(riskquery.ControlEvidenceReader)
	if !ok {
		t.Fatal("focused link page dependency missing")
	}
	for i := range 501 {
		id := fmt.Sprintf("link-%03d", i)
		tx.state.ControlEvidence[id] = domain.ControlEvidence{ID: id, TenantID: "tenant", ControlID: "tenant-control", EvidenceType: "build", SubjectType: "release", SubjectID: "tenant-release", Confidence: "high", SchemaVersion: domain.ControlEvidenceSchemaVersion, CreatedAt: fixedNow()}
	}
	for _, order := range []appquery.Sort{appquery.SortID, appquery.SortCreatedAt} {
		for _, direction := range []appquery.Direction{appquery.Ascending, appquery.Descending} {
			req := riskquery.ControlEvidencePageRequest{TenantID: "tenant", TenantWide: true, Page: appquery.PageRequest{PageSize: 7, Sort: order, Direction: direction}}
			var got []string
			for range 80 {
				result, err := reader.PageControlEvidence(t.Context(), req)
				if err != nil || len(result.Items) > 7 {
					t.Fatal("link page failed", err)
				}
				for _, p := range result.Items {
					got = append(got, p.Link.ID)
				}
				if result.Next == nil {
					break
				}
				last := result.Items[len(result.Items)-1].Link
				if *result.Next != appquery.RecordSortKey(last.ID, last.CreatedAt, order) {
					t.Fatal("link cursor lost last returned row")
				}
				req.After = result.Next
			}
			want := make([]string, 501)
			for i := range want {
				want[i] = fmt.Sprintf("link-%03d", i)
			}
			if direction == appquery.Descending {
				slices.Reverse(want)
			}
			if !slices.Equal(got, want) {
				t.Fatal("link pagination lost/duplicated/reordered records")
			}
		}
	}
	req := riskquery.ControlEvidencePageRequest{TenantID: "tenant", TenantWide: true, Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}}
	bad := tx.state.ControlEvidence["link-001"]
	bad.ID = "wrong"
	tx.state.ControlEvidence["link-001"] = bad
	if v, err := reader.PageControlEvidence(t.Context(), req); !errors.Is(err, riskquery.ErrInvalidProjection) || v.Items != nil || v.Next != nil {
		t.Fatal("malformed selected lookahead exposed partial page", err)
	}
}
