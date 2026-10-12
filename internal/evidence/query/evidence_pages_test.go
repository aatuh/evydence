package query

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

type evidencePageReaderStub struct {
	request EvidencePageRequest
	result  appquery.Result[EvidencePoint]
	err     error
	calls   int
}

func (r *evidencePageReaderStub) PageEvidence(ctx context.Context, in EvidencePageRequest, guard EvidenceReadGuard) (appquery.Result[EvidencePoint], error) {
	r.calls++
	r.request = in
	for _, p := range r.result.Items {
		if err := guard(application.ResourceReferences{ProductID: p.ProductID, ProjectID: p.ProjectID, ReleaseID: p.ReleaseID}); err != nil {
			return appquery.Result[EvidencePoint]{}, err
		}
	}
	return r.result, r.err
}

func TestEvidencePagesPreserveFiltersVisibilityOrderAndCursor(t *testing.T) {
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	one := EvidencePoint{Item: evidencedomain.EvidenceItem{ID: "a", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", Type: "document", Subtype: "manual", SourceSystem: "source", CollectorID: "collector", VerificationStatus: "pending", Tags: []string{"tag"}, SubjectRefs: []evidencedomain.SubjectRef{{Type: "artifact", ID: "artifact", Digest: "digest"}}, CreatedAt: now}, ProductID: "prod_1", ReleaseID: "rel_1"}
	two := one
	two.Item.ID = "b"
	page := appquery.PageRequest{PageSize: 2, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	last := appquery.RecordSortKey("b", now, page.Sort)
	r := &evidencePageReaderStub{result: appquery.Result[EvidencePoint]{Items: []EvidencePoint{one, two}, Next: &last}}
	s, err := NewEvidencePages(r)
	if err != nil {
		t.Fatal(err)
	}
	filter := EvidencePageFilter{ProductID: "prod_1", ReleaseID: "rel_1", Type: "document", Subtype: "manual", SourceSystem: "source", CollectorID: "collector", VerificationStatus: "pending", SubjectType: "artifact", SubjectID: "digest", Tag: "tag", CreatedAfter: now, CreatedBefore: now}
	result, err := s.ListPage(t.Context(), evidenceHumanActor("product", "prod_1"), filter, page, nil)
	if err != nil || len(result.Items) != 2 || result.Items[1].ID != "b" || result.Next == nil || *result.Next != last || r.request.TenantID != "ten_1" || r.request.TenantWide || !reflect.DeepEqual(r.request.AllowedProductIDs, []string{"prod_1"}) || r.request.Filter != filter {
		t.Fatal("page lost filter/authority/cursor", result, err, r.request)
	}
	r.result.Items[0].Item.TenantID = "other"
	if _, err := s.ListPage(t.Context(), evidenceKeyActor(), filter, page, nil); !errors.Is(err, ErrConflict) {
		t.Fatal("foreign returned row accepted", err)
	}
}

func TestEvidencePagesRejectMalformedProjectionAndInput(t *testing.T) {
	page := appquery.PageRequest{PageSize: 2, Sort: appquery.SortID, Direction: appquery.Ascending}
	base := EvidencePoint{Item: evidencedomain.EvidenceItem{ID: "a", TenantID: "ten_1", Type: "document", CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}}
	for _, tc := range []struct {
		name   string
		points []EvidencePoint
		next   *appquery.SortKey
		filter EvidencePageFilter
	}{
		{"wrong next", []EvidencePoint{base}, &appquery.SortKey{ID: "other", Value: "other"}, EvidencePageFilter{}},
		{"duplicate", []EvidencePoint{base, base}, nil, EvidencePageFilter{}},
		{"unvalidated worker", []EvidencePoint{{Item: evidencedomain.EvidenceItem{ID: "a", TenantID: "ten_1", Type: "parser_normalization"}}}, nil, EvidencePageFilter{}},
		{"filter mismatch", []EvidencePoint{base}, nil, EvidencePageFilter{Type: "sbom"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &evidencePageReaderStub{result: appquery.Result[EvidencePoint]{Items: tc.points, Next: tc.next}}
			s, err := NewEvidencePages(r)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.ListPage(t.Context(), evidenceKeyActor(), tc.filter, page, nil); !errors.Is(err, ErrConflict) {
				t.Fatal("invalid page accepted", err)
			}
		})
	}
	r := &evidencePageReaderStub{}
	s, err := NewEvidencePages(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, filter := range []EvidencePageFilter{{ProductID: strings.Repeat("x", 1025)}, {Tag: "tag\x00"}, {CreatedAfter: time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC)}} {
		if _, err := s.ListPage(t.Context(), evidenceKeyActor(), filter, page, nil); !errors.Is(err, ErrValidation) {
			t.Fatal("bad filter reached reader", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.ListPage(ctx, evidenceKeyActor(), EvidencePageFilter{}, page, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("lost cancellation", err)
	}
	if r.calls != 0 {
		t.Fatal("invalid request read storage", r.calls)
	}
	oversized := base
	oversized.Item.Title = strings.Repeat("x", MaxEvidencePageBytes+1)
	r.result = appquery.Result[EvidencePoint]{Items: []EvidencePoint{oversized}}
	if result, err := s.ListPage(t.Context(), evidenceKeyActor(), EvidencePageFilter{}, page, nil); !errors.Is(err, ErrConflict) || len(result.Items) != 0 {
		t.Fatal("oversized page returned partial success", len(result.Items), err)
	}
}
