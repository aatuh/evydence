package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type evidencePageHTTPStub struct {
	calls  int
	filter evidencequery.EvidencePageFilter
	page   appquery.PageRequest
	after  *appquery.SortKey
}

func (f *evidencePageHTTPStub) ListPage(_ context.Context, a identitydomain.Actor, filter evidencequery.EvidencePageFilter, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[evidencedomain.EvidenceItem], error) {
	f.calls++
	f.filter, f.page, f.after = filter, page, after
	return appquery.Result[evidencedomain.EvidenceItem]{Items: []evidencedomain.EvidenceItem{{ID: "evidence-native", TenantID: a.TenantID, Type: "document", CreatedAt: time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)}}}, nil
}

func TestEvidenceCollectionsUseNativePageQueryWithoutAggregate(t *testing.T) {
	base, secret := testServer(t)
	f := &evidencePageHTTPStub{}
	s, err := NewServerWithOptions(base.ledger, ServerOptions{EvidencePageQuery: f})
	if err != nil {
		t.Fatal(err)
	}
	s.ledger, s.evidenceIngestion = nil, nil
	for _, path := range []string{"/v1/evidence?release_id=release&type=document&page_size=1&sort=id&direction=desc", "/v1/evidence/search?product_id=product&project_id=project&release_id=release&build_id=build&deployment_id=deployment&type=document&subtype=manual&source_system=source&collector_id=collector&verification_status=pending&subject_type=artifact&subject_id=digest&tag=tag&created_after=2026-10-01T00%3A00%3A00Z&created_before=2026-10-31T00%3A00%3A00Z&page_size=1&sort=id&direction=desc"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer "+secret)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"id":"evidence-native"`) {
			t.Fatal("native evidence page failed", w.Code, w.Body.String())
		}
	}
	if f.calls != 2 || f.page.PageSize != 1 || f.page.Sort != appquery.SortID || f.page.Direction != appquery.Descending || f.filter.ProductID != "product" || f.filter.ProjectID != "project" || f.filter.SourceSystem != "source" || f.filter.SubjectID != "digest" || f.filter.Tag != "tag" || f.filter.CreatedAfter.IsZero() || f.filter.CreatedBefore.IsZero() {
		t.Fatal("HTTP filter/pagination mapping changed", f)
	}
}
