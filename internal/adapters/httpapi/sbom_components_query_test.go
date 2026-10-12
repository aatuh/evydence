package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type sbomComponentsQueryFake struct {
	calls  int
	filter evidencequery.SBOMComponentFilter
	page   appquery.PageRequest
	after  *appquery.SortKey
	err    error
}

func (f *sbomComponentsQueryFake) ListPage(_ context.Context, _ identitydomain.Actor, filter evidencequery.SBOMComponentFilter, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[evidencedomain.SBOMComponentRecord], error) {
	f.calls++
	f.filter, f.page, f.after = filter, page, after
	if f.err != nil {
		return appquery.Result[evidencedomain.SBOMComponentRecord]{}, f.err
	}
	item := evidencedomain.SBOMComponentRecord{ID: "sbom_1:0", SBOMID: "sbom_1", Format: "cyclonedx", SpecVersion: "1.6", Component: evidencedomain.SBOMComponent{Name: "openssl", PURL: "pkg:generic/openssl@3"}}
	if after != nil {
		item.ID = "sbom_1:1"
		return appquery.Result[evidencedomain.SBOMComponentRecord]{Items: []evidencedomain.SBOMComponentRecord{item}}, nil
	}
	return appquery.Result[evidencedomain.SBOMComponentRecord]{Items: []evidencedomain.SBOMComponentRecord{item}, Next: &appquery.SortKey{Value: item.ID, ID: item.ID}}, nil
}

func TestSBOMComponentsHandlerUsesFocusedPageAndRejectsBadInputs(t *testing.T) {
	server, secret := testServer(t)
	query := &sbomComponentsQueryFake{}
	server.sbomComponentsQuery = query
	first := getRaw(t, server, secret, "/v1/sbom-components?sbom_id=sbom_1&limit=1", http.StatusOK)
	var response struct {
		Data []struct {
			ID        string `json:"id"`
			Component struct {
				Name string `json:"name"`
			} `json:"component"`
		} `json:"data"`
		Meta struct {
			NextCursor string `json:"next_cursor"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &response); err != nil || len(response.Data) != 1 || response.Data[0].ID != "sbom_1:0" || response.Data[0].Component.Name != "openssl" || response.Meta.NextCursor == "" || query.calls != 1 || query.filter.SBOMID != "sbom_1" || query.page.PageSize != 1 {
		t.Fatalf("focused SBOM page=%s query=%#v error=%v", first.Body.String(), query, err)
	}
	second := getRaw(t, server, secret, "/v1/sbom-components?sbom_id=sbom_1&limit=1&cursor="+url.QueryEscape(response.Meta.NextCursor), http.StatusOK)
	if err := json.Unmarshal(second.Body.Bytes(), &response); err != nil || len(response.Data) != 1 || response.Data[0].ID != "sbom_1:1" || query.after == nil || query.calls != 2 {
		t.Fatalf("SBOM continuation=%s query=%#v error=%v", second.Body.String(), query, err)
	}
	for _, path := range []string{
		"/v1/sbom-components?sbom_id=sbom_1&sbom_id=sbom_2",
		"/v1/sbom-components?sbom_id=%20",
		"/v1/sbom-components?limit=0",
		"/v1/sbom-components?limit=1&page_size=1",
		"/v1/sbom-components?sort=created_at",
		"/v1/sbom-components?unknown=value",
	} {
		getRaw(t, server, secret, path, http.StatusBadRequest)
	}
	getRawNoAuth(t, server, "/v1/sbom-components", http.StatusUnauthorized)
	if query.calls != 2 {
		t.Fatalf("invalid or unauthenticated request reached query %d times", query.calls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{evidencequery.ErrValidation, http.StatusBadRequest},
		{evidencequery.ErrNotFound, http.StatusNotFound},
		{evidencequery.ErrConflict, http.StatusConflict},
		{application.ErrForbidden, http.StatusForbidden},
		{errors.New("private-database-detail"), http.StatusInternalServerError},
	} {
		query.err = test.err
		result := getRaw(t, server, secret, "/v1/sbom-components", test.status)
		if strings.Contains(result.Body.String(), "private-database-detail") {
			t.Fatalf("internal detail leaked: %s", result.Body.String())
		}
	}
}
