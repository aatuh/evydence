package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

type portalAccessQueryFake struct {
	calls     int
	packageID string
	after     *appquery.SortKey
	err       error
}

func (f *portalAccessQueryFake) ListPage(_ context.Context, actor identitydomain.Actor, packageID string, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[packagedomain.CustomerPortalAccess], error) {
	f.calls++
	f.packageID, f.after = packageID, after
	if f.err != nil {
		return appquery.Result[packagedomain.CustomerPortalAccess]{}, f.err
	}
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	entry := packagedomain.CustomerPortalAccess{ID: "cpa_1", TenantID: actor.TenantID, PackageID: packageID,
		CustomerName: "Customer", ReviewerEmail: "reviewer@example.test", Prefix: "pref", Hash: "private-token-hash",
		ExpiresAt: now.Add(time.Hour), SchemaVersion: "customer-portal-access.v1.0.0", CreatedAt: now}
	if after != nil {
		entry.ID = "cpa_2"
		return appquery.Result[packagedomain.CustomerPortalAccess]{Items: []packagedomain.CustomerPortalAccess{entry}}, nil
	}
	key := appquery.RecordSortKey(entry.ID, now, page.Sort)
	return appquery.Result[packagedomain.CustomerPortalAccess]{Items: []packagedomain.CustomerPortalAccess{entry}, Next: &key}, nil
}

func TestPortalAccessHandlerUsesFocusedPageAndSafeErrors(t *testing.T) {
	server, secret := testServer(t)
	query := &portalAccessQueryFake{}
	server.portalAccessQuery = query
	first := getRaw(t, server, secret, "/v1/customer-portal/access?package_id=pkg_1&page_size=1", http.StatusOK)
	var response struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Meta struct {
			NextCursor string `json:"next_cursor"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &response); err != nil || len(response.Data) != 1 || response.Data[0].ID != "cpa_1" || response.Meta.NextCursor == "" || query.packageID != "pkg_1" || strings.Contains(first.Body.String(), "private-token-hash") {
		t.Fatalf("first page=%s query=%#v error=%v", first.Body.String(), query, err)
	}
	second := getRaw(t, server, secret, "/v1/customer-portal/access?package_id=pkg_1&page_size=1&cursor="+url.QueryEscape(response.Meta.NextCursor), http.StatusOK)
	if err := json.Unmarshal(second.Body.Bytes(), &response); err != nil || len(response.Data) != 1 || response.Data[0].ID != "cpa_2" || query.after == nil {
		t.Fatalf("second page=%s query=%#v error=%v", second.Body.String(), query, err)
	}
	for _, path := range []string{
		"/v1/customer-portal/access?page_size=0",
		"/v1/customer-portal/access?package_id=pkg_1&package_id=pkg_2",
		"/v1/customer-portal/access?sort=unknown",
	} {
		getRaw(t, server, secret, path, http.StatusBadRequest)
	}
	getRawNoAuth(t, server, "/v1/customer-portal/access", http.StatusUnauthorized)
	if query.calls != 2 {
		t.Fatalf("invalid request reached query %d times", query.calls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{packagequery.ErrPortalAccessValidation, http.StatusBadRequest},
		{packagequery.ErrPortalAccessNotFound, http.StatusNotFound},
		{packagequery.ErrPortalAccessProjection, http.StatusConflict},
		{application.ErrForbidden, http.StatusForbidden},
		{errors.New("private-portal-database-detail"), http.StatusInternalServerError},
	} {
		query.err = test.err
		result := getRaw(t, server, secret, "/v1/customer-portal/access", test.status)
		if strings.Contains(result.Body.String(), "private-portal-database-detail") {
			t.Fatalf("internal error leaked: %s", result.Body.String())
		}
	}
}
