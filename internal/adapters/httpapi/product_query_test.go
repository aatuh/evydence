package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type productPageQueryFake struct {
	calls  int
	tenant string
	after  *appquery.SortKey
}

func (f *productPageQueryFake) ListProductsPage(_ context.Context, actor identitydomain.Actor, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[releasedomain.Product], error) {
	f.calls++
	f.tenant = actor.TenantID
	f.after = after
	createdAt := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	if after == nil {
		key := appquery.RecordSortKey("prod_a", createdAt, page.Sort)
		return appquery.Result[releasedomain.Product]{Items: []releasedomain.Product{{ID: "prod_a", TenantID: actor.TenantID, Name: "A", CreatedAt: createdAt}}, Next: &key}, nil
	}
	return appquery.Result[releasedomain.Product]{Items: []releasedomain.Product{{ID: "prod_b", TenantID: actor.TenantID, Name: "B", CreatedAt: createdAt.Add(time.Second)}}}, nil
}

func TestProductHandlerUsesFocusedPageQueryAndRejectsMalformedInputBeforeRead(t *testing.T) {
	server, secret := testServer(t)
	query := &productPageQueryFake{}
	server.productPages = query
	first := getRaw(t, server, secret, "/v1/products?page_size=1&sort=created_at&direction=asc", http.StatusOK)
	var response struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Meta struct {
			NextCursor string `json:"next_cursor"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &response); err != nil || len(response.Data) != 1 || response.Data[0].ID != "prod_a" || response.Meta.NextCursor == "" || query.calls != 1 || query.tenant == "" {
		t.Fatalf("focused first page=%#v calls=%d tenant=%q error=%v", response, query.calls, query.tenant, err)
	}
	second := getRaw(t, server, secret, "/v1/products?page_size=1&sort=created_at&direction=asc&cursor="+url.QueryEscape(response.Meta.NextCursor), http.StatusOK)
	if err := json.Unmarshal(second.Body.Bytes(), &response); err != nil || len(response.Data) != 1 || response.Data[0].ID != "prod_b" || query.calls != 2 || query.after == nil {
		t.Fatalf("focused continuation=%#v calls=%d after=%#v error=%v", response, query.calls, query.after, err)
	}
	getRaw(t, server, secret, "/v1/products?page_size=1&page_size=2", http.StatusBadRequest)
	if query.calls != 2 {
		t.Fatalf("malformed page reached focused query: calls=%d", query.calls)
	}
}
