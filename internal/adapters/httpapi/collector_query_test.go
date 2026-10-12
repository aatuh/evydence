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
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

type collectorQueryFake struct {
	calls int
	after *appquery.SortKey
	err   error
}

func (f *collectorQueryFake) ListPage(_ context.Context, actor identitydomain.Actor, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[integrationdomain.Collector], error) {
	f.calls++
	f.after = after
	if f.err != nil {
		return appquery.Result[integrationdomain.Collector]{}, f.err
	}
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	status, _ := integrationdomain.ParseCollectorStatus(integrationdomain.CollectorStatusActiveValue)
	item := integrationdomain.Collector{ID: "col_database", TenantID: actor.TenantID, Name: "collector", Type: "ci", Version: "1", APIKeyID: "key_1", Status: status, AllowedScopes: []string{"evidence:write"}, SchemaVersion: "collector.v1.0.0", CreatedAt: now}
	if after != nil {
		item.ID = "col_next"
		return appquery.Result[integrationdomain.Collector]{Items: []integrationdomain.Collector{item}}, nil
	}
	key := appquery.RecordSortKey(item.ID, now, page.Sort)
	return appquery.Result[integrationdomain.Collector]{Items: []integrationdomain.Collector{item}, Next: &key}, nil
}

func TestCollectorHandlerUsesDurablePageAndSafeErrors(t *testing.T) {
	server, secret := testServer(t)
	query := &collectorQueryFake{}
	server.collectorQuery = query
	first := getRaw(t, server, secret, "/v1/collectors?page_size=1", http.StatusOK)
	var response struct {
		Data []struct {
			ID            string   `json:"id"`
			APIKeyID      string   `json:"api_key_id"`
			AllowedScopes []string `json:"allowed_scopes"`
		} `json:"data"`
		Meta struct {
			NextCursor string `json:"next_cursor"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &response); err != nil || len(response.Data) != 1 || response.Data[0].ID != "col_database" || response.Data[0].APIKeyID != "key_1" || len(response.Data[0].AllowedScopes) != 1 || response.Meta.NextCursor == "" || query.calls != 1 {
		t.Fatalf("collector page=%s calls=%d error=%v", first.Body.String(), query.calls, err)
	}
	second := getRaw(t, server, secret, "/v1/collectors?page_size=1&cursor="+url.QueryEscape(response.Meta.NextCursor), http.StatusOK)
	if err := json.Unmarshal(second.Body.Bytes(), &response); err != nil || len(response.Data) != 1 || response.Data[0].ID != "col_next" || query.after == nil {
		t.Fatalf("collector continuation=%s query=%#v error=%v", second.Body.String(), query, err)
	}
	for _, path := range []string{
		"/v1/collectors?page_size=0",
		"/v1/collectors?sort=unknown",
		"/v1/collectors?page_size=1&page_size=2",
	} {
		getRaw(t, server, secret, path, http.StatusBadRequest)
	}
	getRawNoAuth(t, server, "/v1/collectors", http.StatusUnauthorized)
	if query.calls != 2 {
		t.Fatalf("invalid or unauthenticated request reached query %d times", query.calls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{integrationquery.ErrValidation, http.StatusBadRequest},
		{integrationquery.ErrInvalidProjection, http.StatusConflict},
		{application.ErrUnauthorized, http.StatusUnauthorized},
		{application.ErrForbidden, http.StatusForbidden},
		{errors.New("private-database-detail"), http.StatusInternalServerError},
	} {
		query.err = test.err
		result := getRaw(t, server, secret, "/v1/collectors", test.status)
		if strings.Contains(result.Body.String(), "private-database-detail") {
			t.Fatalf("database error leaked: %s", result.Body.String())
		}
	}
}
