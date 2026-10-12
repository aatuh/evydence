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
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

type exceptionQueryFake struct {
	calls     int
	releaseID string
	after     *appquery.SortKey
	err       error
}

func (f *exceptionQueryFake) ListPage(_ context.Context, actor identitydomain.Actor, releaseID string, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[riskdomain.Exception], error) {
	f.calls++
	f.releaseID, f.after = releaseID, after
	if f.err != nil {
		return appquery.Result[riskdomain.Exception]{}, f.err
	}
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	item := riskdomain.Exception{ID: "ex_1", TenantID: actor.TenantID, ReleaseID: releaseID, Reason: "reviewed", Owner: "security", ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if after != nil {
		item.ID = "ex_2"
		return appquery.Result[riskdomain.Exception]{Items: []riskdomain.Exception{item}}, nil
	}
	key := appquery.RecordSortKey(item.ID, item.CreatedAt, page.Sort)
	return appquery.Result[riskdomain.Exception]{Items: []riskdomain.Exception{item}, Next: &key}, nil
}

func TestExceptionsHandlerUsesFocusedScopedPageAndSafeErrors(t *testing.T) {
	server, secret := testServer(t)
	query := &exceptionQueryFake{}
	server.exceptionsQuery = query
	first := getRaw(t, server, secret, "/v1/exceptions?release_id=rel_1&page_size=1", http.StatusOK)
	var response struct {
		Data []struct {
			ID     string `json:"id"`
			Owner  string `json:"owner"`
			Reason string `json:"reason"`
		} `json:"data"`
		Meta struct {
			NextCursor string `json:"next_cursor"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &response); err != nil || len(response.Data) != 1 || response.Data[0].ID != "ex_1" || response.Data[0].Reason != "reviewed" || response.Data[0].Owner != "security" || response.Meta.NextCursor == "" || query.releaseID != "rel_1" {
		t.Fatalf("focused exception page=%s error=%v", first.Body.String(), err)
	}
	second := getRaw(t, server, secret, "/v1/exceptions?release_id=rel_1&page_size=1&cursor="+url.QueryEscape(response.Meta.NextCursor), http.StatusOK)
	if err := json.Unmarshal(second.Body.Bytes(), &response); err != nil || len(response.Data) != 1 || response.Data[0].ID != "ex_2" || query.after == nil {
		t.Fatalf("exception continuation=%s error=%v", second.Body.String(), err)
	}
	for _, path := range []string{
		"/v1/exceptions?release_id=rel_1&release_id=rel_2",
		"/v1/exceptions?release_id=%20",
		"/v1/exceptions?page_size=0",
		"/v1/exceptions?unknown=value",
	} {
		getRaw(t, server, secret, path, http.StatusBadRequest)
	}
	getRawNoAuth(t, server, "/v1/exceptions", http.StatusUnauthorized)
	if query.calls != 2 {
		t.Fatalf("invalid or unauthenticated request reached query %d times", query.calls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{riskquery.ErrValidation, http.StatusBadRequest},
		{riskquery.ErrNotFound, http.StatusNotFound},
		{riskquery.ErrInvalidProjection, http.StatusConflict},
		{application.ErrForbidden, http.StatusForbidden},
		{errors.New("private-database-detail"), http.StatusInternalServerError},
	} {
		query.err = test.err
		result := getRaw(t, server, secret, "/v1/exceptions", test.status)
		if strings.Contains(result.Body.String(), "private-database-detail") {
			t.Fatalf("internal detail leaked: %s", result.Body.String())
		}
	}
}
