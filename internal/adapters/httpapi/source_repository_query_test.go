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

type sourceRepositoryQueryFake struct {
	calls     int
	projectID string
	after     *appquery.SortKey
	err       error
}

func (f *sourceRepositoryQueryFake) ListPage(_ context.Context, actor identitydomain.Actor, projectID string, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[integrationdomain.SourceRepository], error) {
	f.calls++
	f.projectID, f.after = projectID, after
	if f.err != nil {
		return appquery.Result[integrationdomain.SourceRepository]{}, f.err
	}
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	item := integrationdomain.SourceRepository{ID: "repo_database", TenantID: actor.TenantID, ProjectID: projectID, Provider: "git", FullName: "team/repo", CloneURL: "https://example.invalid/repo", DefaultBranch: "main", SchemaVersion: "v1", CreatedAt: now}
	if after == nil {
		key := appquery.RecordSortKey(item.ID, now, page.Sort)
		return appquery.Result[integrationdomain.SourceRepository]{Items: []integrationdomain.SourceRepository{item}, Next: &key}, nil
	}
	item.ID = "repo_next"
	return appquery.Result[integrationdomain.SourceRepository]{Items: []integrationdomain.SourceRepository{item}}, nil
}

func TestSourceRepositoryHandlerUsesFocusedPageAndRejectsBadInput(t *testing.T) {
	server, secret := testServer(t)
	query := &sourceRepositoryQueryFake{}
	server.sourceRepositoryQuery = query
	first := getRaw(t, server, secret, "/v1/source/repositories?project_id=proj_1&page_size=1", http.StatusOK)
	var response struct {
		Data []struct {
			ID       string `json:"id"`
			CloneURL string `json:"clone_url"`
		} `json:"data"`
		Meta struct {
			NextCursor string `json:"next_cursor"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &response); err != nil || len(response.Data) != 1 || response.Data[0].ID != "repo_database" || response.Data[0].CloneURL != "https://example.invalid/repo" || response.Meta.NextCursor == "" || query.calls != 1 || query.projectID != "proj_1" {
		t.Fatalf("focused source repository page=%s query=%#v error=%v", first.Body.String(), query, err)
	}
	second := getRaw(t, server, secret, "/v1/source/repositories?project_id=proj_1&page_size=1&cursor="+url.QueryEscape(response.Meta.NextCursor), http.StatusOK)
	if err := json.Unmarshal(second.Body.Bytes(), &response); err != nil || len(response.Data) != 1 || response.Data[0].ID != "repo_next" || query.calls != 2 || query.after == nil {
		t.Fatalf("source repository continuation=%s query=%#v error=%v", second.Body.String(), query, err)
	}
	for _, path := range []string{
		"/v1/source/repositories?project_id=proj_1&project_id=proj_2",
		"/v1/source/repositories?project_id=%20",
		"/v1/source/repositories?page_size=0",
		"/v1/source/repositories?sort=unknown",
	} {
		getRaw(t, server, secret, path, http.StatusBadRequest)
	}
	getRawNoAuth(t, server, "/v1/source/repositories", http.StatusUnauthorized)
	if query.calls != 2 {
		t.Fatalf("unauthorized or invalid source read reached query %d times", query.calls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{err: integrationquery.ErrValidation, status: http.StatusBadRequest},
		{err: integrationquery.ErrInvalidProjection, status: http.StatusConflict},
		{err: application.ErrUnauthorized, status: http.StatusUnauthorized},
		{err: application.ErrForbidden, status: http.StatusForbidden},
		{err: errors.New("private-database-detail"), status: http.StatusInternalServerError},
	} {
		query.err = test.err
		result := getRaw(t, server, secret, "/v1/source/repositories", test.status)
		if strings.Contains(result.Body.String(), "private-database-detail") {
			t.Fatalf("internal detail leaked: %s", result.Body.String())
		}
	}
}
