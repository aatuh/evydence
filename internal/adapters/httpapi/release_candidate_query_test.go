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
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

type releaseCandidateQueryFake struct {
	pageCalls  int
	pointCalls int
	releaseID  string
	after      *appquery.SortKey
	err        error
}

func (f *releaseCandidateQueryFake) ListPage(_ context.Context, actor identitydomain.Actor, releaseID string, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[releasedomain.ReleaseCandidate], error) {
	f.pageCalls++
	f.releaseID, f.after = releaseID, after
	if f.err != nil {
		return appquery.Result[releasedomain.ReleaseCandidate]{}, f.err
	}
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	state, _ := releasedomain.ParseReleaseCandidateState(releasedomain.ReleaseCandidateStateOpenValue)
	item := releasedomain.ReleaseCandidate{ID: "cand_database", TenantID: actor.TenantID, ReleaseID: releaseID, Name: "candidate", Revision: 1, State: state, BuildIDs: []string{"bld_1"}, SnapshotHash: "sha256:test", SchemaVersion: "release-candidate.v1.0.0", CreatedAt: now}
	if after != nil {
		item.ID = "cand_next"
		return appquery.Result[releasedomain.ReleaseCandidate]{Items: []releasedomain.ReleaseCandidate{item}}, nil
	}
	key := appquery.RecordSortKey(item.ID, now, page.Sort)
	return appquery.Result[releasedomain.ReleaseCandidate]{Items: []releasedomain.ReleaseCandidate{item}, Next: &key}, nil
}

func (f *releaseCandidateQueryFake) GetReleaseCandidate(_ context.Context, actor identitydomain.Actor, id string) (releasedomain.ReleaseCandidate, error) {
	f.pointCalls++
	if f.err != nil {
		return releasedomain.ReleaseCandidate{}, f.err
	}
	state, _ := releasedomain.ParseReleaseCandidateState(releasedomain.ReleaseCandidateStateOpenValue)
	return releasedomain.ReleaseCandidate{ID: id, TenantID: actor.TenantID, ReleaseID: "rel_1", State: state}, nil
}

func TestReleaseCandidateHandlersUseFocusedQueriesAndSafeErrors(t *testing.T) {
	server, secret := testServer(t)
	query := &releaseCandidateQueryFake{}
	server.releaseCandidateQuery = query
	first := getRaw(t, server, secret, "/v1/release-candidates?release_id=rel_1&page_size=1", http.StatusOK)
	var response struct {
		Data []struct {
			ID       string   `json:"id"`
			Revision int64    `json:"revision"`
			BuildIDs []string `json:"build_ids"`
		} `json:"data"`
		Meta struct {
			NextCursor string `json:"next_cursor"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &response); err != nil || len(response.Data) != 1 || response.Data[0].ID != "cand_database" || response.Data[0].Revision != 1 || len(response.Data[0].BuildIDs) != 1 || response.Meta.NextCursor == "" || query.pageCalls != 1 || query.releaseID != "rel_1" {
		t.Fatalf("focused candidate page=%s query=%#v error=%v", first.Body.String(), query, err)
	}
	second := getRaw(t, server, secret, "/v1/release-candidates?release_id=rel_1&page_size=1&cursor="+url.QueryEscape(response.Meta.NextCursor), http.StatusOK)
	if err := json.Unmarshal(second.Body.Bytes(), &response); err != nil || len(response.Data) != 1 || response.Data[0].ID != "cand_next" || query.after == nil {
		t.Fatalf("candidate continuation=%s query=%#v error=%v", second.Body.String(), query, err)
	}
	point := getRaw(t, server, secret, "/v1/release-candidates/cand_database", http.StatusOK)
	if !strings.Contains(point.Body.String(), `"id":"cand_database"`) || query.pointCalls != 1 {
		t.Fatalf("candidate point=%s calls=%d", point.Body.String(), query.pointCalls)
	}
	for _, path := range []string{
		"/v1/release-candidates?release_id=rel_1&release_id=rel_2",
		"/v1/release-candidates?release_id=%20",
		"/v1/release-candidates?page_size=0",
		"/v1/release-candidates?sort=unknown",
	} {
		getRaw(t, server, secret, path, http.StatusBadRequest)
	}
	getRawNoAuth(t, server, "/v1/release-candidates", http.StatusUnauthorized)
	if query.pageCalls != 2 {
		t.Fatalf("invalid request reached candidate query %d times", query.pageCalls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{releasequery.ErrValidation, http.StatusBadRequest},
		{releasequery.ErrNotFound, http.StatusNotFound},
		{releasequery.ErrInvalidProjection, http.StatusConflict},
		{application.ErrUnauthorized, http.StatusUnauthorized},
		{application.ErrForbidden, http.StatusForbidden},
		{errors.New("private-database-detail"), http.StatusInternalServerError},
	} {
		query.err = test.err
		result := getRaw(t, server, secret, "/v1/release-candidates/cand_database", test.status)
		if strings.Contains(result.Body.String(), "private-database-detail") {
			t.Fatalf("internal detail leaked: %s", result.Body.String())
		}
	}
}
