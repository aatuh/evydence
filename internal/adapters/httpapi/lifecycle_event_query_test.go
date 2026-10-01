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
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type lifecycleEventsQueryFake struct {
	calls int
	id    string
	after *appquery.SortKey
	err   error
}

func (f *lifecycleEventsQueryFake) ListPage(_ context.Context, _ identitydomain.Actor, id string, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[evidencedomain.EvidenceLifecycleEvent], error) {
	f.calls++
	f.id, f.after = id, after
	if f.err != nil {
		return appquery.Result[evidencedomain.EvidenceLifecycleEvent]{}, f.err
	}
	action, _ := evidencedomain.ParseEvidenceLifecycleState("amendment")
	event := evidencedomain.EvidenceLifecycleEvent{
		ID: "life_1", TenantID: "ten_1", EvidenceID: id, Action: action,
		Reason: "api_key=secret-value", Details: map[string]any{"secret": "hidden", "note": "visible", evidencedomain.LegacyCanonicalOriginDetailKey: "internal"},
		ActorID: "usr_1", SchemaVersion: "evidence-lifecycle.v1", CreatedAt: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC),
	}
	if after != nil {
		event.ID = "life_2"
		return appquery.Result[evidencedomain.EvidenceLifecycleEvent]{Items: []evidencedomain.EvidenceLifecycleEvent{event}}, nil
	}
	key := appquery.RecordSortKey(event.ID, event.CreatedAt, page.Sort)
	return appquery.Result[evidencedomain.EvidenceLifecycleEvent]{Items: []evidencedomain.EvidenceLifecycleEvent{event}, Next: &key}, nil
}

func TestLifecycleEventsHandlerUsesScopedPageAndRedactsDetails(t *testing.T) {
	server, secret := testServer(t)
	query := &lifecycleEventsQueryFake{}
	server.lifecycleEventsQuery = query
	fallback := &evidenceProjectionFallbackFake{}
	server.evidenceIngestion = fallback
	first := getRaw(t, server, secret, "/v1/evidence/ev_1/lifecycle-events?page_size=1", http.StatusOK)
	var response struct {
		Data []struct {
			ID      string         `json:"id"`
			Reason  string         `json:"reason"`
			Details map[string]any `json:"details"`
		} `json:"data"`
		Meta struct {
			NextCursor string `json:"next_cursor"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &response); err != nil || len(response.Data) != 1 || response.Data[0].ID != "life_1" || response.Meta.NextCursor == "" || query.id != "ev_1" {
		t.Fatalf("focused event page=%s error=%v", first.Body.String(), err)
	}
	if strings.Contains(first.Body.String(), "secret-value") || strings.Contains(first.Body.String(), "hidden") || strings.Contains(first.Body.String(), evidencedomain.LegacyCanonicalOriginDetailKey) || response.Data[0].Details["note"] != "visible" {
		t.Fatalf("sensitive lifecycle output=%s", first.Body.String())
	}
	second := getRaw(t, server, secret, "/v1/evidence/ev_1/lifecycle-events?page_size=1&cursor="+url.QueryEscape(response.Meta.NextCursor), http.StatusOK)
	if err := json.Unmarshal(second.Body.Bytes(), &response); err != nil || len(response.Data) != 1 || response.Data[0].ID != "life_2" || query.after == nil {
		t.Fatalf("continuation=%s error=%v", second.Body.String(), err)
	}
	for _, path := range []string{
		"/v1/evidence/ev_1/lifecycle-events?page_size=0",
		"/v1/evidence/ev_1/lifecycle-events?page_size=1&page_size=2",
		"/v1/evidence/ev_1/lifecycle-events?unknown=value",
	} {
		getRaw(t, server, secret, path, http.StatusBadRequest)
	}
	getRawNoAuth(t, server, "/v1/evidence/ev_1/lifecycle-events", http.StatusUnauthorized)
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
		result := getRaw(t, server, secret, "/v1/evidence/ev_1/lifecycle-events", test.status)
		if strings.Contains(result.Body.String(), "private-database-detail") {
			t.Fatalf("internal detail leaked: %s", result.Body.String())
		}
	}
	query.err = evidencequery.ErrConflict
	getRaw(t, server, secret, "/v1/evidence/ev_worker/lifecycle-events", http.StatusConflict)
	if fallback.lifecycleCalls != 0 {
		t.Fatal("focused lifecycle query used compatibility aggregate")
	}
	server.lifecycleEventsQuery = nil
	getRaw(t, server, secret, "/v1/evidence/ev_local/lifecycle-events", http.StatusOK)
	if fallback.lifecycleCalls != 1 {
		t.Fatal("explicit local-memory lifecycle path removed")
	}
}
