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

type controlsQueryFake struct {
	pageCalls  int
	pointCalls int
	after      *appquery.SortKey
	err        error
}

func (f *controlsQueryFake) ListFrameworksPage(_ context.Context, actor identitydomain.Actor, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[riskdomain.ControlFramework], error) {
	f.pageCalls++
	f.after = after
	if f.err != nil {
		return appquery.Result[riskdomain.ControlFramework]{}, f.err
	}
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	item := riskdomain.ControlFramework{ID: "fw_database", TenantID: actor.TenantID, Name: "Framework", Slug: "framework", Version: "1", Status: "active", CreatedAt: now}
	if after != nil {
		item.ID = "fw_next"
		return appquery.Result[riskdomain.ControlFramework]{Items: []riskdomain.ControlFramework{item}}, nil
	}
	key := appquery.RecordSortKey(item.ID, now, page.Sort)
	return appquery.Result[riskdomain.ControlFramework]{Items: []riskdomain.ControlFramework{item}, Next: &key}, nil
}

func (f *controlsQueryFake) GetSecurityControl(_ context.Context, actor identitydomain.Actor, id string) (riskdomain.SecurityControl, error) {
	f.pointCalls++
	if f.err != nil {
		return riskdomain.SecurityControl{}, f.err
	}
	return riskdomain.SecurityControl{ID: id, TenantID: actor.TenantID, FrameworkID: "fw_database", Code: "BUILD", Title: "Build evidence", EvidenceRequirements: []riskdomain.ControlEvidenceRequirement{{Type: "build", FreshnessDays: 7, Required: true}}}, nil
}

func TestControlsHandlersUseFocusedQueriesAndSafeErrors(t *testing.T) {
	server, secret := testServer(t)
	query := &controlsQueryFake{}
	server.controlsQuery = query
	first := getRaw(t, server, secret, "/v1/control-frameworks?page_size=1", http.StatusOK)
	var response struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Meta struct {
			NextCursor string `json:"next_cursor"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &response); err != nil || len(response.Data) != 1 || response.Data[0].ID != "fw_database" || response.Meta.NextCursor == "" || query.pageCalls != 1 {
		t.Fatalf("framework page=%s calls=%d error=%v", first.Body.String(), query.pageCalls, err)
	}
	second := getRaw(t, server, secret, "/v1/control-frameworks?page_size=1&cursor="+url.QueryEscape(response.Meta.NextCursor), http.StatusOK)
	if err := json.Unmarshal(second.Body.Bytes(), &response); err != nil || len(response.Data) != 1 || response.Data[0].ID != "fw_next" || query.after == nil {
		t.Fatalf("framework continuation=%s query=%#v error=%v", second.Body.String(), query, err)
	}
	point := getRaw(t, server, secret, "/v1/controls/ctrl_database", http.StatusOK)
	if !strings.Contains(point.Body.String(), `"id":"ctrl_database"`) || !strings.Contains(point.Body.String(), `"freshness_days":7`) || query.pointCalls != 1 {
		t.Fatalf("control point=%s calls=%d", point.Body.String(), query.pointCalls)
	}
	for _, path := range []string{
		"/v1/control-frameworks?page_size=0",
		"/v1/control-frameworks?sort=unknown",
		"/v1/control-frameworks?page_size=1&page_size=2",
	} {
		getRaw(t, server, secret, path, http.StatusBadRequest)
	}
	getRawNoAuth(t, server, "/v1/control-frameworks", http.StatusUnauthorized)
	if query.pageCalls != 2 {
		t.Fatalf("invalid request reached framework query %d times", query.pageCalls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{riskquery.ErrValidation, http.StatusBadRequest},
		{riskquery.ErrNotFound, http.StatusNotFound},
		{riskquery.ErrInvalidProjection, http.StatusConflict},
		{application.ErrUnauthorized, http.StatusUnauthorized},
		{application.ErrForbidden, http.StatusForbidden},
		{errors.New("private-database-detail"), http.StatusInternalServerError},
	} {
		query.err = test.err
		result := getRaw(t, server, secret, "/v1/controls/ctrl_database", test.status)
		if strings.Contains(result.Body.String(), "private-database-detail") {
			t.Fatalf("database error leaked: %s", result.Body.String())
		}
	}
}
