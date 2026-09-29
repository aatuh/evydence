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
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

type deploymentListQueryFake struct {
	envCalls, depCalls int
	envProduct         string
	depRelease         string
	depEnvironment     string
	after              *appquery.SortKey
	err                error
}

func (f *deploymentListQueryFake) ListEnvironmentsPage(_ context.Context, actor identitydomain.Actor, productID string, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[operationsdomain.DeploymentEnvironment], error) {
	f.envCalls++
	f.envProduct = productID
	f.after = after
	if f.err != nil {
		return appquery.Result[operationsdomain.DeploymentEnvironment]{}, f.err
	}
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	return appquery.Result[operationsdomain.DeploymentEnvironment]{Items: []operationsdomain.DeploymentEnvironment{{ID: "env_database", TenantID: actor.TenantID, ProductID: "prod_1", Name: "production", Kind: "production", CreatedAt: now}}}, nil
}

func (f *deploymentListQueryFake) ListDeploymentsPage(_ context.Context, actor identitydomain.Actor, releaseID, environmentID string, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[operationsdomain.DeploymentEvent], error) {
	f.depCalls++
	f.depRelease, f.depEnvironment = releaseID, environmentID
	f.after = after
	if f.err != nil {
		return appquery.Result[operationsdomain.DeploymentEvent]{}, f.err
	}
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	item := operationsdomain.DeploymentEvent{ID: "dep_database", TenantID: actor.TenantID, ReleaseID: "rel_1", EnvironmentID: "env_1", ArtifactIDs: []string{"art_1"}, Status: "succeeded", StartedAt: now, CreatedAt: now}
	if after == nil {
		key := appquery.RecordSortKey(item.ID, now, page.Sort)
		return appquery.Result[operationsdomain.DeploymentEvent]{Items: []operationsdomain.DeploymentEvent{item}, Next: &key}, nil
	}
	item.ID = "dep_next"
	return appquery.Result[operationsdomain.DeploymentEvent]{Items: []operationsdomain.DeploymentEvent{item}}, nil
}

func TestDeploymentListHandlersUseFocusedPagesAndRejectMalformedQueries(t *testing.T) {
	server, secret := testServer(t)
	query := &deploymentListQueryFake{}
	server.deploymentListQuery = query
	environments := getRaw(t, server, secret, "/v1/environments?product_id=prod_1&page_size=1", http.StatusOK)
	if !strings.Contains(environments.Body.String(), `"env_database"`) || query.envCalls != 1 || query.envProduct != "prod_1" {
		t.Fatalf("focused environments=%s query=%#v", environments.Body.String(), query)
	}
	first := getRaw(t, server, secret, "/v1/deployments?release_id=rel_1&environment_id=env_1&page_size=1", http.StatusOK)
	var body struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Meta struct {
			NextCursor string `json:"next_cursor"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &body); err != nil || len(body.Data) != 1 || body.Data[0].ID != "dep_database" || body.Meta.NextCursor == "" || query.depCalls != 1 || query.depRelease != "rel_1" || query.depEnvironment != "env_1" {
		t.Fatalf("focused first deployment page=%s query=%#v error=%v", first.Body.String(), query, err)
	}
	second := getRaw(t, server, secret, "/v1/deployments?release_id=rel_1&environment_id=env_1&page_size=1&cursor="+url.QueryEscape(body.Meta.NextCursor), http.StatusOK)
	if err := json.Unmarshal(second.Body.Bytes(), &body); err != nil || len(body.Data) != 1 || body.Data[0].ID != "dep_next" || query.after == nil || query.depCalls != 2 {
		t.Fatalf("focused continuation=%s query=%#v error=%v", second.Body.String(), query, err)
	}
	for _, path := range []string{
		"/v1/deployments?release_id=rel_1&release_id=rel_2",
		"/v1/deployments?page_size=0",
		"/v1/deployments?environment_id=%20",
		"/v1/environments?product_id=prod_1&product_id=prod_2",
	} {
		getRaw(t, server, secret, path, http.StatusBadRequest)
	}
	if query.envCalls != 1 || query.depCalls != 2 {
		t.Fatalf("malformed input reached storage: environments=%d deployments=%d", query.envCalls, query.depCalls)
	}
	getRawNoAuth(t, server, "/v1/deployments", http.StatusUnauthorized)
	getRawNoAuth(t, server, "/v1/environments", http.StatusUnauthorized)
	if query.envCalls != 1 || query.depCalls != 2 {
		t.Fatalf("unauthenticated input reached storage: environments=%d deployments=%d", query.envCalls, query.depCalls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{err: operationsquery.ErrValidation, status: http.StatusBadRequest},
		{err: operationsquery.ErrInvalidProjection, status: http.StatusConflict},
		{err: application.ErrUnauthorized, status: http.StatusUnauthorized},
		{err: application.ErrForbidden, status: http.StatusForbidden},
		{err: errors.New("postgres-private-detail"), status: http.StatusInternalServerError},
	} {
		query.err = test.err
		for _, path := range []string{"/v1/deployments", "/v1/environments"} {
			response := getRaw(t, server, secret, path, test.status)
			if strings.Contains(response.Body.String(), "postgres-private-detail") {
				t.Fatalf("internal detail leaked: %s", response.Body.String())
			}
		}
	}
}
