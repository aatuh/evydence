package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

type catalogPointQueryFake struct {
	projectTenant string
	projectID     string
	releaseTenant string
	releaseID     string
	projectErr    error
	releaseErr    error
}

func (f *catalogPointQueryFake) GetProject(_ context.Context, actor identitydomain.Actor, id string) (releasedomain.Project, error) {
	f.projectTenant, f.projectID = actor.TenantID, id
	if f.projectErr != nil {
		return releasedomain.Project{}, f.projectErr
	}
	return releasedomain.Project{ID: id, TenantID: actor.TenantID, ProductID: "prod_database", Name: "Database project"}, nil
}

func (f *catalogPointQueryFake) GetRelease(_ context.Context, actor identitydomain.Actor, id string) (releasedomain.Release, error) {
	f.releaseTenant, f.releaseID = actor.TenantID, id
	if f.releaseErr != nil {
		return releasedomain.Release{}, f.releaseErr
	}
	state, _ := releasedomain.ParseReleaseState(releasedomain.ReleaseStateFrozenValue)
	return releasedomain.Release{ID: id, TenantID: actor.TenantID, ProductID: "prod_database", Version: "1.0.0", Revision: 2, State: state}, nil
}

func TestCatalogPointHandlersMapValidationAndVisibilityErrors(t *testing.T) {
	for _, test := range []struct {
		name   string
		path   string
		err    error
		status int
	}{
		{name: "project not found", path: "/v1/projects/proj_missing", err: releasequery.ErrNotFound, status: http.StatusNotFound},
		{name: "project denied", path: "/v1/projects/proj_denied", err: application.ErrForbidden, status: http.StatusForbidden},
		{name: "project missing identity", path: "/v1/projects/proj_unauthorized", err: application.ErrUnauthorized, status: http.StatusUnauthorized},
		{name: "release not found", path: "/v1/releases/rel_missing", err: releasequery.ErrNotFound, status: http.StatusNotFound},
		{name: "release denied", path: "/v1/releases/rel_denied", err: application.ErrForbidden, status: http.StatusForbidden},
		{name: "release missing identity", path: "/v1/releases/rel_unauthorized", err: application.ErrUnauthorized, status: http.StatusUnauthorized},
		{name: "invalid release", path: "/v1/releases/rel_invalid", err: releasequery.ErrValidation, status: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, secret := testServer(t)
			query := &catalogPointQueryFake{projectErr: test.err, releaseErr: test.err}
			server.catalogPointQuery = query
			getRaw(t, server, secret, test.path, test.status)
		})
	}
}

func TestCatalogPointHandlersUseFocusedQueries(t *testing.T) {
	server, secret := testServer(t)
	query := &catalogPointQueryFake{}
	server.catalogPointQuery = query
	projectResponse := getRaw(t, server, secret, "/v1/projects/proj_database_only", http.StatusOK)
	var project struct {
		Data struct {
			ID        string `json:"id"`
			ProductID string `json:"product_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(projectResponse.Body.Bytes(), &project); err != nil || project.Data.ID != "proj_database_only" || project.Data.ProductID != "prod_database" || query.projectTenant == "" || query.projectID != "proj_database_only" {
		t.Fatalf("focused project=%#v query=%#v error=%v", project, query, err)
	}
	releaseResponse := getRaw(t, server, secret, "/v1/releases/rel_database_only", http.StatusOK)
	var release struct {
		Data struct {
			ID       string `json:"id"`
			Revision int64  `json:"revision"`
			State    string `json:"state"`
		} `json:"data"`
	}
	if err := json.Unmarshal(releaseResponse.Body.Bytes(), &release); err != nil || release.Data.ID != "rel_database_only" || release.Data.Revision != 2 || release.Data.State != releasedomain.ReleaseStateFrozenValue || query.releaseTenant == "" || query.releaseID != "rel_database_only" {
		t.Fatalf("focused release=%#v query=%#v error=%v", release, query, err)
	}
}
