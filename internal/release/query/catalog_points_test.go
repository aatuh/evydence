package query

import (
	"context"
	"errors"
	"testing"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type catalogPointReaderFake struct {
	project releasedomain.Project
	release releasedomain.Release
	err     error
	tenant  string
	id      string
	calls   int
}

func (f *catalogPointReaderFake) GetProject(_ context.Context, tenantID, id string) (releasedomain.Project, error) {
	f.tenant, f.id = tenantID, id
	f.calls++
	return f.project, f.err
}

func (f *catalogPointReaderFake) GetRelease(_ context.Context, tenantID, id string) (releasedomain.Release, error) {
	f.tenant, f.id = tenantID, id
	f.calls++
	return f.release, f.err
}

type catalogPointAuthorizerFake struct {
	allow     bool
	denyScope bool
	seen      []application.AuthorizationRequest
}

func (f *catalogPointAuthorizerFake) Authorize(_ context.Context, _ identitydomain.Actor, request application.AuthorizationRequest) error {
	f.seen = append(f.seen, request)
	if request.ScopeOnly && f.denyScope {
		return application.ErrForbidden
	}
	if request.ScopeOnly || f.allow {
		return nil
	}
	return application.ErrForbidden
}

func TestCatalogPointQueriesAuthorizeTenantBoundProjectAndRelease(t *testing.T) {
	createdAt := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	frozen, err := releasedomain.ParseReleaseState(releasedomain.ReleaseStateFrozenValue)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		scope string
		id    string
	}{
		{name: "project", scope: "project:read", id: "proj_allowed"},
		{name: "release", scope: "release:read", id: "rel_allowed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &catalogPointReaderFake{
				project: releasedomain.Project{ID: "proj_allowed", TenantID: "ten_1", ProductID: "prod_1", CreatedAt: createdAt},
				release: releasedomain.Release{ID: "rel_allowed", TenantID: "ten_1", ProductID: "prod_1", Revision: 2, State: frozen, CreatedAt: createdAt},
			}
			authorizer := &catalogPointAuthorizerFake{allow: true}
			service, err := NewCatalogPoints(reader, authorizer)
			if err != nil {
				t.Fatal(err)
			}
			actor := identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1"}
			if test.name == "project" {
				project, err := service.GetProject(t.Context(), actor, test.id)
				if err != nil || project.ID != test.id || project.ProductID != "prod_1" {
					t.Fatalf("project=%#v error=%v", project, err)
				}
			} else {
				release, err := service.GetRelease(t.Context(), actor, test.id)
				if err != nil || release.ID != test.id || release.Revision != 2 || release.State != frozen {
					t.Fatalf("release=%#v error=%v", release, err)
				}
			}
			if reader.tenant != actor.TenantID || reader.id != test.id || reader.calls != 1 || len(authorizer.seen) != 2 {
				t.Fatalf("query scope reader=%#v authorizations=%#v", reader, authorizer.seen)
			}
			if first, last := authorizer.seen[0], authorizer.seen[1]; first.Scope != test.scope || !first.ScopeOnly || last.Scope != test.scope || last.ScopeOnly || last.Resources.ProductID != "prod_1" {
				t.Fatalf("authorization sequence=%#v", authorizer.seen)
			}
			if last := authorizer.seen[1]; (test.name == "project" && (last.Resources.ProjectID != test.id || last.Resources.ReleaseID != "")) || (test.name == "release" && (last.Resources.ReleaseID != test.id || last.Resources.ProjectID != "")) {
				t.Fatalf("resource authorization coordinates=%#v", last.Resources)
			}
		})
	}
}

func TestCatalogPointQueriesFailClosedOnForeignAndRevokedResources(t *testing.T) {
	for _, test := range []struct {
		name    string
		project releasedomain.Project
		release releasedomain.Release
		allow   bool
	}{
		{name: "foreign project", project: releasedomain.Project{ID: "proj_1", TenantID: "ten_2", ProductID: "prod_1"}, allow: true},
		{name: "wrong project id", project: releasedomain.Project{ID: "proj_2", TenantID: "ten_1", ProductID: "prod_1"}, allow: true},
		{name: "project without product", project: releasedomain.Project{ID: "proj_1", TenantID: "ten_1"}, allow: true},
		{name: "revoked project grant", project: releasedomain.Project{ID: "proj_1", TenantID: "ten_1", ProductID: "prod_1"}},
		{name: "foreign release", release: releasedomain.Release{ID: "rel_1", TenantID: "ten_2", ProductID: "prod_1"}, allow: true},
		{name: "wrong release id", release: releasedomain.Release{ID: "rel_2", TenantID: "ten_1", ProductID: "prod_1"}, allow: true},
		{name: "release without product", release: releasedomain.Release{ID: "rel_1", TenantID: "ten_1"}, allow: true},
		{name: "revoked release grant", release: releasedomain.Release{ID: "rel_1", TenantID: "ten_1", ProductID: "prod_1"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &catalogPointReaderFake{project: test.project, release: test.release}
			service, err := NewCatalogPoints(reader, &catalogPointAuthorizerFake{allow: test.allow})
			if err != nil {
				t.Fatal(err)
			}
			actor := identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1"}
			if test.project.ID != "" {
				project, err := service.GetProject(t.Context(), actor, "proj_1")
				if err == nil || project.ID != "" {
					t.Fatalf("unsafe project=%#v error=%v", project, err)
				}
			} else {
				release, err := service.GetRelease(t.Context(), actor, "rel_1")
				if err == nil || release.ID != "" {
					t.Fatalf("unsafe release=%#v error=%v", release, err)
				}
			}
		})
	}
}

func TestCatalogPointQueriesRejectMissingScopeAndInvalidCoordinatesBeforeRead(t *testing.T) {
	reader := &catalogPointReaderFake{project: releasedomain.Project{ID: "proj_1", TenantID: "ten_1", ProductID: "prod_1"}}
	authorizer := &catalogPointAuthorizerFake{allow: true}
	service, err := NewCatalogPoints(reader, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	if project, err := service.GetProject(t.Context(), identitydomain.Actor{}, "proj_1"); !errors.Is(err, ErrValidation) || project.ID != "" || reader.calls != 0 {
		t.Fatalf("missing tenant project=%#v calls=%d error=%v", project, reader.calls, err)
	}
	if release, err := service.GetRelease(t.Context(), identitydomain.Actor{TenantID: "ten_1"}, " "); !errors.Is(err, ErrNotFound) || release.ID != "" || reader.calls != 0 {
		t.Fatalf("blank release=%#v calls=%d error=%v", release, reader.calls, err)
	}
	denied, err := NewCatalogPoints(reader, &catalogPointAuthorizerFake{denyScope: true})
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1"}
	if project, err := denied.GetProject(t.Context(), actor, "proj_1"); !errors.Is(err, application.ErrForbidden) || project.ID != "" || reader.calls != 0 {
		t.Fatalf("project scope denial=%#v calls=%d error=%v", project, reader.calls, err)
	}
	if release, err := denied.GetRelease(t.Context(), actor, "rel_1"); !errors.Is(err, application.ErrForbidden) || release.ID != "" || reader.calls != 0 {
		t.Fatalf("release scope denial=%#v calls=%d error=%v", release, reader.calls, err)
	}
	if _, err := NewCatalogPoints(nil, authorizer); !errors.Is(err, ErrValidation) {
		t.Fatalf("nil reader error=%v", err)
	}
	if _, err := NewCatalogPoints(reader, nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("nil authorizer error=%v", err)
	}
}
