package query

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type buildPointReaderFake struct {
	point  BuildPoint
	err    error
	tenant string
	id     string
	calls  int
}

func (f *buildPointReaderFake) GetBuildPoint(_ context.Context, tenantID, id string) (BuildPoint, error) {
	f.tenant, f.id = tenantID, id
	f.calls++
	return f.point, f.err
}

func TestBuildPointAuthorizesTenantBoundCoordinates(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	reader := &buildPointReaderFake{point: BuildPoint{Build: releasedomain.BuildRun{
		ID: "bld_1", TenantID: "ten_1", ProjectID: "proj_1", ReleaseID: "rel_1",
		Provider: "github", CommitSHA: "0123456789abcdef", Status: "completed",
		StartedAt: now, CreatedAt: now,
	}, ProductID: "prod_1"}}
	service, err := NewBuildPoints(reader, NewCatalogAuthorizer())
	if err != nil {
		t.Fatal(err)
	}
	actor := catalogActor("build:read", "project", "proj_1", "build:read")
	build, err := service.GetBuildRun(t.Context(), actor, "bld_1")
	if err != nil || build.ID != "bld_1" || reader.tenant != actor.TenantID || reader.id != "bld_1" || reader.calls != 1 {
		t.Fatalf("build=%#v reader=%#v error=%v", build, reader, err)
	}
	actor.ResourceGrants[0].ResourceID = "proj_other"
	if build, err := service.GetBuildRun(t.Context(), actor, "bld_1"); !errors.Is(err, application.ErrForbidden) || build.ID != "" {
		t.Fatalf("wrong-project build=%#v error=%v", build, err)
	}
	actor.Scopes = []string{"release:read"}
	if build, err := service.GetBuildRun(t.Context(), actor, "bld_1"); !errors.Is(err, application.ErrForbidden) || build.ID != "" {
		t.Fatalf("missing-scope build=%#v error=%v", build, err)
	}
}

func TestBuildPointRejectsForeignOrInconsistentProjection(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"build:read"}}
	for _, test := range []struct {
		name  string
		point BuildPoint
	}{
		{name: "foreign tenant", point: BuildPoint{Build: releasedomain.BuildRun{ID: "bld_1", TenantID: "ten_other", ProjectID: "proj_1", ReleaseID: "rel_1", StartedAt: now, CreatedAt: now}, ProductID: "prod_1"}},
		{name: "wrong build", point: BuildPoint{Build: releasedomain.BuildRun{ID: "bld_other", TenantID: "ten_1", ProjectID: "proj_1", ReleaseID: "rel_1", StartedAt: now, CreatedAt: now}, ProductID: "prod_1"}},
		{name: "missing product", point: BuildPoint{Build: releasedomain.BuildRun{ID: "bld_1", TenantID: "ten_1", ProjectID: "proj_1", ReleaseID: "rel_1", StartedAt: now, CreatedAt: now}}},
		{name: "missing project", point: BuildPoint{Build: releasedomain.BuildRun{ID: "bld_1", TenantID: "ten_1", ReleaseID: "rel_1", StartedAt: now, CreatedAt: now}, ProductID: "prod_1"}},
		{name: "missing release", point: BuildPoint{Build: releasedomain.BuildRun{ID: "bld_1", TenantID: "ten_1", ProjectID: "proj_1", StartedAt: now, CreatedAt: now}, ProductID: "prod_1"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &buildPointReaderFake{point: test.point}
			service, err := NewBuildPoints(reader, NewCatalogAuthorizer())
			if err != nil {
				t.Fatal(err)
			}
			if build, err := service.GetBuildRun(t.Context(), actor, "bld_1"); !errors.Is(err, ErrNotFound) || build.ID != "" {
				t.Fatalf("unsafe build=%#v error=%v", build, err)
			}
		})
	}
	if _, err := NewBuildPoints(nil, NewCatalogAuthorizer()); !errors.Is(err, ErrValidation) {
		t.Fatalf("nil reader error=%v", err)
	}
	if _, err := NewBuildPoints(&buildPointReaderFake{}, nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("nil authorizer error=%v", err)
	}
}

func TestBuildPointRejectsMissingIdentityAndBlankIDBeforeRead(t *testing.T) {
	reader := &buildPointReaderFake{}
	service, err := NewBuildPoints(reader, NewCatalogAuthorizer())
	if err != nil {
		t.Fatal(err)
	}
	if build, err := service.GetBuildRun(t.Context(), identitydomain.Actor{TenantID: "ten_1", Scopes: []string{"build:read"}}, "bld_1"); !errors.Is(err, application.ErrUnauthorized) || build.ID != "" {
		t.Fatalf("missing identity build=%#v error=%v", build, err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"build:read"}}
	if build, err := service.GetBuildRun(t.Context(), actor, " "); !errors.Is(err, ErrNotFound) || build.ID != "" {
		t.Fatalf("blank id build=%#v error=%v", build, err)
	}
	if reader.calls != 0 {
		t.Fatalf("invalid reads reached build reader %d times", reader.calls)
	}
}
