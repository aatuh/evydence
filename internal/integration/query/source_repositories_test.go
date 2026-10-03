package query

import (
	"context"
	"errors"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

type sourceRepositoryReaderStub struct {
	request SourceRepositoryPageRequest
	result  appquery.Result[SourceRepositoryPoint]
	calls   int
}

func (r *sourceRepositoryReaderStub) PageSourceRepositories(_ context.Context, request SourceRepositoryPageRequest) (appquery.Result[SourceRepositoryPoint], error) {
	r.request, r.calls = request, r.calls+1
	return r.result, nil
}

func TestSourceRepositoriesAuthorizeCurrentParentAndFilterBeforeLimit(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	reader := &sourceRepositoryReaderStub{result: appquery.Result[SourceRepositoryPoint]{Items: []SourceRepositoryPoint{{
		Repository: integrationdomain.SourceRepository{ID: "repo_1", TenantID: "ten_1", ProjectID: "proj_1", CreatedAt: now}, ProductID: "prod_1",
	}}}}
	service, err := NewSourceRepositories(reader)
	if err != nil {
		t.Fatal(err)
	}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	for _, test := range []struct {
		name     string
		actor    identitydomain.Actor
		products []string
		projects []string
		wide     bool
	}{
		{name: "key", actor: sourceKeyActor(), wide: true},
		{name: "tenant grant", actor: sourceHumanActor("tenant", "ten_1"), wide: true},
		{name: "product grant", actor: sourceHumanActor("product", "prod_1"), products: []string{"prod_1"}},
		{name: "project grant", actor: sourceHumanActor("project", "proj_1"), projects: []string{"proj_1"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := service.ListPage(t.Context(), test.actor, "proj_1", page, nil)
			if err != nil || len(result.Items) != 1 || result.Items[0].ID != "repo_1" || reader.request.TenantWide != test.wide || reader.request.ProjectID != "proj_1" || len(reader.request.AllowedProductIDs) != len(test.products) || len(reader.request.AllowedProjectIDs) != len(test.projects) {
				t.Fatalf("source repository page=%#v request=%#v error=%v", result, reader.request, err)
			}
		})
	}
	reader.result.Items[0].ProductID = "prod_other"
	if _, err := service.ListPage(t.Context(), sourceHumanActor("product", "prod_1"), "", page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("wrong-product projection error=%v", err)
	}
	reader.result.Items[0].ProductID = "prod_1"
	reader.result.Items[0].Repository.TenantID = "ten_other"
	if _, err := service.ListPage(t.Context(), sourceKeyActor(), "", page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("foreign-tenant projection error=%v", err)
	}
	reader.result.Items[0].Repository.TenantID = "ten_1"
	reader.result.Items[0].Repository.ProjectID = "proj_other"
	if _, err := service.ListPage(t.Context(), sourceHumanActor("project", "proj_1"), "", page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("wrong-project projection error=%v", err)
	}
}

func TestSourceRepositoriesDetachedAndRevokedAccess(t *testing.T) {
	reader := &sourceRepositoryReaderStub{result: appquery.Result[SourceRepositoryPoint]{Items: []SourceRepositoryPoint{{Repository: integrationdomain.SourceRepository{ID: "repo_detached", TenantID: "ten_1"}}}}}
	service, err := NewSourceRepositories(reader)
	if err != nil {
		t.Fatal(err)
	}
	page := appquery.PageRequest{PageSize: 2, Sort: appquery.SortID, Direction: appquery.Descending}
	if result, err := service.ListPage(t.Context(), sourceHumanActor("tenant", "ten_1"), "", page, nil); err != nil || len(result.Items) != 1 {
		t.Fatalf("tenant-granted detached repository=%#v error=%v", result, err)
	}
	if result, err := service.ListPage(t.Context(), sourceKeyActor(), "", page, nil); err != nil || len(result.Items) != 1 {
		t.Fatalf("credential-scoped detached repository=%#v error=%v", result, err)
	}
	if _, err := service.ListPage(t.Context(), sourceHumanActor("product", "prod_1"), "", page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("product grant accepted detached repository projection: %v", err)
	}
	if _, err := service.ListPage(t.Context(), sourceHumanActor("project", "proj_1"), "", page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("project grant accepted detached repository projection: %v", err)
	}
	reader.result.Items = nil
	if result, err := service.ListPage(t.Context(), sourceHumanActor("product", "prod_1"), "", page, nil); err != nil || len(result.Items) != 0 || reader.calls != 5 {
		t.Fatalf("product grant saw detached repository=%#v error=%v calls=%d", result, err, reader.calls)
	}
	actor := sourceHumanActor("project", "proj_1")
	actor.ResourceGrants = nil
	if result, err := service.ListPage(t.Context(), actor, "", page, nil); err != nil || len(result.Items) != 0 || reader.calls != 5 {
		t.Fatalf("revoked grant left access=%#v error=%v calls=%d", result, err, reader.calls)
	}
	if _, err := service.ListPage(t.Context(), sourceKeyActor(), "", appquery.PageRequest{}, nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid page error=%v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := service.ListPage(ctx, sourceKeyActor(), "", page, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled page error=%v", err)
	}
	if _, err := service.ListPage(t.Context(), identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1"}, "", page, nil); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("missing source scope error=%v", err)
	}
	if _, err := service.ListPage(t.Context(), identitydomain.Actor{TenantID: "ten_1", Scopes: []string{"source:read"}}, "", page, nil); !errors.Is(err, application.ErrUnauthorized) {
		t.Fatalf("missing identity error=%v", err)
	}
}

func sourceKeyActor() identitydomain.Actor {
	return identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"source:read"}}
}

func sourceHumanActor(resourceType, resourceID string) identitydomain.Actor {
	return identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"source:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: resourceType, ResourceID: resourceID, Scopes: []string{"source:read"}}}}
}
