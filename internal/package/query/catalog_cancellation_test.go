package query

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type catalogReadBoundary struct {
	hook  func()
	calls int
}

func (r *catalogReadBoundary) PageAnswerLibrary(_ context.Context, req AnswerLibraryPageRequest) (appquery.Result[AnswerLibraryPoint], error) {
	r.calls++
	if r.hook != nil {
		r.hook()
	}
	return appquery.Result[AnswerLibraryPoint]{Items: []AnswerLibraryPoint{{Entry: packagedomain.QuestionnaireAnswerLibraryEntry{ID: "answer", TenantID: req.TenantID, ProductID: "product", Answer: "private reviewed text", SchemaVersion: packagedomain.QuestionnaireAnswerLibraryVersion, CreatedAt: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)}, EffectiveProductID: "product"}}}, nil
}
func (r *catalogReadBoundary) PagePortalAccess(_ context.Context, req PortalAccessPageRequest) (appquery.Result[PortalAccessPoint], error) {
	r.calls++
	if r.hook != nil {
		r.hook()
	}
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	return appquery.Result[PortalAccessPoint]{Items: []PortalAccessPoint{{Access: packagedomain.CustomerPortalAccess{ID: "access", TenantID: req.TenantID, PackageID: "package", CustomerName: "customer", Prefix: "public-prefix", ExpiresAt: now.Add(time.Hour), SchemaVersion: "customer-portal-access.v1.0.0", CreatedAt: now}, ProductID: "product", ReleaseID: "release"}}}, nil
}
func (r *catalogReadBoundary) GetReleaseBundlePoint(_ context.Context, tenant, id string) (ReleaseBundlePoint, error) {
	r.calls++
	if r.hook != nil {
		r.hook()
	}
	state, err := packagedomain.ParseBundleState(packagedomain.BundleStateGeneratedValue)
	return ReleaseBundlePoint{Bundle: packagedomain.ReleaseBundle{ID: id, TenantID: tenant, ReleaseID: "release", State: state, Manifest: map[string]any{"version": "test"}, ManifestHash: "sha256:hash", CreatedAt: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)}, ProductID: "product"}, err
}

func TestPackageCatalogsWithholdResultsAfterReaderCancellation(t *testing.T) {
	page := appquery.PageRequest{PageSize: 2, Sort: appquery.SortID, Direction: appquery.Ascending}
	for _, tc := range []struct {
		name    string
		revoked error
		run     func(context.Context, identitydomain.Actor, *catalogReadBoundary) (any, error)
	}{
		{"answers", ErrInvalidProjection, func(ctx context.Context, a identitydomain.Actor, r *catalogReadBoundary) (any, error) {
			s, err := NewAnswerLibrary(r)
			if err != nil {
				return nil, err
			}
			return s.ListPage(ctx, a, AnswerLibraryFilter{}, page, nil)
		}},
		{"portal access", ErrPortalAccessProjection, func(ctx context.Context, a identitydomain.Actor, r *catalogReadBoundary) (any, error) {
			s, err := NewPortalAccess(r)
			if err != nil {
				return nil, err
			}
			return s.ListPage(ctx, a, "", page, nil)
		}},
		{"release bundles", application.ErrForbidden, func(ctx context.Context, a identitydomain.Actor, r *catalogReadBoundary) (any, error) {
			s, err := NewReleaseBundles(r)
			if err != nil {
				return nil, err
			}
			return s.GetReleaseBundle(ctx, a, "bundle")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "sso", Scopes: []string{"package:read", "bundle:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"*"}}}}
			r := &catalogReadBoundary{}
			if result, err := tc.run(t.Context(), a, r); err != nil || reflect.ValueOf(result).IsZero() || r.calls != 1 {
				t.Fatal("authorized baseline", err, r.calls)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			r.hook = cancel
			if result, err := tc.run(ctx, a, r); !errors.Is(err, context.Canceled) || !reflect.ValueOf(result).IsZero() || r.calls != 2 {
				t.Error("canceled reader returned private contents or cursor", err, r.calls)
			}
			r.hook = func() { a.ResourceGrants[0].Scopes = nil }
			if result, err := tc.run(t.Context(), a, r); !errors.Is(err, tc.revoked) || !reflect.ValueOf(result).IsZero() || r.calls != 3 {
				t.Error("changed grant returned private contents or cursor", err, r.calls)
			}
		})
	}
}
