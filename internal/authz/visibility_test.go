package authz

import (
	"context"
	"errors"
	"reflect"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestOperationsReadVisibilityUsesCurrentApplicableGrants(t *testing.T) {
	for _, action := range []Action{ActionEnvironmentsRead, ActionDeploymentsRead} {
		t.Run(string(action), func(t *testing.T) {
			actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "session", Scopes: []string{"deployment:read"}, ResourceGrants: []identitydomain.ResourceGrant{
				{ResourceType: "product", ResourceID: "product-b", Scopes: []string{"deployment:read"}},
				{ResourceType: "product", ResourceID: "product-a", Scopes: []string{"*"}},
				{ResourceType: "product", ResourceID: "product-a", Scopes: []string{"admin"}},
				{ResourceType: "product", ResourceID: "denied", Scopes: []string{"deployment:write"}},
				{ResourceType: "product", Scopes: []string{"deployment:read"}},
				{ResourceType: "release", ResourceID: "release-b", Scopes: []string{"deployment:read"}},
				{ResourceType: "release", ResourceID: "release-a", Scopes: []string{"admin"}},
				{ResourceType: "project", ResourceID: "project", Scopes: []string{"*"}},
				{ResourceType: "environment", ResourceID: "environment", Scopes: []string{"*"}},
				{ResourceType: "tenant", ResourceID: "foreign", Scopes: []string{"*"}},
			}}
			visibility, err := ReadVisibility(t.Context(), actor, action)
			wantReleases := []string(nil)
			if action == ActionDeploymentsRead {
				wantReleases = []string{"release-a", "release-b"}
			}
			if err != nil || visibility.TenantID != "tenant" || visibility.TenantWide || !reflect.DeepEqual(visibility.ProductIDs, []string{"product-a", "product-b"}) || !reflect.DeepEqual(visibility.ReleaseIDs, wantReleases) {
				t.Fatalf("visibility=%#v error=%v", visibility, err)
			}
			actor.ResourceGrants = nil
			revoked, err := ReadVisibility(t.Context(), actor, action)
			if err != nil || revoked.TenantID != "tenant" || revoked.TenantWide || len(revoked.ProductIDs) != 0 || len(revoked.ReleaseIDs) != 0 {
				t.Fatalf("revoked grants exposed rows: %#v error=%v", revoked, err)
			}
			for _, grant := range []identitydomain.ResourceGrant{
				{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"deployment:read"}},
				{Scopes: []string{"*"}},
			} {
				actor.ResourceGrants = []identitydomain.ResourceGrant{grant}
				visibility, err := ReadVisibility(t.Context(), actor, action)
				if err != nil || !visibility.TenantWide || visibility.TenantID != "tenant" || visibility.ProductIDs != nil || visibility.ReleaseIDs != nil {
					t.Fatalf("tenant visibility=%#v error=%v", visibility, err)
				}
			}
			actor.Scopes = nil
			if visibility, err := ReadVisibility(t.Context(), actor, action); !errors.Is(err, ErrForbidden) || !reflect.DeepEqual(visibility, Visibility{}) {
				t.Fatalf("grant bypassed issued scope: %#v error=%v", visibility, err)
			}
		})
	}
}

func TestOperationsReadVisibilityIssuedActorsAndFailClosedActions(t *testing.T) {
	for _, action := range []Action{ActionEnvironmentsRead, ActionDeploymentsRead} {
		for _, actor := range []identitydomain.Actor{
			{TenantID: "tenant", KeyID: "key", Scopes: []string{"deployment:read"}},
			{TenantID: "tenant", CollectorID: "collector", Scopes: []string{"deployment:read"}},
		} {
			visibility, err := ReadVisibility(t.Context(), actor, action)
			if err != nil || visibility.TenantID != "tenant" || !visibility.TenantWide || visibility.ProductIDs != nil || visibility.ReleaseIDs != nil {
				t.Fatalf("issued actor visibility=%#v error=%v", visibility, err)
			}
		}
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"*"}}
	for _, action := range []Action{"", "unknown", ActionDeploymentsRecord, ActionIncidentsManage, ActionProductsRead, ActionOutboxReplay} {
		visibility, err := ReadVisibility(t.Context(), actor, action)
		if !errors.Is(err, ErrForbidden) || !reflect.DeepEqual(visibility, Visibility{}) {
			t.Fatalf("unsupported action %s visibility=%#v: %v", action, visibility, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := ReadVisibility(ctx, actor, ActionDeploymentsRead); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := ReadVisibility(t.Context(), identitydomain.Actor{}, ActionDeploymentsRead); !errors.Is(err, ErrUnauthorized) {
		t.Fatal(err)
	}
	var missingContext context.Context
	if _, err := ReadVisibility(missingContext, actor, ActionDeploymentsRead); !errors.Is(err, ErrUnauthorized) {
		t.Fatal(err)
	}
}
