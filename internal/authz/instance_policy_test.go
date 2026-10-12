package authz

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestAPIKeyScopeDelegationRequiresExactExplicitInstanceAuthority(t *testing.T) {
	for _, tc := range []struct {
		name    string
		actor   identitydomain.Actor
		allowed bool
	}{
		{"explicit key", identitydomain.Actor{KeyID: "key", Scopes: []string{"instance:admin"}}, true},
		{"explicit collector", identitydomain.Actor{CollectorID: "collector", Scopes: []string{"instance:admin"}}, true},
		{"explicit human", identitydomain.Actor{UserID: "human", Scopes: []string{"instance:admin"}}, true},
		{"wildcard", identitydomain.Actor{Scopes: []string{"*"}}, false},
		{"tenant admin", identitydomain.Actor{Scopes: []string{"admin"}}, false},
		{"padded actor claim", identitydomain.Actor{Scopes: []string{" instance:admin "}}, false},
		{"tenant grant", identitydomain.Actor{ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"instance:admin", "*"}}}}, false},
		{"empty actor", identitydomain.Actor{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, scopes := range [][]string{{"instance:admin"}, {" instance:admin "}, {"unknown", "instance:admin", "instance:admin"}} {
				before := slices.Clone(scopes)
				err := CheckAPIKeyScopeDelegation(tc.actor, scopes)
				if tc.allowed && err != nil || !tc.allowed && !errors.Is(err, ErrForbidden) {
					t.Fatal("instance delegation authority", scopes, err)
				}
				if !reflect.DeepEqual(scopes, before) {
					t.Fatal("delegation check mutated requested scopes")
				}
			}
			for _, scopes := range [][]string{nil, {"", " ", "unknown", "unknown", "instance:read"}} {
				before := slices.Clone(scopes)
				if err := CheckAPIKeyScopeDelegation(tc.actor, scopes); err != nil || !reflect.DeepEqual(scopes, before) {
					t.Fatal("inert scope compatibility changed", scopes, err)
				}
			}
		})
	}
}

func TestMetricsPolicySelectsOnlyAuthorizedTenantOrExplicitInstanceView(t *testing.T) {
	grant := func(kind, id string, scopes ...string) []identitydomain.ResourceGrant {
		return []identitydomain.ResourceGrant{{ResourceType: kind, ResourceID: id, Scopes: scopes}}
	}
	for _, tc := range []struct {
		name   string
		actor  identitydomain.Actor
		action Action
		err    error
	}{
		{"key tenant admin", identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"admin"}}, ActionTenantMetricsRead, nil},
		{"key wildcard", identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"*"}}, ActionTenantMetricsRead, nil},
		{"collector tenant admin", identitydomain.Actor{TenantID: "tenant", CollectorID: "collector", Scopes: []string{"admin"}}, ActionTenantMetricsRead, nil},
		{"key instance", identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"instance:admin"}}, ActionInstanceMetricsRead, nil},
		{"collector instance", identitydomain.Actor{TenantID: "tenant", CollectorID: "collector", Scopes: []string{"instance:admin"}}, ActionInstanceMetricsRead, nil},
		{"human instance without tenant grant", identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"instance:admin"}}, ActionInstanceMetricsRead, nil},
		{"human current tenant", identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"admin"}, ResourceGrants: grant("tenant", "tenant", "admin")}, ActionTenantMetricsRead, nil},
		{"human instance grant is not instance capability", identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"*"}, ResourceGrants: grant("tenant", "tenant", "*", "instance:admin")}, ActionTenantMetricsRead, nil},
		{"human no current grant", identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"admin"}}, "", ErrForbidden},
		{"human foreign tenant", identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"admin"}, ResourceGrants: grant("tenant", "foreign", "admin")}, "", ErrForbidden},
		{"human narrow grant", identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"admin"}, ResourceGrants: grant("product", "product", "admin")}, "", ErrForbidden},
		{"human revoked capability", identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"admin"}, ResourceGrants: grant("tenant", "tenant", "evidence:read")}, "", ErrForbidden},
		{"padded instance claim", identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{" instance:admin "}}, "", ErrForbidden},
		{"no tenant", identitydomain.Actor{KeyID: "key", Scopes: []string{"instance:admin"}}, "", ErrUnauthorized},
		{"no authenticated identity", identitydomain.Actor{TenantID: "tenant", Scopes: []string{"instance:admin"}}, "", ErrUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			action, err := AuthorizeMetrics(t.Context(), tc.actor)
			if action != tc.action || !errors.Is(err, tc.err) {
				t.Fatal("metrics selection", action, err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if action, err := AuthorizeMetrics(ctx, tc.actor); action != "" || !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation returned an authorized view", action, err)
			}
			var missingContext context.Context
			if action, err := AuthorizeMetrics(missingContext, tc.actor); action != "" || !errors.Is(err, ErrUnauthorized) {
				t.Fatal("nil context returned an authorized view", action, err)
			}
		})
	}
}
