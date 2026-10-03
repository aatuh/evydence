package application

import (
	"errors"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestAuthorizeTenantWideScope(t *testing.T) {
	for _, test := range []struct {
		name  string
		actor identitydomain.Actor
		want  error
	}{
		{name: "missing identity", want: ErrUnauthorized},
		{name: "api key without scope", actor: identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"evidence:read"}}, want: ErrForbidden},
		{name: "API key wildcard", actor: identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"*"}}},
		{name: "collector admin", actor: identitydomain.Actor{TenantID: "ten_1", CollectorID: "col_1", Scopes: []string{"admin"}}},
		{name: "human without grant", actor: identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"admin"}}, want: ErrForbidden},
		{name: "product scoped human", actor: identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"admin"}}}}, want: ErrForbidden},
		{name: "foreign tenant grant", actor: identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "ten_2", Scopes: []string{"admin"}}}}, want: ErrForbidden},
		{name: "human tenant grant", actor: identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "ten_1", Scopes: []string{"*"}}}}},
		{name: "human unscoped grant", actor: identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"admin"}, ResourceGrants: []identitydomain.ResourceGrant{{Scopes: []string{"admin"}}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := AuthorizeTenantWideScope(t.Context(), test.actor, "admin")
			if test.want == nil && err != nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("authorization error=%v, want %v", err, test.want)
			}
		})
	}
}
