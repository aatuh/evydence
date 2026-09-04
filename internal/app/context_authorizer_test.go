package app

import (
	"context"
	"errors"
	"testing"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestLedgerContextAuthorizerRequiresTenantWideHumanGrantWhenRequested(t *testing.T) {
	ledger := &Ledger{}
	authorizer := ledgerContextAuthorizer{ledger: ledger}
	request := application.AuthorizationRequest{Scope: ScopeIdentityAdmin, ScopeOnly: true, TenantWide: true}

	productScoped := identitydomain.Actor{
		TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"*"},
		ResourceGrants: []identitydomain.ResourceGrant{{Role: "tenant_admin", ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"*"}}},
	}
	if err := authorizer.Authorize(context.Background(), productScoped, request); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("product-scoped tenant admin error = %v, want forbidden", err)
	}

	tenantScoped := productScoped
	tenantScoped.ResourceGrants = []identitydomain.ResourceGrant{{Role: "tenant_admin", ResourceType: "tenant", ResourceID: tenantScoped.TenantID, Scopes: []string{"*"}}}
	if err := authorizer.Authorize(context.Background(), tenantScoped, request); err != nil {
		t.Fatalf("tenant-scoped tenant admin: %v", err)
	}

	apiKeyAdmin := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"*"}}
	if err := authorizer.Authorize(context.Background(), apiKeyAdmin, request); err != nil {
		t.Fatalf("API-key tenant admin: %v", err)
	}
}
