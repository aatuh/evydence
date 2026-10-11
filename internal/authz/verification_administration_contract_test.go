package authz_test

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func TestVerificationAdministrationUsesTypedActionsAndCurrentTenantGrants(t *testing.T) {
	for _, tc := range []struct {
		policy application.Authorizer
		action authz.Action
		scope  string
	}{
		{verificationquery.NewSigningKeyAdminAuthorizer(), "signing_keys.manage", "keys:admin"},
		{verificationquery.NewTrustConfigurationAuthorizer(), "trust_configurations.manage", "keys:admin"},
		{verificationquery.NewSigningOperationAuthorizer(), "signing_operations.create", "keys:admin"},
		{verificationquery.NewMerkleCreationAuthorizer(), "merkle_batches.create", "keys:admin"},
		{verificationquery.NewTransparencyCheckpointAuthorizer(), "transparency_checkpoints.record", "keys:admin"},
		{verificationquery.NewBackupGenerationAuthorizer(), "backup.generate", "admin"},
		{verificationquery.NewRetentionAuthorizer(), "retention_policies.manage", "admin"},
		{verificationquery.NewRetentionAuthorizer(), "retention_policies.read", "verify:read"},
		{operationsapp.NewRetentionMarkerAuthorizer(), "retention_markers.manage", "admin"},
	} {
		t.Run(string(tc.action), func(t *testing.T) {
			request := application.AuthorizationRequest{Action: tc.action, TenantWide: true}
			actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "sso", Scopes: []string{tc.scope}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{tc.scope}}}}
			if err := tc.policy.Authorize(t.Context(), actor, request); err != nil {
				t.Fatal("typed administration denied", err)
			}
			for _, kind := range []string{"product", "project", "release", "customer_security_package"} {
				actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: kind, ResourceID: kind, Scopes: []string{"*"}}}
				if err := tc.policy.Authorize(t.Context(), actor, request); !errors.Is(err, application.ErrForbidden) {
					t.Fatal("scoped grant authorized tenant administration", kind, err)
				}
			}
			actor.ResourceGrants = nil
			if err := tc.policy.Authorize(t.Context(), actor, request); !errors.Is(err, application.ErrForbidden) {
				t.Fatal("revoked tenant grant", err)
			}
			actor.UserID, actor.KeyID = "", "key"
			if err := tc.policy.Authorize(t.Context(), actor, request); err != nil {
				t.Fatal("issued credential", err)
			}
			for _, bad := range []application.AuthorizationRequest{{Scope: tc.scope, TenantWide: true}, {Action: tc.action, Scope: tc.scope, TenantWide: true}, {Action: tc.action}, {Action: tc.action, TenantWide: true, ScopeOnly: true}, {Action: tc.action, TenantWide: true, Resources: application.ResourceReferences{ProductID: "product"}}, {Action: "backup.verify", TenantWide: true}} {
				if err := tc.policy.Authorize(t.Context(), actor, bad); !errors.Is(err, application.ErrForbidden) {
					t.Fatal("scope/shape/family substitution", bad, err)
				}
			}
			actor.Scopes = []string{"*"}
			for _, other := range []authz.Action{"signing_keys.manage", "trust_configurations.manage", "signing_operations.create", "merkle_batches.create", "transparency_checkpoints.record", "backup.generate", "retention_policies.manage", "retention_policies.read", "retention_markers.manage"} {
				if other == tc.action || (tc.action == "retention_policies.manage" || tc.action == "retention_policies.read") && (other == "retention_policies.manage" || other == "retention_policies.read") {
					continue
				}
				if err := tc.policy.Authorize(t.Context(), actor, application.AuthorizationRequest{Action: other, TenantWide: true}); !errors.Is(err, application.ErrForbidden) {
					t.Fatal("privileged factory accepted foreign operation", other, err)
				}
			}
		})
	}
}

func TestPrivilegedVerificationCallersUseActionsNotScopes(t *testing.T) {
	for _, path := range []string{
		"../verification/app/signing_key_commands.go", "../verification/app/signing_key_lifecycle.go", "../verification/app/signing_key_guard.go",
		"../verification/app/trust_configuration_commands.go", "../verification/app/signing_operation_commands.go", "../verification/app/merkle_creation.go", "../verification/app/transparency_checkpoint_commands.go",
		"../verification/app/backup_generation.go", "../verification/app/retention_commands.go", "../verification/app/retention.go", "../operations/app/retention_marker_commands.go",
	} {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		requests := 0
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			typ, ok := literal.Type.(*ast.SelectorExpr)
			if !ok || typ.Sel.Name != "AuthorizationRequest" {
				return true
			}
			requests++
			hasAction := false
			for _, element := range literal.Elts {
				if field, ok := element.(*ast.KeyValueExpr); ok {
					if name, ok := field.Key.(*ast.Ident); ok {
						if name.Name == "Scope" {
							t.Errorf("%s retains scope authority", path)
						}
						if name.Name == "Action" {
							hasAction = true
						}
					}
				}
			}
			if !hasAction {
				t.Errorf("%s omitted own typed action", path)
			}
			return true
		})
		if requests == 0 {
			t.Fatal("privileged caller coverage disappeared", path)
		}
	}
}
