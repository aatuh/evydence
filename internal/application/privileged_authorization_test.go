package application

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Characterize the issued-credential and current-human-grant contract before
// replacing the scope-string entry points with centralized typed actions.
func TestPrivilegedScopeActorCharacterization(t *testing.T) {
	actions := map[string]authz.Action{
		"admin":           authz.ActionAPIKeysRead,
		"identity:admin":  authz.ActionMembershipsManage,
		"controls:read":   authz.ActionControlsRead,
		"controls:admin":  authz.ActionControlsManage,
		"security:read":   authz.ActionVulnerabilityPostureRead,
		"report:read":     authz.ActionControlCoverageRead,
		"collector:read":  authz.ActionCollectorsRead,
		"collector:admin": authz.ActionCollectorsManage,
		"keys:admin":      authz.ActionSigningKeysManage,
		"verify:read":     authz.ActionSigningKeysRead,
		"bundle:write":    authz.ActionBundleImport,
		"package:write":   authz.ActionQuestionnaireTemplatesManage,
	}
	for _, scope := range []string{"admin", "identity:admin", "controls:read", "controls:admin", "security:read", "report:read", "collector:read", "collector:admin", "keys:admin", "verify:read", "bundle:write", "package:write"} {
		t.Run(scope, func(t *testing.T) {
			request := authz.Request{Action: actions[scope]}
			for _, identity := range []identitydomain.Actor{{KeyID: "key"}, {CollectorID: "collector"}, {KeyID: "collector-key", CollectorID: "collector"}} {
				identity.TenantID, identity.Scopes = "tenant", []string{scope}
				if err := authz.Authorize(t.Context(), identity, request); err != nil {
					t.Fatalf("issued identity %v denied: %v", identity, err)
				}
			}
			human := identitydomain.Actor{TenantID: "tenant", UserID: "user", SessionID: "session", Scopes: []string{scope}}
			for _, grant := range []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{scope}}, {ResourceType: "tenant", ResourceID: "foreign", Scopes: []string{scope}}, {ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"unrelated"}}} {
				human.ResourceGrants = []identitydomain.ResourceGrant{grant}
				if err := authz.Authorize(t.Context(), human, request); !errors.Is(err, ErrForbidden) {
					t.Fatalf("inapplicable grant authorized: %v", err)
				}
			}
			for _, grantScope := range []string{scope, "admin", "*"} {
				human.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{grantScope}}}
				if err := authz.Authorize(t.Context(), human, request); err != nil {
					t.Fatalf("matching grant denied: %v", err)
				}
			}
			human.ResourceGrants = nil
			if err := authz.Authorize(t.Context(), human, request); !errors.Is(err, ErrForbidden) {
				t.Fatalf("revoked grant authorized: %v", err)
			}
		})
	}
}

func TestInstanceScopeRequiresExplicitAuthority(t *testing.T) {
	for _, identity := range []identitydomain.Actor{{KeyID: "key"}, {UserID: "user", SessionID: "session"}, {CollectorID: "collector"}} {
		identity.TenantID = "tenant"
		for _, scope := range []string{"admin", "*", "identity:admin"} {
			identity.Scopes = []string{scope}
			identity.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"instance:admin", "*"}}}
			if err := authz.Authorize(t.Context(), identity, authz.Request{Action: authz.ActionInstanceSnapshotRead}); !errors.Is(err, ErrForbidden) {
				t.Fatalf("tenant authority %q implies instance authority: %v", scope, err)
			}
		}
		identity.Scopes = []string{"instance:admin"}
		if err := authz.Authorize(t.Context(), identity, authz.Request{Action: authz.ActionInstanceSnapshotRead}); err != nil {
			t.Fatalf("explicit instance scope denied: %v", err)
		}
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"*", "instance:admin"}}
	var nilContext context.Context
	for _, action := range []authz.Action{authz.ActionAPIKeysRead, authz.ActionInstanceSnapshotRead} {
		if err := authz.Authorize(nilContext, actor, authz.Request{Action: action}); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("nil context error = %v", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := authz.Authorize(ctx, actor, authz.Request{Action: action}); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation not propagated: %v", err)
		}
	}
}
