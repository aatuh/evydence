package authz

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"
	"time"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var actionCases = []struct {
	action   Action
	scope    string
	boundary Boundary
}{
	{ActionAPIKeysRead, "admin", TenantBoundary},
	{ActionAPIKeysManage, "admin", TenantBoundary},
	{ActionMembershipsManage, "identity:admin", TenantBoundary},
	{ActionRoleBindingsRead, "identity:admin", TenantBoundary},
	{ActionControlsRead, "controls:read", TenantBoundary},
	{ActionControlsManage, "controls:admin", TenantBoundary},
	{ActionVulnerabilityPostureRead, "security:read", TenantBoundary},
	{ActionControlCoverageRead, "report:read", TenantBoundary},
	{ActionCollectorsRead, "collector:read", TenantBoundary},
	{ActionCommercialCollectorsRead, "collector:read", TenantBoundary},
	{ActionCollectorHealthRead, "collector:read", TenantBoundary},
	{ActionCollectorsManage, "collector:admin", TenantBoundary},
	{ActionMarketplaceCollectorsRead, "collector:read", TenantBoundary},
	{ActionMarketplaceCollectorsManage, "collector:admin", TenantBoundary},
	{ActionSigningCustodyRead, "keys:admin", TenantBoundary},
	{ActionSigningKeysManage, "keys:admin", TenantBoundary},
	{ActionTransparencyMetadataPublish, "keys:admin", TenantBoundary},
	{ActionSigningKeysRead, "verify:read", TenantBoundary},
	{ActionRetentionPoliciesRead, "verify:read", TenantBoundary},
	{ActionRetentionPoliciesManage, "admin", TenantBoundary},
	{ActionRetentionReportRead, "admin", TenantBoundary},
	{ActionRetentionMarkersManage, "admin", TenantBoundary},
	{ActionAuditLogRead, "admin", TenantBoundary},
	{ActionTenantMetricsRead, "admin", TenantBoundary},
	{ActionReportTemplatesManage, "report:read", TenantBoundary},
	{ActionBundleImport, "bundle:write", TenantBoundary},
	{ActionQuestionnaireTemplatesManage, "package:write", TenantBoundary},
	{ActionRedactionProfilesManage, "package:write", TenantBoundary},
	{ActionInstanceSnapshotRead, "instance:admin", InstanceBoundary},
	{ActionInstanceReadinessRead, "instance:admin", InstanceBoundary},
	{ActionInstanceMetricsRead, "instance:admin", InstanceBoundary},
	{ActionOutboxDiagnosticsRead, "instance:admin", InstanceBoundary},
	{ActionOutboxReplay, "instance:admin", InstanceBoundary},
	{ActionSaaSProfilesManage, "instance:admin", InstanceBoundary},
	{ActionTenantSubjectVerify, "verify:read", TenantBoundary},
	{ActionBackupGenerate, "admin", TenantBoundary},
}

func TestEveryDeclaredActionHasPolicyAndBehaviorCases(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "actions.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	declared := 0
	ast.Inspect(file, func(node ast.Node) bool {
		decl, ok := node.(*ast.GenDecl)
		if !ok || decl.Tok != token.CONST {
			return true
		}
		for _, spec := range decl.Specs {
			value := spec.(*ast.ValueSpec)
			for _, name := range value.Names {
				if len(name.Name) > len("Action") && name.Name[:len("Action")] == "Action" {
					declared++
				}
			}
		}
		return false
	})
	seen := map[Action]bool{}
	for _, tc := range actionCases {
		if seen[tc.action] {
			t.Fatalf("duplicate action case: %s", tc.action)
		}
		seen[tc.action] = true
		definition, ok := DefinitionFor(tc.action)
		if !ok || definition.Scope != tc.scope || definition.Boundary != tc.boundary {
			t.Fatalf("%s definition = %#v, registered=%v", tc.action, definition, ok)
		}
	}
	for _, tc := range catalogCases {
		if seen[tc.action] {
			t.Fatalf("duplicate catalog action case: %s", tc.action)
		}
		seen[tc.action] = true
		definition, ok := DefinitionFor(tc.action)
		if !ok || definition.Scope != tc.scope || definition.Boundary != tc.boundary {
			t.Fatalf("%s definition = %#v, registered=%v", tc.action, definition, ok)
		}
	}
	if declared != len(seen) {
		t.Fatalf("%d declared actions but %d positive/negative behavior cases", declared, len(seen))
	}
}

func TestPolicyIssuedCredentialsAndCurrentSSOGrants(t *testing.T) {
	for _, tc := range actionCases {
		t.Run(string(tc.action), func(t *testing.T) {
			request := Request{Action: tc.action}
			for _, actor := range []identitydomain.Actor{
				{TenantID: "tenant", KeyID: "key"},
				{TenantID: "tenant", CollectorID: "collector"},
				{TenantID: "tenant", KeyID: "collector-key", CollectorID: "collector"},
				{TenantID: "tenant", UserID: "user", KeyID: "issued-key"},
			} {
				actor.Scopes = []string{tc.scope}
				if err := Authorize(t.Context(), actor, request); err != nil {
					t.Fatalf("issued scope denied: %v", err)
				}
				actor.Scopes = []string{"unrelated"}
				if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
					t.Fatalf("missing issued scope allowed: %v", err)
				}
				for _, scope := range []string{"admin", "*"} {
					actor.Scopes = []string{scope}
					err := Authorize(t.Context(), actor, request)
					if tc.boundary == TenantBoundary && err != nil || tc.boundary == InstanceBoundary && !errors.Is(err, ErrForbidden) {
						t.Fatalf("scope %q crossed boundary %v: %v", scope, tc.boundary, err)
					}
				}
			}

			human := identitydomain.Actor{TenantID: "tenant", UserID: "user", SessionID: "session", Scopes: []string{tc.scope}}
			if tc.boundary == InstanceBoundary {
				if err := Authorize(t.Context(), human, request); err != nil {
					t.Fatalf("explicit issued instance authority denied: %v", err)
				}
				human.Scopes = []string{"admin", "*"}
				human.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"instance:admin", "*"}}}
				if err := Authorize(t.Context(), human, request); !errors.Is(err, ErrForbidden) {
					t.Fatalf("tenant grant implied instance authority: %v", err)
				}
				return
			}
			for _, grant := range []identitydomain.ResourceGrant{
				{},
				{ResourceType: "product", ResourceID: "product", Scopes: []string{tc.scope}},
				{ResourceType: "tenant", ResourceID: "foreign", Scopes: []string{tc.scope}},
				{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"unrelated"}},
			} {
				human.ResourceGrants = []identitydomain.ResourceGrant{grant}
				if err := Authorize(t.Context(), human, request); !errors.Is(err, ErrForbidden) {
					t.Fatalf("inapplicable human grant authorized: %v", err)
				}
			}
			for _, grantedScope := range []string{tc.scope, "admin", "*"} {
				for _, grant := range []identitydomain.ResourceGrant{
					{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{grantedScope}},
					{Scopes: []string{grantedScope}},
				} {
					human.ResourceGrants = []identitydomain.ResourceGrant{grant}
					if err := Authorize(t.Context(), human, request); err != nil {
						t.Fatalf("current tenant grant denied: %v", err)
					}
				}
			}
			human.Scopes = []string{"unrelated"}
			if err := Authorize(t.Context(), human, request); !errors.Is(err, ErrForbidden) {
				t.Fatalf("grant bypassed effective issued scopes: %v", err)
			}
			human.Scopes = []string{tc.scope}
			human.ResourceGrants = nil
			if err := Authorize(t.Context(), human, request); !errors.Is(err, ErrForbidden) {
				t.Fatalf("revoked grant authorized: %v", err)
			}
		})
	}
}

func TestPolicyRejectsForeignTenantAndUnsupportedResourceCoordinates(t *testing.T) {
	for _, tc := range actionCases {
		actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{tc.scope}}
		if err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: ResourceReferences{TenantID: "foreign"}}); !errors.Is(err, ErrForbidden) {
			t.Fatalf("%s allowed a foreign target: %v", tc.action, err)
		}
		sameTenantErr := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: ResourceReferences{TenantID: "tenant"}})
		if tc.boundary == TenantBoundary && sameTenantErr != nil || tc.boundary == InstanceBoundary && !errors.Is(sameTenantErr, ErrForbidden) {
			t.Fatalf("%s target boundary error = %v", tc.action, sameTenantErr)
		}
		refs := ResourceReferences{}
		fields := reflect.ValueOf(&refs).Elem()
		for i := 0; i < fields.NumField(); i++ {
			if fields.Type().Field(i).Name == "TenantID" {
				continue
			}
			fields.Field(i).SetString("resource")
			if err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: refs}); !errors.Is(err, ErrForbidden) {
				t.Fatalf("%s allowed unexpected %s: %v", tc.action, fields.Type().Field(i).Name, err)
			}
			fields.Field(i).SetString("")
		}
	}
}

func TestPolicyFailClosedAndContextPropagation(t *testing.T) {
	admin := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"*", "instance:admin", "unknown"}}
	for _, action := range []Action{"", "unknown", "admin", "instance:admin", "instance_snapshot.read "} {
		if _, ok := DefinitionFor(action); ok {
			t.Fatalf("unregistered action %q has a policy", action)
		}
		if err := Authorize(t.Context(), admin, Request{Action: action}); !errors.Is(err, ErrForbidden) {
			t.Fatalf("unregistered action %q authorized: %v", action, err)
		}
	}
	for _, actor := range []identitydomain.Actor{{}, {TenantID: "tenant", Scopes: []string{"*"}}, {KeyID: "key", Scopes: []string{"*"}}} {
		if err := Authorize(t.Context(), actor, Request{Action: ActionAPIKeysRead}); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("missing authenticated identity error = %v", err)
		}
	}
	var nilContext context.Context
	if err := Authorize(nilContext, admin, Request{Action: ActionAPIKeysRead}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("nil context error = %v", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	deadline, cancelDeadline := context.WithDeadline(t.Context(), time.Unix(1, 0))
	defer cancelDeadline()
	for _, tc := range []struct {
		ctx  context.Context
		want error
	}{{canceled, context.Canceled}, {deadline, context.DeadlineExceeded}} {
		if err := Authorize(tc.ctx, admin, Request{Action: ActionAPIKeysRead}); !errors.Is(err, tc.want) {
			t.Fatalf("context cause = %v, want %v", err, tc.want)
		}
	}
}
