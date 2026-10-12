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
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func TestPackageCommandDelegatesRequireOwnActionWithoutScopeSubstitution(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"report:read", "package:read", "package:write", "evidence:read"}}
	for _, tc := range []struct {
		policy    application.Authorizer
		action    authz.Action
		packageID bool
	}{
		{packagequery.NewReportAuthorizer(), "cra_readiness_html.generate", false},
		{packagequery.NewPDFReportAuthorizer(), "pdf_reports.generate", false},
		{packagequery.NewGraphSnapshotAuthorizer(), "graph_snapshots.create", false},
		{packagequery.NewQuestionnaireDraftAuthorizer(), "questionnaire_drafts.create", false},
		{packagequery.NewAnswerLibraryAuthorizer(), "answer_library_entries.create", false},
		{packagequery.NewQuestionnairePackageAuthorizer(), "questionnaire_packages.create", true},
		{packagequery.NewCustomerPackageCreationAuthorizer(), "customer_packages.create", false},
		{packagequery.NewPackageAccessAuthorizer(), "customer_packages.access", true},
		{packagequery.NewPortalAccessWriteAuthorizer(), "portal_access.manage", true},
	} {
		t.Run(string(tc.action), func(t *testing.T) {
			refs := application.ResourceReferences{ProductID: "product", ReleaseID: "release"}
			if tc.packageID {
				refs.CustomerPackageID = "package"
			}
			if err := tc.policy.Authorize(t.Context(), actor, application.AuthorizationRequest{Action: tc.action, Resources: refs}); err != nil {
				t.Fatal("typed command denied", err)
			}
			preflight := application.AuthorizationRequest{Action: tc.action, ScopeOnly: true}
			err := tc.policy.Authorize(t.Context(), actor, preflight)
			if tc.action == "cra_readiness_html.generate" && !errors.Is(err, application.ErrForbidden) || tc.action != "cra_readiness_html.generate" && err != nil {
				t.Fatal("native preflight phase changed", err)
			}
			tenantAllowed := tc.action == "pdf_reports.generate" || tc.action == "graph_snapshots.create" || tc.action == "questionnaire_drafts.create" || tc.action == "answer_library_entries.create" || tc.action == "questionnaire_packages.create"
			err = tc.policy.Authorize(t.Context(), actor, application.AuthorizationRequest{Action: tc.action, TenantWide: true})
			if tenantAllowed && err != nil || !tenantAllowed && !errors.Is(err, application.ErrForbidden) {
				t.Fatal("native tenant phase changed", err)
			}
			if err := tc.policy.Authorize(t.Context(), actor, application.AuthorizationRequest{Action: tc.action}); !errors.Is(err, application.ErrForbidden) {
				t.Fatal("omitted phase promoted to tenant authority", err)
			}
			strayTenant := refs
			strayTenant.TenantID = actor.TenantID
			if err := tc.policy.Authorize(t.Context(), actor, application.AuthorizationRequest{Action: tc.action, Resources: strayTenant}); !errors.Is(err, application.ErrForbidden) {
				t.Fatal("native envelope accepted stray tenant target", err)
			}
			other := authz.Action("questionnaire_packages.create")
			if tc.action == other {
				other = "answer_library_entries.create"
			}
			for _, bad := range []application.AuthorizationRequest{
				{Scope: "package:write", Resources: refs}, {Action: tc.action, Scope: "package:read", Resources: refs},
				{Action: other, Resources: refs}, {Action: tc.action, ScopeOnly: true, TenantWide: true},
				{Action: tc.action, ScopeOnly: true, Resources: refs}, {Action: tc.action, TenantWide: true, Resources: refs},
			} {
				if err := tc.policy.Authorize(t.Context(), actor, bad); !errors.Is(err, application.ErrForbidden) {
					t.Fatal("command envelope substituted authority", bad, err)
				}
			}
		})
	}
}

func TestPackageCommandCallersBindTypedActionsAndRemoveLocalGrantPolicies(t *testing.T) {
	for _, tc := range []struct{ path, action string }{
		{"html_report.go", "ActionCRAReadinessHTMLGenerate"}, {"pdf_report_commands.go", "ActionPDFReportsGenerate"},
		{"graph_snapshot_commands.go", "ActionGraphSnapshotsCreate"}, {"questionnaire_draft_commands.go", "ActionQuestionnaireDraftsCreate"},
		{"answer_library_commands.go", "ActionAnswerLibraryEntriesCreate"}, {"questionnaire_package_commands.go", "ActionQuestionnairePackagesCreate"},
		{"customer_package_commands.go", "ActionCustomerPackagesCreate"}, {"access_commands.go", "ActionCustomerPackagesAccess"}, {"portal_access_commands.go", "ActionPortalAccessManage"},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), "../package/app/"+tc.path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		seen, requests := false, 0
		ast.Inspect(file, func(node ast.Node) bool {
			if selector, ok := node.(*ast.SelectorExpr); ok {
				if selector.Sel.Name == "ResourceGrants" || selector.Sel.Name == "HasScope" {
					t.Errorf("%s retains local grant policy", tc.path)
				}
				if id, ok := selector.X.(*ast.Ident); ok && id.Name == "authz" && selector.Sel.Name == tc.action {
					seen = true
				}
			}
			if literal, ok := node.(*ast.CompositeLit); ok {
				if typ, ok := literal.Type.(*ast.SelectorExpr); ok && typ.Sel.Name == "AuthorizationRequest" {
					requests++
					for _, element := range literal.Elts {
						if field, ok := element.(*ast.KeyValueExpr); ok {
							if name, ok := field.Key.(*ast.Ident); ok && name.Name == "Scope" {
								t.Errorf("%s retains scope-string requests", tc.path)
							}
						}
					}
				}
			}
			return true
		})
		if !seen || requests == 0 {
			t.Errorf("%s lacks own-action requests", tc.path)
		}
	}
	for _, path := range []string{"command_authorizer.go", "access_authorizer.go", "report_authorizer.go", "questionnaire_draft_authorizer.go", "questionnaire_package_authorizer.go", "portal_access_authorizer.go", "customer_package_creation_authorizer.go", "pdf_report_authorizer.go", "graph_snapshot_authorizer.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), "../package/query/"+path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if selector, ok := node.(*ast.SelectorExpr); ok && (selector.Sel.Name == "ResourceGrants" || selector.Sel.Name == "HasScope") {
				t.Errorf("%s retains local actor policy", path)
			}
			return true
		})
	}
}
