package authz_test

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func TestPackageExportDelegatesRejectScopeAndOperationSubstitution(t *testing.T) {
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"report:read", "bundle:read", "bundle:write", "package:write"}}
	for _, tc := range []struct {
		policy application.Authorizer
		action authz.Action
		tenant bool
	}{
		{packagequery.NewEvidenceSummaryAuthorizer(), "evidence_summaries.create", false},
		{packagequery.NewEvidenceBundleAuthorizer(), "evidence_bundles.export", false},
		{packagequery.NewReleaseBundleAuthorizer(), "release_bundles.create", false},
		{packagequery.NewTemplateAuthorizer(), "report_templates.manage", true},
		{packagequery.NewBundleImportAuthorizer(), "bundle.import", true},
		{packagequery.NewQuestionnaireTemplateAuthorizer(), "questionnaire_templates.manage", true},
		{packagequery.NewRedactionProfileAuthorizer(), "redaction_profiles.manage", true},
	} {
		t.Run(string(tc.action), func(t *testing.T) {
			request := application.AuthorizationRequest{Action: tc.action, Resources: application.ResourceReferences{ProductID: "product", ReleaseID: "release"}}
			if tc.tenant {
				request.Resources = application.ResourceReferences{}
				request.TenantWide = true
			}
			if err := tc.policy.Authorize(t.Context(), a, request); err != nil {
				t.Fatal("typed export denied", err)
			}
			for _, bad := range []application.AuthorizationRequest{{Scope: "report:read", Resources: request.Resources, TenantWide: request.TenantWide}, {Action: tc.action, Scope: "bundle:write", Resources: request.Resources, TenantWide: request.TenantWide}, {Action: "questionnaire_packages.create", Resources: request.Resources, TenantWide: request.TenantWide}, {Action: tc.action, ScopeOnly: true, TenantWide: true}} {
				if err := tc.policy.Authorize(t.Context(), a, bad); !errors.Is(err, application.ErrForbidden) {
					t.Fatal("export envelope substituted policy", bad, err)
				}
			}
		})
	}
}

func TestPackageContextCannotReintroduceLocalGrantOrScopeRequestPolicies(t *testing.T) {
	files := 0
	for _, dir := range []string{"../package/app", "../package/query"} {
		paths, err := filepath.Glob(dir + "/*.go")
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			files++
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(file, func(node ast.Node) bool {
				if selector, ok := node.(*ast.SelectorExpr); ok && (selector.Sel.Name == "ResourceGrants" || selector.Sel.Name == "HasScope" || selector.Sel.Name == "HasExplicitScope") {
					t.Errorf("%s retains actor policy outside authz", path)
				}
				literal, ok := node.(*ast.CompositeLit)
				if !ok {
					return true
				}
				typ, ok := literal.Type.(*ast.SelectorExpr)
				if !ok || typ.Sel.Name != "AuthorizationRequest" {
					return true
				}
				hasAction := false
				for _, element := range literal.Elts {
					if field, ok := element.(*ast.KeyValueExpr); ok {
						if name, ok := field.Key.(*ast.Ident); ok {
							if name.Name == "Scope" {
								t.Errorf("%s reintroduced a scope request", path)
							}
							if name.Name == "Action" {
								hasAction = true
							}
						}
					}
				}
				if !hasAction {
					t.Errorf("%s has an untyped authorization envelope", path)
				}
				return true
			})
		}
	}
	if files == 0 {
		t.Fatal("package policy guard scanned no production sources")
	}
}

func TestPackageCatalogAndExportCallersUseCentralActionsWithoutLocalGrants(t *testing.T) {
	for _, tc := range []struct{ path, action string }{
		{"../package/query/answer_library.go", "ActionAnswerLibraryEntriesRead"}, {"../package/query/portal_access.go", "ActionPortalAccessRead"}, {"../package/query/release_bundles.go", "ActionReleaseBundlesRead"},
		{"../package/app/evidence_summary_commands.go", "ActionEvidenceSummariesCreate"}, {"../package/app/evidence_bundle.go", "ActionEvidenceBundlesExport"}, {"../package/app/evidence_bundle_guard.go", "ActionEvidenceBundlesExport"}, {"../package/app/evidence_bundle_commands.go", "ActionEvidenceBundlesExport"},
		{"../platform/wiring/evidence_bundle_commands.go", "ActionEvidenceBundlesExport"},
		{"../package/app/release_bundle.go", "ActionReleaseBundlesCreate"}, {"../package/app/release_bundle_creation_guard.go", "ActionReleaseBundlesCreate"},
		{"../package/app/report_templates.go", "ActionReportTemplatesManage"}, {"../package/app/report_template_guard.go", "ActionReportTemplatesManage"}, {"../package/app/bundle_import_guard.go", "ActionBundleImport"}, {"../package/app/questionnaire_template_commands.go", "ActionQuestionnaireTemplatesManage"}, {"../package/app/redaction_profile_commands.go", "ActionRedactionProfilesManage"},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), tc.path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		seen := false
		ast.Inspect(file, func(node ast.Node) bool {
			if selector, ok := node.(*ast.SelectorExpr); ok {
				if selector.Sel.Name == "HasScope" || selector.Sel.Name == "ResourceGrants" {
					t.Errorf("%s retains local actor policy", tc.path)
				}
				if id, ok := selector.X.(*ast.Ident); ok && id.Name == "authz" && selector.Sel.Name == tc.action {
					seen = true
				}
			}
			if literal, ok := node.(*ast.CompositeLit); ok {
				if typ, ok := literal.Type.(*ast.SelectorExpr); ok && typ.Sel.Name == "AuthorizationRequest" {
					for _, element := range literal.Elts {
						if field, ok := element.(*ast.KeyValueExpr); ok {
							if name, ok := field.Key.(*ast.Ident); ok && name.Name == "Scope" {
								t.Errorf("%s retains scope requests", tc.path)
							}
						}
					}
				}
			}
			return true
		})
		if !seen {
			t.Errorf("%s lacks own action", tc.path)
		}
	}
}
