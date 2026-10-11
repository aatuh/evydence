package authz

import (
	"errors"
	"reflect"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var packageExportCases = []struct {
	action                               Action
	scope                                string
	refs                                 ResourceReferences
	tenant, projects, packages, detached bool
}{
	{"answer_library_entries.read", "package:read", ResourceReferences{ProductID: "product", ReleaseID: "release"}, true, false, false, false},
	{"portal_access.read", "package:read", ResourceReferences{ProductID: "product", ReleaseID: "release", CustomerPackageID: "package"}, true, false, true, false},
	{"release_bundles.read", "bundle:read", ResourceReferences{ProductID: "product", ReleaseID: "release"}, false, false, false, false},
	{"evidence_summaries.create", "report:read", ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release", BuildID: "build", DeploymentID: "deployment", CustomerPackageID: "package"}, true, true, true, false},
	{"anomaly_reports.generate", "report:read", ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release", BuildID: "build", DeploymentID: "deployment", CustomerPackageID: "package"}, true, true, true, false},
	{"evidence_bundles.export", "bundle:read", ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release", BuildID: "build", DeploymentID: "deployment"}, false, true, false, true},
	{"release_bundles.create", "bundle:write", ResourceReferences{ProductID: "product", ReleaseID: "release"}, false, false, false, false},
}

func TestPackageExportPolicyPreservesOperationSpecificCurrentGrants(t *testing.T) {
	for _, tc := range packageExportCases {
		t.Run(string(tc.action), func(t *testing.T) {
			a := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "sso", Scopes: []string{tc.scope}}
			request := Request{Action: tc.action, Resources: tc.refs}
			for _, kind := range []string{"tenant", "product", "project", "release", "customer_security_package", "build", "deployment", "artifact", "environment"} {
				id := kind
				if kind == "customer_security_package" {
					id = "package"
				}
				for _, scope := range []string{tc.scope, "admin", "*"} {
					a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: kind, ResourceID: id, Scopes: []string{scope}}}
					allow := kind == "tenant" || kind == "product" || kind == "release" || tc.projects && kind == "project" || tc.packages && kind == "customer_security_package"
					err := Authorize(t.Context(), a, request)
					if allow && err != nil || !allow && !errors.Is(err, ErrForbidden) {
						t.Fatal("export root boundary", kind, scope, allow, err)
					}
				}
				a.ResourceGrants[0].ResourceID = "foreign"
				if err := Authorize(t.Context(), a, request); !errors.Is(err, ErrForbidden) {
					t.Fatal("foreign grant", kind, err)
				}
			}
			a.ResourceGrants = nil
			if err := Authorize(t.Context(), a, request); !errors.Is(err, ErrForbidden) {
				t.Fatal("revoked grant", err)
			}
			a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"*"}}}
			a.Scopes = []string{"instance:admin", "unrelated"}
			if err := Authorize(t.Context(), a, request); !errors.Is(err, ErrForbidden) {
				t.Fatal("grant/instance authority minted export capability", err)
			}
			for _, issued := range []identitydomain.Actor{{TenantID: "tenant", KeyID: "key"}, {TenantID: "tenant", CollectorID: "collector"}} {
				for _, scope := range []string{tc.scope, "admin", "*"} {
					issued.Scopes = []string{scope}
					if err := Authorize(t.Context(), issued, request); err != nil {
						t.Fatal("issued capability", scope, err)
					}
				}
			}
		})
	}
}

func TestPackageExportPolicyRejectsStrayCoordinatesAndTenantPromotion(t *testing.T) {
	for _, tc := range packageExportCases {
		t.Run(string(tc.action), func(t *testing.T) {
			a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{tc.scope}}
			for i := 0; i < reflect.TypeOf(tc.refs).NumField(); i++ {
				if reflect.ValueOf(tc.refs).Field(i).String() != "" {
					continue
				}
				request := Request{Action: tc.action, Resources: tc.refs}
				reflect.ValueOf(&request.Resources).Elem().Field(i).SetString("foreign")
				if err := Authorize(t.Context(), a, request); !errors.Is(err, ErrForbidden) {
					t.Fatal("unsupported export coordinate", request, err)
				}
			}
			if err := Authorize(t.Context(), a, Request{Action: tc.action, Evaluation: ScopeEvaluation}); err != nil {
				t.Fatal("export preflight", err)
			}
			if err := Authorize(t.Context(), a, Request{Action: tc.action, Evaluation: TenantEvaluation}); tc.tenant && err != nil || !tc.tenant && !errors.Is(err, ErrForbidden) {
				t.Fatal("tenant promotion", err)
			}
			if err := Authorize(t.Context(), a, Request{Action: tc.action}); tc.detached && err != nil || !tc.detached && !errors.Is(err, ErrForbidden) {
				t.Fatal("detached authority", err)
			}
			a.KeyID, a.UserID = "", "human"
			a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{tc.scope}}}
			if err := Authorize(t.Context(), a, Request{Action: tc.action, Evaluation: TenantEvaluation}); !errors.Is(err, ErrForbidden) {
				t.Fatal("release grant broadened inventory", err)
			}
			if err := Authorize(t.Context(), a, Request{Action: tc.action}); !errors.Is(err, ErrForbidden) {
				t.Fatal("release grant broadened detached selection", err)
			}
		})
	}
}
