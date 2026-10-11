package authz

import (
	"errors"
	"reflect"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var packageCommandCases = []struct {
	action               Action
	scope                string
	tenant, packageGrant bool
}{
	{"cra_readiness_html.generate", "report:read", false, false},
	{"pdf_reports.generate", "report:read", true, false},
	{"graph_snapshots.create", "evidence:read", true, false},
	{"questionnaire_drafts.create", "package:read", true, false},
	{"answer_library_entries.create", "package:write", true, false},
	{"questionnaire_packages.create", "package:write", true, true},
	{"customer_packages.create", "package:write", false, false},
	{"customer_packages.access", "package:read", false, true},
	{"portal_access.manage", "package:write", false, true},
}

func TestPackageCommandPolicyPreservesClosedRootAndPackageGrants(t *testing.T) {
	for _, tc := range packageCommandCases {
		t.Run(string(tc.action), func(t *testing.T) {
			refs := ResourceReferences{ProductID: "product", ReleaseID: "release"}
			if tc.packageGrant {
				refs.CustomerPackageID = "package"
			}
			request := Request{Action: tc.action, Resources: refs}
			actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "sso", Scopes: []string{tc.scope}}
			for _, kind := range []string{"tenant", "product", "release", "project", "customer_security_package", "artifact", "environment"} {
				id := kind
				if kind == "customer_security_package" {
					id = "package"
				}
				for _, scope := range []string{tc.scope, "admin", "*"} {
					actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: kind, ResourceID: id, Scopes: []string{scope}}}
					allowed := kind == "tenant" || kind == "product" || kind == "release" || tc.packageGrant && kind == "customer_security_package"
					err := Authorize(t.Context(), actor, request)
					if allowed && err != nil || !allowed && !errors.Is(err, ErrForbidden) {
						t.Fatal("command grant boundary", kind, scope, allowed, err)
					}
				}
				actor.ResourceGrants[0].ResourceID = "foreign"
				if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
					t.Fatal("foreign command grant", kind, err)
				}
			}
			actor.ResourceGrants = nil
			if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
				t.Fatal("revoked grant", err)
			}
			actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"*"}}}
			actor.Scopes = []string{"instance:admin", "unrelated"}
			if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
				t.Fatal("instance/resource grant minted command capability", err)
			}
			for _, scope := range []string{tc.scope, "admin", "*"} {
				actor.Scopes = []string{scope}
				if err := Authorize(t.Context(), actor, request); err != nil {
					t.Fatal("human effective capability", scope, err)
				}
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

func TestPackageCommandPolicyRejectsShapeAndPhasePromotion(t *testing.T) {
	for _, tc := range packageCommandCases {
		t.Run(string(tc.action), func(t *testing.T) {
			actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{tc.scope}}
			refs := ResourceReferences{ProductID: "product", ReleaseID: "release"}
			if tc.packageGrant {
				refs.CustomerPackageID = "package"
			}
			request := Request{Action: tc.action, Resources: refs}
			for i := 0; i < reflect.TypeOf(refs).NumField(); i++ {
				if reflect.ValueOf(refs).Field(i).String() != "" {
					continue
				}
				invalid := request
				reflect.ValueOf(&invalid.Resources).Elem().Field(i).SetString("foreign")
				if err := Authorize(t.Context(), actor, invalid); !errors.Is(err, ErrForbidden) {
					t.Fatal("stray command coordinate", invalid, err)
				}
			}
			for _, invalid := range []Request{{Action: tc.action}, {Action: tc.action, Resources: ResourceReferences{ReleaseID: "release"}}, {Action: tc.action, Resources: refs, Evaluation: ScopeEvaluation}, {Action: tc.action, Resources: refs, Evaluation: TenantEvaluation}} {
				if err := Authorize(t.Context(), actor, invalid); !errors.Is(err, ErrForbidden) {
					t.Fatal("unresolved/stray phase authorized", invalid, err)
				}
			}
			request = Request{Action: tc.action, Evaluation: TenantEvaluation}
			if err := Authorize(t.Context(), actor, request); tc.tenant && err != nil || !tc.tenant && !errors.Is(err, ErrForbidden) {
				t.Fatal("tenant command admission", err)
			}
			actor.KeyID, actor.UserID = "", "human"
			actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "customer_security_package", ResourceID: "package", Scopes: []string{tc.scope}}}
			for _, request := range []Request{{Action: tc.action, Evaluation: TenantEvaluation}, {Action: tc.action, Resources: ResourceReferences{ProductID: "product", ReleaseID: "release"}}} {
				if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
					t.Fatal("package grant broadened selection", request, err)
				}
			}
		})
	}
}
