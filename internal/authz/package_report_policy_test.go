package authz

import (
	"errors"
	"reflect"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var packageReportCases = []struct {
	action          Action
	scope           string
	releaseRequired bool
	tenantAllowed   bool
}{
	{"release_vulnerability_posture.read", "security:read", true, false},
	{"control_coverage_report.read", "report:read", false, true},
	{"cra_readiness_report.read", "report:read", false, false},
	{"cra_vulnerability_handling.read", "report:read", true, false},
	{"release_readiness_report.read", "verify:read", true, false},
	{"security_update_evidence.read", "report:read", true, false},
	{"incident_report.read", "incident:read", false, false},
}

func TestPackageReportPolicyPreservesCurrentRootGrantsAndCapabilities(t *testing.T) {
	for _, tc := range packageReportCases {
		t.Run(string(tc.action), func(t *testing.T) {
			request := Request{Action: tc.action, Resources: ResourceReferences{ProductID: "product", ReleaseID: "release"}}
			actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "sso", Scopes: []string{tc.scope}}
			for _, kind := range []string{"tenant", "product", "release", "project", "customer_security_package", "artifact", "environment"} {
				for _, scope := range []string{tc.scope, "admin", "*"} {
					actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: kind, ResourceID: kind, Scopes: []string{scope}}}
					allowed := kind == "tenant" || kind == "product" || kind == "release"
					err := Authorize(t.Context(), actor, request)
					if allowed && err != nil || !allowed && !errors.Is(err, ErrForbidden) {
						t.Fatal("report root grant", kind, scope, allowed, err)
					}
				}
				actor.ResourceGrants[0].ResourceID = "foreign"
				if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
					t.Fatal("foreign grant authorized report", kind, err)
				}
			}
			actor.ResourceGrants = nil
			if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
				t.Fatal("revoked grant", err)
			}
			actor.Scopes = []string{"instance:admin", "unrelated"}
			actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"*"}}}
			if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
				t.Fatal("resource grant or instance scope minted report capability", err)
			}
			actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{tc.scope}}}
			for _, scope := range []string{tc.scope, "admin", "*"} {
				actor.Scopes = []string{scope}
				if err := Authorize(t.Context(), actor, request); err != nil {
					t.Fatal("human credential capability with current release grant", scope, err)
				}
			}
			for _, issued := range []identitydomain.Actor{{TenantID: "tenant", KeyID: "key"}, {TenantID: "tenant", CollectorID: "collector"}} {
				for _, scope := range []string{tc.scope, "admin", "*"} {
					issued.Scopes = []string{scope}
					if err := Authorize(t.Context(), issued, request); err != nil {
						t.Fatal("issued capability denied", scope, err)
					}
				}
			}
		})
	}
}

func TestPackageReportPolicyConstrainsCoordinatesAndEvaluationPhases(t *testing.T) {
	for _, tc := range packageReportCases {
		t.Run(string(tc.action), func(t *testing.T) {
			actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{tc.scope}}
			request := Request{Action: tc.action, Resources: ResourceReferences{ProductID: "product", ReleaseID: "release"}}
			for i := 0; i < reflect.TypeOf(request.Resources).NumField(); i++ {
				if reflect.ValueOf(request.Resources).Field(i).String() != "" {
					continue
				}
				invalid := request
				reflect.ValueOf(&invalid.Resources).Elem().Field(i).SetString("foreign")
				if err := Authorize(t.Context(), actor, invalid); !errors.Is(err, ErrForbidden) {
					t.Fatal("stray report coordinate", invalid, err)
				}
			}
			request.Resources = ResourceReferences{ProductID: "product"}
			if err := Authorize(t.Context(), actor, request); tc.releaseRequired && !errors.Is(err, ErrForbidden) || !tc.releaseRequired && err != nil {
				t.Fatal("release requirement", err)
			}
			request.Resources = ResourceReferences{ReleaseID: "release"}
			if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
				t.Fatal("unresolved parent authorized", err)
			}
			request = Request{Action: tc.action, Evaluation: TenantEvaluation}
			if err := Authorize(t.Context(), actor, request); tc.tenantAllowed && err != nil || !tc.tenantAllowed && !errors.Is(err, ErrForbidden) {
				t.Fatal("tenant inventory promotion", err)
			}
			if err := Authorize(t.Context(), actor, Request{Action: tc.action, Evaluation: ScopeEvaluation}); err != nil {
				t.Fatal("report preflight", err)
			}
			actor.KeyID, actor.UserID = "", "human"
			actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{tc.scope}}}
			if err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: ResourceReferences{ProductID: "product"}}); !errors.Is(err, ErrForbidden) {
				t.Fatal("release grant authorized product-wide report", err)
			}
			if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
				t.Fatal("release grant authorized tenant report", err)
			}
		})
	}
}

func TestReleaseReadinessReportVisibilityResolvesOnlyCurrentProductAndReleaseGrants(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "sso", Scopes: []string{"verify:read"}, ResourceGrants: []identitydomain.ResourceGrant{
		{ResourceType: "product", ResourceID: "product-b", Scopes: []string{"verify:read"}},
		{ResourceType: "product", ResourceID: "product-a", Scopes: []string{"admin"}},
		{ResourceType: "product", ResourceID: "product-a", Scopes: []string{"*"}},
		{ResourceType: "release", ResourceID: "release", Scopes: []string{"verify:read"}},
		{ResourceType: "project", ResourceID: "project", Scopes: []string{"verify:read"}},
		{ResourceType: "product", ResourceID: "wrong-scope", Scopes: []string{"report:read"}},
	}}
	visibility, err := ReadVisibility(t.Context(), actor, "release_readiness_report.read")
	want := Visibility{TenantID: "tenant", ProductIDs: []string{"product-a", "product-b"}, ReleaseIDs: []string{"release"}}
	if err != nil || !reflect.DeepEqual(visibility, want) {
		t.Fatal("report visibility", visibility, want, err)
	}
	actor.ResourceGrants = nil
	visibility, err = ReadVisibility(t.Context(), actor, "release_readiness_report.read")
	if err != nil || !reflect.DeepEqual(visibility, Visibility{TenantID: "tenant"}) {
		t.Fatal("revoked report visibility", visibility, err)
	}
	actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"*"}}}
	visibility, err = ReadVisibility(t.Context(), actor, "release_readiness_report.read")
	if err != nil || !reflect.DeepEqual(visibility, Visibility{TenantID: "tenant", TenantWide: true}) {
		t.Fatal("tenant report visibility", visibility, err)
	}
	actor.Scopes = []string{"report:read"}
	if visibility, err = ReadVisibility(t.Context(), actor, "release_readiness_report.read"); !errors.Is(err, ErrForbidden) || !reflect.DeepEqual(visibility, Visibility{}) {
		t.Fatal("wrong capability returned visibility", visibility, err)
	}
}
