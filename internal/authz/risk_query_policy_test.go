package authz

import (
	"errors"
	"reflect"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var riskReadCases = []struct {
	action   Action
	scope    string
	boundary Boundary
	refs     ResourceReferences
}{
	{"vulnerability_decisions.read", "evidence:read", ResourceBoundary, ResourceReferences{ProductID: "product", ReleaseID: "release"}},
	{"exceptions.read", "verify:read", ResourceBoundary, ResourceReferences{ProductID: "product", ReleaseID: "release"}},
	{"control_evidence.read", "controls:read", ResourceBoundary, ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release"}},
	{"vulnerability_decision_summary.read", "report:read", ResourceBoundary, ResourceReferences{ProductID: "product", ReleaseID: "release"}},
	{"release_readiness.read", "verify:read", ResourceBoundary, ResourceReferences{ProductID: "product", ReleaseID: "release"}},
	{"release_security_summary.read", "report:read", ResourceBoundary, ResourceReferences{ProductID: "product", ReleaseID: "release"}},
	{"control_templates.read", "controls:read", CredentialBoundary, ResourceReferences{}},
}

func TestRiskQueryPolicyIssuedScopesCurrentGrantsAndStaticCatalog(t *testing.T) {
	for _, tc := range riskReadCases {
		t.Run(string(tc.action), func(t *testing.T) {
			request := Request{Action: tc.action, Resources: tc.refs}
			for _, actor := range []identitydomain.Actor{{TenantID: "tenant", KeyID: "key"}, {TenantID: "tenant", CollectorID: "collector"}} {
				for _, scope := range []string{tc.scope, "admin", "*"} {
					actor.Scopes = []string{scope}
					if err := Authorize(t.Context(), actor, request); err != nil {
						t.Fatalf("issued scope %q denied: %v", scope, err)
					}
				}
				actor.Scopes = []string{"unrelated", "instance:admin"}
				if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
					t.Fatal("unrelated scope allowed", err)
				}
			}
			actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "session", Scopes: []string{tc.scope}}
			err := Authorize(t.Context(), actor, request)
			static := tc.action == "control_templates.read"
			if static && err != nil || !static && !errors.Is(err, ErrForbidden) {
				t.Fatalf("grantless human static=%v: %v", static, err)
			}
			for _, kind := range []string{"tenant", "product", "project", "release", "artifact"} {
				actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: kind, ResourceID: kind, Scopes: []string{tc.scope}}}
				allow := static || kind == "tenant" || kind == "product" || kind == "release" || kind == "project" && tc.action == "control_evidence.read"
				err := Authorize(t.Context(), actor, request)
				if allow && err != nil || !allow && !errors.Is(err, ErrForbidden) {
					t.Fatalf("%s grant allowed=%v: %v", kind, allow, err)
				}
				actor.ResourceGrants[0].ResourceID = "foreign"
				err = Authorize(t.Context(), actor, request)
				if static && err != nil || !static && !errors.Is(err, ErrForbidden) {
					t.Fatalf("foreign grant static=%v: %v", static, err)
				}
			}
			actor.Scopes = nil
			actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"*"}}}
			if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
				t.Fatal("grant minted issued scope", err)
			}
		})
	}
}

func TestRiskQueryPolicyShapesAndExplicitEvaluationModes(t *testing.T) {
	for _, tc := range riskReadCases {
		t.Run(string(tc.action), func(t *testing.T) {
			actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{tc.scope}}
			static := tc.action == "control_templates.read"
			for _, mode := range []Evaluation{ScopeEvaluation, TenantEvaluation, Evaluation(255)} {
				err := Authorize(t.Context(), actor, Request{Action: tc.action, Evaluation: mode})
				allow := !static && mode != Evaluation(255)
				if allow && err != nil || !allow && !errors.Is(err, ErrForbidden) {
					t.Fatalf("mode %v allowed=%v: %v", mode, allow, err)
				}
			}
			for i := 0; i < reflect.TypeOf(tc.refs).NumField(); i++ {
				field := reflect.TypeOf(tc.refs).Field(i).Name
				changed := tc.refs
				value := reflect.ValueOf(&changed).Elem().Field(i)
				allow := false
				if value.String() == "" {
					value.SetString("foreign")
				} else {
					value.SetString("")
					allow = tc.action == "control_evidence.read" || tc.action == "vulnerability_decisions.read" && field == "ReleaseID"
				}
				err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: changed})
				if allow && err != nil || !allow && !errors.Is(err, ErrForbidden) {
					t.Fatalf("field %s allowed=%v: %v", field, allow, err)
				}
			}
			if !static {
				for _, mode := range []Evaluation{ScopeEvaluation, TenantEvaluation} {
					if err := Authorize(t.Context(), actor, Request{Action: tc.action, Evaluation: mode, Resources: tc.refs}); !errors.Is(err, ErrForbidden) {
						t.Fatal("phase discarded resources", err)
					}
				}
			}
		})
	}
}

func TestRiskQueryReadVisibilityExcludesInapplicableAndRevokedGrants(t *testing.T) {
	for _, tc := range riskReadCases {
		actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{tc.scope}, ResourceGrants: []identitydomain.ResourceGrant{
			{ResourceType: "product", ResourceID: "product", Scopes: []string{tc.scope}},
			{ResourceType: "project", ResourceID: "project", Scopes: []string{tc.scope}},
			{ResourceType: "release", ResourceID: "release", Scopes: []string{tc.scope}},
			{ResourceType: "tenant", ResourceID: "foreign", Scopes: []string{"*"}},
		}}
		visibility, err := ReadVisibility(t.Context(), actor, tc.action)
		if tc.action == "control_templates.read" {
			if !errors.Is(err, ErrForbidden) {
				t.Fatalf("static action became tenant visibility: %v", err)
			}
			continue
		}
		if err != nil || visibility.TenantID != "tenant" || visibility.TenantWide || !reflect.DeepEqual(visibility.ProductIDs, []string{"product"}) || !reflect.DeepEqual(visibility.ReleaseIDs, []string{"release"}) {
			t.Fatalf("%s visibility=%#v: %v", tc.action, visibility, err)
		}
		wantProjects := []string(nil)
		if tc.action == "control_evidence.read" {
			wantProjects = []string{"project"}
		}
		if !reflect.DeepEqual(visibility.ProjectIDs, wantProjects) {
			t.Fatalf("%s project visibility=%#v, want=%#v", tc.action, visibility.ProjectIDs, wantProjects)
		}
		actor.ResourceGrants = nil
		visibility, err = ReadVisibility(t.Context(), actor, tc.action)
		if err != nil || visibility.TenantWide || len(visibility.ProductIDs) != 0 || len(visibility.ProjectIDs) != 0 || len(visibility.ReleaseIDs) != 0 {
			t.Fatalf("revoked grants exposed %s rows: %#v: %v", tc.action, visibility, err)
		}
	}
}

func TestStaticCatalogPolicyDoesNotGrantTenantOrInstanceAuthority(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "session", Scopes: []string{"*"}}
	if err := Authorize(t.Context(), actor, Request{Action: ActionControlTemplatesRead}); err != nil {
		t.Fatal("static catalog denied", err)
	}
	for _, action := range []Action{ActionControlsRead, ActionInstanceSnapshotRead, ActionOutboxReplay} {
		if err := Authorize(t.Context(), actor, Request{Action: action}); !errors.Is(err, ErrForbidden) {
			t.Fatalf("static credential gained %s authority: %v", action, err)
		}
	}
	for _, refs := range []ResourceReferences{{}, {ProductID: "product"}, {ProjectID: "project"}, {ReleaseID: "release"}} {
		key := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"controls:read"}}
		if err := Authorize(t.Context(), key, Request{Action: ActionControlEvidenceRead, Resources: refs}); err != nil {
			t.Fatalf("tenant-owned/projected control evidence lost compatibility: %#v: %v", refs, err)
		}
	}
}
