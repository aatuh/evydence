package authz

import (
	"errors"
	"reflect"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var evidenceCases = []struct {
	action    Action
	scope     string
	parents   bool
	inventory bool
}{
	{"evidence.write", "evidence:write", true, false},
	{"security_evidence.write", "security:write", true, false},
	{"evidence.read", "evidence:read", false, true},
	{"sboms.read", "evidence:read", false, true},
	{"vex_documents.read", "evidence:read", false, true},
	{"openapi_contracts.read", "evidence:read", false, true},
	{"vulnerability_scans.read", "evidence:read", false, true},
	{"evidence_lifecycle.read", "evidence:read", false, true},
	{"sbom_components.read", "evidence:read", false, true},
	{"vex_preview.read", "evidence:read", false, true},
	{"evidence_diffs.create", "evidence:read", false, false},
}

func TestEvidencePolicyCurrentGrantsAndIssuedCapabilities(t *testing.T) {
	refs := ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release"}
	for _, tc := range evidenceCases {
		t.Run(string(tc.action), func(t *testing.T) {
			for _, actor := range []identitydomain.Actor{{TenantID: "tenant", KeyID: "key"}, {TenantID: "tenant", CollectorID: "collector"}} {
				for _, scope := range []string{tc.scope, "admin", "*"} {
					actor.Scopes = []string{scope}
					if err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: refs}); err != nil {
						t.Fatal("issued capability", err)
					}
				}
				actor.Scopes = []string{"unrelated", "instance:admin"}
				if err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: refs}); !errors.Is(err, ErrForbidden) {
					t.Fatal("unrelated capability", err)
				}
			}
			actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "session", Scopes: []string{tc.scope}}
			for _, kind := range []string{"tenant", "product", "project", "release", "build", "deployment"} {
				actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: kind, ResourceID: kind, Scopes: []string{tc.scope}}}
				allow := kind != "build" && kind != "deployment"
				err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: refs})
				if allow && err != nil || !allow && !errors.Is(err, ErrForbidden) {
					t.Fatalf("%s grant allowed=%v: %v", kind, allow, err)
				}
				actor.ResourceGrants[0].ResourceID = "foreign"
				if err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: refs}); !errors.Is(err, ErrForbidden) {
					t.Fatal("foreign grant", err)
				}
			}
			actor.ResourceGrants = nil
			if err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: refs}); !errors.Is(err, ErrForbidden) {
				t.Fatal("revoked grant", err)
			}
			if err := Authorize(t.Context(), actor, Request{Action: tc.action, Evaluation: ScopeEvaluation}); err != nil {
				t.Fatal("preflight", err)
			}
			actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{tc.scope}}}
			if err := Authorize(t.Context(), actor, Request{Action: tc.action}); err != nil {
				t.Fatal("detached evidence tenant grant", err)
			}
			err := Authorize(t.Context(), actor, Request{Action: tc.action, Evaluation: TenantEvaluation})
			if tc.inventory && err != nil || !tc.inventory && !errors.Is(err, ErrForbidden) {
				t.Fatalf("inventory allowed=%v: %v", tc.inventory, err)
			}
			actor.Scopes = nil
			if err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: refs}); !errors.Is(err, ErrForbidden) {
				t.Fatal("grant minted issued scope", err)
			}
		})
	}
}

func TestEvidencePolicyRejectsUnsupportedCoordinatesAndPhasePromotion(t *testing.T) {
	for _, tc := range evidenceCases {
		actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{tc.scope}}
		base := ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release"}
		for i := 0; i < reflect.TypeOf(base).NumField(); i++ {
			name := reflect.TypeOf(base).Field(i).Name
			if name == "ProductID" || name == "ProjectID" || name == "ReleaseID" {
				continue
			}
			refs := base
			reflect.ValueOf(&refs).Elem().Field(i).SetString("foreign")
			allow := tc.parents && (name == "BuildID" || name == "DeploymentID")
			err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: refs})
			if allow && err != nil || !allow && !errors.Is(err, ErrForbidden) {
				t.Fatalf("%s coordinate %s allowed=%v: %v", tc.action, name, allow, err)
			}
		}
		for _, mode := range []Evaluation{ScopeEvaluation, TenantEvaluation, Evaluation(255)} {
			if err := Authorize(t.Context(), actor, Request{Action: tc.action, Evaluation: mode, Resources: base}); !errors.Is(err, ErrForbidden) {
				t.Fatal("phase discarded resources", err)
			}
		}
		if tc.parents {
			for _, refs := range []ResourceReferences{{BuildID: "build"}, {DeploymentID: "deployment"}, {ProjectID: "project"}, {ReleaseID: "release"}, {ProductID: "product", BuildID: "build", ReleaseID: "release"}} {
				if err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: refs}); !errors.Is(err, ErrForbidden) {
					t.Fatal("unresolved ownership authorized", err)
				}
			}
		}
	}
}

func TestEvidenceListVisibilityUsesCurrentProjectGrantsAndRevocation(t *testing.T) {
	for _, action := range []Action{ActionEvidenceRead, ActionSBOMComponentsRead} {
		actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "session", Scopes: []string{"evidence:read"}, ResourceGrants: []identitydomain.ResourceGrant{
			{ResourceType: "project", ResourceID: "project-b", Scopes: []string{"evidence:read"}},
			{ResourceType: "project", ResourceID: "project-a", Scopes: []string{"*"}},
			{ResourceType: "project", ResourceID: "project-a", Scopes: []string{"admin"}},
			{ResourceType: "release", ResourceID: "wrong-scope", Scopes: []string{"evidence:write"}},
			{ResourceType: "tenant", ResourceID: "foreign", Scopes: []string{"*"}},
		}}
		visibility, err := ReadVisibility(t.Context(), actor, action)
		if err != nil || visibility.TenantID != actor.TenantID || visibility.TenantWide || !reflect.DeepEqual(visibility.ProjectIDs, []string{"project-a", "project-b"}) || len(visibility.ProductIDs) != 0 || len(visibility.ReleaseIDs) != 0 {
			t.Fatalf("%s visibility=%#v: %v", action, visibility, err)
		}
		actor.ResourceGrants = nil
		visibility, err = ReadVisibility(t.Context(), actor, action)
		if err != nil || visibility.TenantWide || len(visibility.ProjectIDs)+len(visibility.ProductIDs)+len(visibility.ReleaseIDs) != 0 {
			t.Fatal("revoked grant remained visible", visibility, err)
		}
	}
}
