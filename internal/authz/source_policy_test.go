package authz

import (
	"errors"
	"reflect"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var sourceCases = []struct {
	action Action
	scope  string
	read   bool
}{
	{"source_repositories.create", "source:write", false},
	{"source_commits.record", "source:write", false},
	{"source_branches.upsert", "source:write", false},
	{"pull_requests.record", "source:write", false},
	{"source_snapshots.record", "source:write", false},
	{"source_repositories.read", "source:read", true},
}

func TestSourcePolicyRequiresIssuedCapabilityAndCurrentParentOrTenantGrant(t *testing.T) {
	for _, tc := range sourceCases {
		t.Run(string(tc.action), func(t *testing.T) {
			refs := ResourceReferences{ProductID: "product", ProjectID: "project"}
			actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "sso", Scopes: []string{tc.scope}}
			for _, grant := range []struct {
				kind, id string
				allow    bool
			}{
				{"tenant", "tenant", true}, {"product", "product", true}, {"project", "project", true},
				{"tenant", "foreign", false}, {"project", "foreign", false}, {"release", "release", false}, {"build", "build", false},
			} {
				for _, scope := range []string{tc.scope, "admin", "*"} {
					actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: grant.kind, ResourceID: grant.id, Scopes: []string{scope}}}
					err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: refs})
					if grant.allow && err != nil || !grant.allow && !errors.Is(err, ErrForbidden) {
						t.Fatal("current parent grant", grant, scope, err)
					}
				}
			}
			actor.ResourceGrants = nil
			if err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: refs}); !errors.Is(err, ErrForbidden) {
				t.Fatal("revoked parent grant", err)
			}
			if err := Authorize(t.Context(), actor, Request{Action: tc.action, Evaluation: ScopeEvaluation}); err != nil {
				t.Fatal("scope preflight", err)
			}
			actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{tc.scope}}}
			if err := Authorize(t.Context(), actor, Request{Action: tc.action, Evaluation: TenantEvaluation}); err != nil {
				t.Fatal("detached repository tenant authority", err)
			}
			err := Authorize(t.Context(), actor, Request{Action: tc.action})
			if tc.read && err != nil || !tc.read && !errors.Is(err, ErrForbidden) {
				t.Fatal("empty resolved write promoted to tenant authority", tc.read, err)
			}
			actor.Scopes = nil
			if err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: refs}); !errors.Is(err, ErrForbidden) {
				t.Fatal("grant minted credential capability", err)
			}
			for _, actor := range []identitydomain.Actor{{TenantID: "tenant", KeyID: "key"}, {TenantID: "tenant", CollectorID: "collector"}} {
				for _, scope := range []string{tc.scope, "admin", "*"} {
					actor.Scopes = []string{scope}
					if err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: refs}); err != nil {
						t.Fatal("issued capability denied", scope, err)
					}
				}
				actor.Scopes = []string{"instance:admin", "unrelated"}
				if err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: refs}); !errors.Is(err, ErrForbidden) {
					t.Fatal("instance capability crossed source boundary", err)
				}
			}
		})
	}
}

func TestSourcePolicyRejectsUnresolvedCoordinatesAndPhasePromotion(t *testing.T) {
	for _, tc := range sourceCases {
		actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{tc.scope}}
		base := ResourceReferences{ProductID: "product", ProjectID: "project"}
		for i := 0; i < reflect.TypeOf(base).NumField(); i++ {
			refs := base
			value := reflect.ValueOf(&refs).Elem().Field(i)
			if value.String() == "" {
				value.SetString("foreign")
			} else {
				value.SetString("")
			}
			if err := Authorize(t.Context(), actor, Request{Action: tc.action, Resources: refs}); !errors.Is(err, ErrForbidden) {
				t.Fatal("unresolved/unsupported source coordinate", tc.action, refs, err)
			}
		}
		for _, mode := range []Evaluation{ScopeEvaluation, TenantEvaluation, Evaluation(255)} {
			if err := Authorize(t.Context(), actor, Request{Action: tc.action, Evaluation: mode, Resources: base}); !errors.Is(err, ErrForbidden) {
				t.Fatal("phase discarded source coordinates", tc.action, mode, err)
			}
		}
	}
}

func TestSourceReadVisibilityRetainsProductProjectButNotReleaseAuthority(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "sso", Scopes: []string{"source:read"}, ResourceGrants: []identitydomain.ResourceGrant{
		{ResourceType: "product", ResourceID: "product-b", Scopes: []string{"source:read"}},
		{ResourceType: "product", ResourceID: "product-a", Scopes: []string{"*"}},
		{ResourceType: "product", ResourceID: "product-a", Scopes: []string{"admin"}},
		{ResourceType: "project", ResourceID: "project", Scopes: []string{"source:read"}},
		{ResourceType: "release", ResourceID: "release", Scopes: []string{"source:read"}},
		{ResourceType: "product", ResourceID: "wrong-scope", Scopes: []string{"source:write"}},
		{ResourceType: "tenant", ResourceID: "foreign", Scopes: []string{"*"}},
	}}
	visibility, err := ReadVisibility(t.Context(), actor, "source_repositories.read")
	want := Visibility{TenantID: "tenant", ProductIDs: []string{"product-a", "product-b"}, ProjectIDs: []string{"project"}}
	if err != nil || !reflect.DeepEqual(visibility, want) {
		t.Fatal("source filters", visibility, want, err)
	}
	actor.ResourceGrants = nil
	visibility, err = ReadVisibility(t.Context(), actor, "source_repositories.read")
	if err != nil || !reflect.DeepEqual(visibility, Visibility{TenantID: "tenant"}) {
		t.Fatal("revoked source filters", visibility, err)
	}
}
