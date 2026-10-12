package authz

import (
	"errors"
	"reflect"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var verificationCases = []struct {
	action Action
	scope  string
	kind   string
}{
	{"evidence.verify", "verify:read", "evidence"}, {"dsse.verify", "verify:read", "evidence"},
	{"audit_chain.verify", "verify:read", "tenant"}, {"merkle_batch.verify", "verify:read", "tenant"},
	{"merkle_checkpoint.verify", "verify:read", "tenant"}, {"release_manifest_checkpoint.verify", "verify:read", "tenant"},
	{"backup_manifest.verify", "verify:read", "tenant"}, {"release_bundle.verify", "verify:read", "release"},
	{"cosign.verify", "verify:read", "artifact"}, {"artifact_signature.verify", "verify:read", "artifact"},
	{"subject_verification.dispatch", "verify:read", "dispatch"}, {"artifact_signatures.read", "evidence:read", "signature"},
}

func verificationRequest(tc struct {
	action      Action
	scope, kind string
}) Request {
	request := Request{Action: tc.action}
	switch tc.kind {
	case "evidence":
		request.Resources = ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release", BuildID: "build", DeploymentID: "deployment"}
	case "release":
		request.Resources = ResourceReferences{ProductID: "product", ReleaseID: "release"}
	case "artifact":
		request.Resources = ResourceReferences{ArtifactID: "artifact"}
	case "signature":
		request.Resources = ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release"}
	case "tenant":
		request.Evaluation = TenantEvaluation
	case "dispatch":
		request.Evaluation = ScopeEvaluation
	}
	return request
}

func TestVerificationPolicyPreservesActionSpecificAuthorityAndRevocation(t *testing.T) {
	for _, tc := range verificationCases {
		t.Run(string(tc.action), func(t *testing.T) {
			request := verificationRequest(tc)
			actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "sso", Scopes: []string{tc.scope}}
			for _, kind := range []string{"tenant", "product", "project", "release", "artifact", "build", "deployment"} {
				for _, scope := range []string{tc.scope, "admin", "*"} {
					actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: kind, ResourceID: kind, Scopes: []string{scope}}}
					allow := tc.kind == "dispatch" || kind == "tenant" ||
						(tc.kind == "evidence" || tc.kind == "signature") && (kind == "product" || kind == "project" || kind == "release") ||
						tc.kind == "release" && (kind == "product" || kind == "release")
					err := Authorize(t.Context(), actor, request)
					if allow && err != nil || !allow && !errors.Is(err, ErrForbidden) {
						t.Fatal("action-specific grant", kind, scope, allow, err)
					}
				}
				actor.ResourceGrants[0].ResourceID = "foreign"
				if err := Authorize(t.Context(), actor, request); tc.kind != "dispatch" && !errors.Is(err, ErrForbidden) {
					t.Fatal("foreign grant", kind, err)
				}
			}
			actor.ResourceGrants = nil
			if err := Authorize(t.Context(), actor, request); tc.kind != "dispatch" && !errors.Is(err, ErrForbidden) {
				t.Fatal("revoked grant", err)
			}
			actor.Scopes = []string{"instance:admin", "unrelated"}
			actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"*"}}}
			if err := Authorize(t.Context(), actor, request); !errors.Is(err, ErrForbidden) {
				t.Fatal("grant or instance scope minted verifier capability", err)
			}
			for _, actor := range []identitydomain.Actor{{TenantID: "tenant", KeyID: "key"}, {TenantID: "tenant", CollectorID: "collector"}} {
				for _, scope := range []string{tc.scope, "admin", "*"} {
					actor.Scopes = []string{scope}
					if err := Authorize(t.Context(), actor, request); err != nil {
						t.Fatal("issued capability", scope, err)
					}
				}
			}
		})
	}
}

func TestVerificationPolicyRejectsStrayCoordinatesAndPhasePromotion(t *testing.T) {
	for _, tc := range verificationCases {
		actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{tc.scope}}
		request := verificationRequest(tc)
		for i := 0; i < reflect.TypeOf(request.Resources).NumField(); i++ {
			if reflect.ValueOf(request.Resources).Field(i).String() != "" {
				continue
			}
			invalid := request
			reflect.ValueOf(&invalid.Resources).Elem().Field(i).SetString("foreign")
			if err := Authorize(t.Context(), actor, invalid); !errors.Is(err, ErrForbidden) {
				t.Fatal("unsupported verification coordinate", tc.action, invalid, err)
			}
		}
		if err := Authorize(t.Context(), actor, Request{Action: tc.action, Evaluation: ScopeEvaluation}); err != nil {
			t.Fatal("registered verifier preflight", tc.action, err)
		}
		if tc.kind == "dispatch" {
			for _, mode := range []Evaluation{ResolvedEvaluation, TenantEvaluation} {
				if err := Authorize(t.Context(), actor, Request{Action: tc.action, Evaluation: mode}); !errors.Is(err, ErrForbidden) {
					t.Fatal("dispatcher preflight promoted to authority", mode, err)
				}
			}
		}
	}
}

func TestArtifactSignatureVisibilityUsesEvidenceReadGrantsAndCurrentRevocation(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "sso", Scopes: []string{"evidence:read"}, ResourceGrants: []identitydomain.ResourceGrant{
		{ResourceType: "product", ResourceID: "product-b", Scopes: []string{"evidence:read"}},
		{ResourceType: "product", ResourceID: "product-a", Scopes: []string{"admin"}},
		{ResourceType: "product", ResourceID: "product-a", Scopes: []string{"*"}},
		{ResourceType: "project", ResourceID: "project", Scopes: []string{"evidence:read"}},
		{ResourceType: "release", ResourceID: "release", Scopes: []string{"evidence:read"}},
		{ResourceType: "product", ResourceID: "verify-only", Scopes: []string{"verify:read"}},
	}}
	visibility, err := ReadVisibility(t.Context(), actor, "artifact_signatures.read")
	want := Visibility{TenantID: "tenant", ProductIDs: []string{"product-a", "product-b"}, ProjectIDs: []string{"project"}, ReleaseIDs: []string{"release"}}
	if err != nil || !reflect.DeepEqual(visibility, want) {
		t.Fatal("signature visibility", visibility, want, err)
	}
	actor.ResourceGrants = nil
	visibility, err = ReadVisibility(t.Context(), actor, "artifact_signatures.read")
	if err != nil || !reflect.DeepEqual(visibility, Visibility{TenantID: "tenant"}) {
		t.Fatal("revoked signature visibility", visibility, err)
	}
	actor.Scopes = []string{"verify:read"}
	if visibility, err = ReadVisibility(t.Context(), actor, "artifact_signatures.read"); !errors.Is(err, ErrForbidden) || !reflect.DeepEqual(visibility, Visibility{}) {
		t.Fatal("verification capability implied signature metadata read", visibility, err)
	}
}
