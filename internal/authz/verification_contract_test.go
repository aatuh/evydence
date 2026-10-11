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
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func TestVerificationDelegatesRequireTypedActionAndRejectSharedScopeSubstitution(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"verify:read"}}
	for _, tc := range []struct {
		policy application.Authorizer
		action authz.Action
		refs   application.ResourceReferences
		wide   bool
	}{
		{verificationquery.NewEvidenceVerificationAuthorizer(), "evidence.verify", application.ResourceReferences{ProjectID: "project"}, false},
		{verificationquery.NewEvidenceVerificationAuthorizer(), "dsse.verify", application.ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release", BuildID: "build"}, false},
		{verificationquery.NewEvidenceVerificationAuthorizer(), "audit_chain.verify", application.ResourceReferences{}, true},
		{verificationquery.NewEvidenceVerificationAuthorizer(), "merkle_batch.verify", application.ResourceReferences{}, true},
		{verificationquery.NewEvidenceVerificationAuthorizer(), "merkle_checkpoint.verify", application.ResourceReferences{}, true},
		{verificationquery.NewEvidenceVerificationAuthorizer(), "release_manifest_checkpoint.verify", application.ResourceReferences{}, true},
		{verificationquery.NewEvidenceVerificationAuthorizer(), "backup_manifest.verify", application.ResourceReferences{}, true},
		{verificationquery.NewCosignVerificationAuthorizer(), "cosign.verify", application.ResourceReferences{ArtifactID: "artifact"}, false},
		{verificationquery.NewCosignVerificationAuthorizer(), "artifact_signature.verify", application.ResourceReferences{ArtifactID: "artifact"}, false},
		{verificationquery.NewReleaseBundleVerificationAuthorizer(), "release_bundle.verify", application.ResourceReferences{ProductID: "product", ReleaseID: "release"}, false},
	} {
		t.Run(string(tc.action), func(t *testing.T) {
			request := application.AuthorizationRequest{Action: tc.action, Resources: tc.refs, TenantWide: tc.wide}
			if err := tc.policy.Authorize(t.Context(), actor, request); err != nil {
				t.Fatal("typed verifier denied", request, err)
			}
			for _, bad := range []application.AuthorizationRequest{
				{Scope: "verify:read", Resources: tc.refs, TenantWide: tc.wide},
				{Action: tc.action, Scope: "verify:read", Resources: tc.refs, TenantWide: tc.wide},
				{Action: tc.action, ScopeOnly: true, TenantWide: true},
				{Action: authz.ActionEvidenceRead, Resources: tc.refs, TenantWide: tc.wide},
				{Action: "subject_verification.dispatch", Resources: tc.refs, TenantWide: tc.wide},
			} {
				if err := tc.policy.Authorize(t.Context(), actor, bad); !errors.Is(err, application.ErrForbidden) {
					t.Fatal("scope/operation substitution authorized", bad, err)
				}
			}
		})
	}
}

func TestSubjectVerificationDelegateCannotPromoteDispatchPreflightOrSelectCosign(t *testing.T) {
	policy := verificationquery.NewSubjectVerificationAuthorizer()
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"verify:read", "evidence:read"}}
	if err := policy.Authorize(t.Context(), actor, application.AuthorizationRequest{Action: authz.ActionSubjectVerificationDispatch, ScopeOnly: true}); err != nil {
		t.Fatal("dispatcher preflight", err)
	}
	for _, request := range []application.AuthorizationRequest{
		{Action: authz.ActionSubjectVerificationDispatch}, {Action: authz.ActionSubjectVerificationDispatch, TenantWide: true},
		{Action: authz.ActionCosignVerify, ScopeOnly: true},
		{Action: authz.ActionCosignVerify, Resources: application.ResourceReferences{ArtifactID: "artifact"}},
		{Action: authz.ActionArtifactSignaturesRead, Resources: application.ResourceReferences{ProductID: "product"}},
	} {
		if err := policy.Authorize(t.Context(), actor, request); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("dispatcher minted child/foreign-family authority", request, err)
		}
	}
	if err := policy.Authorize(t.Context(), actor, application.AuthorizationRequest{Action: authz.ActionArtifactSignatureVerify, Resources: application.ResourceReferences{ArtifactID: "artifact"}}); err != nil {
		t.Fatal("closed metadata-verification child", err)
	}
}

func TestVerificationCallersHaveOwnTypedActionsAndNoScopeFallback(t *testing.T) {
	for _, tc := range []struct{ path, action string }{
		{"evidence_verification.go", "ActionEvidenceVerify"}, {"dsse_verification.go", "ActionDSSEVerify"},
		{"audit_chain_verification.go", "ActionAuditChainVerify"}, {"merkle_verification.go", "ActionMerkleBatchVerify"},
		{"merkle_checkpoint_verification.go", "ActionMerkleCheckpointVerify"}, {"release_manifest_checkpoint.go", "ActionReleaseManifestCheckpointVerify"},
		{"backup_verification.go", "ActionBackupManifestVerify"}, {"release_bundle_verification.go", "ActionReleaseBundleVerify"},
		{"cosign_commands.go", "ActionCosignVerify"}, {"artifact_signature_verification.go", "ActionArtifactSignatureVerify"},
		{"subject_verification.go", "ActionSubjectVerificationDispatch"},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), "../verification/app/"+tc.path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		actions, requests := 0, 0
		ast.Inspect(file, func(node ast.Node) bool {
			if selector, ok := node.(*ast.SelectorExpr); ok {
				if qualifier, ok := selector.X.(*ast.Ident); ok && qualifier.Name == "authz" && selector.Sel.Name == tc.action {
					actions++
				}
			}
			literal, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			typ, ok := literal.Type.(*ast.SelectorExpr)
			if !ok || typ.Sel.Name != "AuthorizationRequest" {
				return true
			}
			requests++
			for _, element := range literal.Elts {
				field, ok := element.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if name, ok := field.Key.(*ast.Ident); ok && name.Name == "Scope" {
					t.Errorf("%s retains scope-string requests", tc.path)
				}
			}
			return true
		})
		if actions == 0 || requests == 0 {
			t.Errorf("%s has no covered own-action requests", tc.path)
		}
	}
}

func TestVerificationQueriesDoNotRetainLocalActorGrantPolicies(t *testing.T) {
	for _, path := range []string{"evidence_authorizer.go", "cosign_authorizer.go", "release_bundle_authorizer.go", "artifact_signature.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), "../verification/query/"+path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if selector, ok := node.(*ast.SelectorExpr); ok && (selector.Sel.Name == "ResourceGrants" || selector.Sel.Name == "HasScope" || selector.Sel.Name == "HasExplicitScope") {
				t.Errorf("%s retains local actor grants", path)
			}
			return true
		})
	}
}
