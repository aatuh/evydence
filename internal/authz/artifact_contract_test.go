package authz_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

type artifactPolicyReader struct {
	requests []releasequery.ArtifactReadRequest
	point    releasequery.ArtifactPoint
	err      error
}

func (r *artifactPolicyReader) GetArtifactPoint(_ context.Context, request releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	r.requests = append(r.requests, request)
	return r.point, r.err
}

func TestArtifactDelegatesRequireTheirTypedActionAndCurrentTenantPoint(t *testing.T) {
	for _, tc := range []struct {
		name    string
		factory func(releasequery.ArtifactPointReader) (application.Authorizer, error)
		actions []authz.Action
		scope   string
	}{
		{"write", releasequery.NewArtifactWriteAuthorizer, []authz.Action{authz.ActionArtifactsWrite, authz.ActionEvidenceWrite}, "evidence:write"},
		{"security", releasequery.NewArtifactSecurityWriteAuthorizer, []authz.Action{authz.ActionSecurityEvidenceWrite}, "security:write"},
		{"read", releasequery.NewArtifactReadAuthorizer, []authz.Action{authz.ActionEvidenceDiffsCreate, authz.ActionVEXPreviewRead}, "evidence:read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &artifactPolicyReader{point: releasequery.ArtifactPoint{Artifact: releasedomain.Artifact{ID: "artifact", TenantID: "tenant"}, Visible: true}}
			policy, err := tc.factory(reader)
			if err != nil {
				t.Fatal(err)
			}
			actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", SessionID: "sso", Scopes: []string{tc.scope}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{tc.scope}}}}
			for _, action := range tc.actions {
				request := application.AuthorizationRequest{Action: action, Resources: application.ResourceReferences{ArtifactID: "artifact"}}
				before := len(reader.requests)
				if err := policy.Authorize(t.Context(), actor, request); err != nil || len(reader.requests) != before+1 || !reader.requests[before].TenantWide || reader.requests[before].TenantID != "tenant" || reader.requests[before].ID != "artifact" {
					t.Fatal("typed tenant artifact proof", action, reader.requests, err)
				}
				for _, bad := range []application.AuthorizationRequest{
					{Scope: tc.scope, Resources: request.Resources},
					{Action: action, Scope: tc.scope, Resources: request.Resources},
					{Action: authz.ActionEvidenceRead, Resources: request.Resources},
					{Action: action, TenantWide: true, Resources: request.Resources},
					{Action: action, Resources: application.ResourceReferences{ArtifactID: "artifact", ProductID: "product"}},
				} {
					before = len(reader.requests)
					if err := policy.Authorize(t.Context(), actor, bad); !errors.Is(err, application.ErrForbidden) || len(reader.requests) != before {
						t.Fatal("wrong operation/envelope reached storage", bad, err)
					}
				}
				reader.point.Artifact.TenantID = "foreign"
				if err := policy.Authorize(t.Context(), actor, request); !errors.Is(err, application.ErrForbidden) {
					t.Fatal("foreign point authorized", err)
				}
				reader.point.Artifact.TenantID = "tenant"
				reader.err = releasequery.ErrNotFound
				if err := policy.Authorize(t.Context(), actor, request); !errors.Is(err, application.ErrForbidden) {
					t.Fatal("missing artifact revealed/authorized", err)
				}
				reader.err = nil
			}
		})
	}
}

func TestArtifactDelegatesDoNotRetainLocalGrantDecisions(t *testing.T) {
	for _, path := range []string{"../release/query/artifact_write_authorizer.go", "../release/query/artifact_read_authorizer.go", "../release/query/build_authorizer.go", "../release/query/candidate_authorizer.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if selector, ok := node.(*ast.SelectorExpr); ok && (selector.Sel.Name == "ResourceGrants" || selector.Sel.Name == "HasScope" || selector.Sel.Name == "HasExplicitScope") {
				t.Errorf("%s retains local grant policy: %s", path, selector.Sel.Name)
			}
			if call, ok := node.(*ast.CallExpr); ok {
				if name, ok := call.Fun.(*ast.Ident); ok && name.Name == "artifactVisibilityForScope" {
					t.Errorf("%s still selects artifact grants locally", path)
				}
			}
			return true
		})
	}
}
