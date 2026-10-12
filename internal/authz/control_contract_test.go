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
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

type controlAssociationReader struct{ calls int }

func (r *controlAssociationReader) ControlEvidenceArtifactVisible(_ context.Context, _ riskapp.ControlEvidenceArtifactGrantRequest) (bool, error) {
	r.calls++
	return true, nil
}

func TestControlLinkFactoryRejectsLegacyScopesOtherActionsAndAmbiguousPhases(t *testing.T) {
	reader := &controlAssociationReader{}
	policy, err := riskapp.NewControlEvidenceWriteAuthorizer(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"*"}}
	refs := application.ResourceReferences{ArtifactID: "artifact", ProductID: "product", ReleaseID: "release"}
	for _, request := range []application.AuthorizationRequest{
		{Scope: "controls:write", Resources: refs},
		{Action: authz.ActionControlEvidenceLink, Scope: "controls:write", Resources: refs},
		{Action: authz.ActionControlEvidenceLink, ScopeOnly: true, TenantWide: true},
		{Action: authz.ActionControlEvidenceLink, ScopeOnly: true, Resources: refs},
		{Action: authz.ActionControlEvidenceLink, TenantWide: true, Resources: refs},
		{Action: authz.ActionControlsManage, TenantWide: true},
		{Action: authz.ActionControlEvidenceRead, Resources: refs},
		{Action: authz.ActionControlEvidenceLink, Resources: application.ResourceReferences{TenantID: "foreign", ArtifactID: "artifact"}},
	} {
		if err := policy.Authorize(t.Context(), actor, request); !errors.Is(err, application.ErrForbidden) || reader.calls != 0 {
			t.Fatalf("unsupported request=%#v calls=%d: %v", request, reader.calls, err)
		}
	}
}

func TestControlWriteRequestsAndGrantPolicyRemainCentral(t *testing.T) {
	for _, path := range []string{"../risk/app/control_commands.go", "../risk/app/control_evidence_guard.go", "../risk/app/control_evidence_validation.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		requests := 0
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			kind, ok := literal.Type.(*ast.SelectorExpr)
			if !ok || kind.Sel.Name != "AuthorizationRequest" {
				return true
			}
			requests++
			action := false
			for _, field := range literal.Elts {
				pair, ok := field.(*ast.KeyValueExpr)
				if !ok {
					t.Errorf("%s unkeyed authority", path)
					continue
				}
				key, ok := pair.Key.(*ast.Ident)
				if !ok {
					continue
				}
				if key.Name == "Scope" {
					t.Errorf("%s scope-string authority", path)
				}
				if key.Name == "Action" {
					action = true
				}
			}
			if !action {
				t.Errorf("%s missing typed action", path)
			}
			return true
		})
		if requests == 0 {
			t.Fatalf("%s request coverage disappeared", path)
		}
	}
	file, err := parser.ParseFile(token.NewFileSet(), "../risk/app/control_evidence_authorizer.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	central := 0
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if selector.Sel.Name == "ResourceGrants" || selector.Sel.Name == "HasScope" || selector.Sel.Name == "HasExplicitScope" {
			t.Errorf("local control grant policy: %s", selector.Sel.Name)
		}
		if qualifier, ok := selector.X.(*ast.Ident); ok && qualifier.Name == "authz" && selector.Sel.Name == "AuthorizeWithArtifactVisibility" {
			central++
		}
		return true
	})
	if central == 0 {
		t.Fatal("control artifact policy no longer central")
	}
}
