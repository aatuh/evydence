package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type controlArtifactGrantFake struct {
	requests []ControlEvidenceArtifactGrantRequest
	visible  bool
	err      error
}

func TestControlEvidenceArtifactGrantBudgets(t *testing.T) {
	base := ControlEvidenceArtifactGrantRequest{TenantID: "tenant", ArtifactID: "artifact", AllowedProductIDs: []string{"product"}}
	for _, test := range []struct {
		name   string
		change func(*ControlEvidenceArtifactGrantRequest)
	}{
		{"missing tenant", func(r *ControlEvidenceArtifactGrantRequest) { r.TenantID = "" }},
		{"missing artifact", func(r *ControlEvidenceArtifactGrantRequest) { r.ArtifactID = "" }},
		{"unbounded filter", func(r *ControlEvidenceArtifactGrantRequest) { r.ProductID = strings.Repeat("x", 1025) }},
		{"NUL filter", func(r *ControlEvidenceArtifactGrantRequest) { r.ReleaseID = "bad\x00id" }},
		{"no grants", func(r *ControlEvidenceArtifactGrantRequest) { r.AllowedProductIDs = nil }},
		{"invalid grant text", func(r *ControlEvidenceArtifactGrantRequest) { r.AllowedProjectIDs = []string{string([]byte{0xff})} }},
		{"excessive grants", func(r *ControlEvidenceArtifactGrantRequest) { r.AllowedProjectIDs = make([]string, 4096) }},
		{"excessive bytes", func(r *ControlEvidenceArtifactGrantRequest) {
			for i := 0; i < 64; i++ {
				r.AllowedProjectIDs = append(r.AllowedProjectIDs, strings.Repeat("x", 1024))
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			v := base
			test.change(&v)
			if ValidControlEvidenceArtifactGrantRequest(v) {
				t.Fatal("excessive grant input accepted", test.name)
			}
		})
	}
	if !ValidControlEvidenceArtifactGrantRequest(base) {
		t.Fatal("normal grant request rejected")
	}
	large := base
	large.AllowedProductIDs = nil
	for i := 0; i < 64; i++ {
		large.AllowedProjectIDs = append(large.AllowedProjectIDs, strings.Repeat("x", 1024))
	}
	if !ValidControlEvidenceArtifactGrantRequest(large) {
		t.Fatal("exact byte budget rejected")
	}
	large.AllowedProjectIDs = make([]string, 4096)
	for i := range large.AllowedProjectIDs {
		large.AllowedProjectIDs[i] = "x"
	}
	if !ValidControlEvidenceArtifactGrantRequest(large) {
		t.Fatal("exact count budget rejected")
	}
}

func (f *controlArtifactGrantFake) ControlEvidenceArtifactVisible(_ context.Context, r ControlEvidenceArtifactGrantRequest) (bool, error) {
	f.requests = append(f.requests, r)
	return f.visible, f.err
}

func TestControlEvidenceWriteAuthorizerUsesCurrentGrantsAndStrictRequestShapes(t *testing.T) {
	for _, test := range []struct {
		name    string
		actor   identitydomain.Actor
		request application.AuthorizationRequest
		want    error
	}{
		{"anonymous", identitydomain.Actor{}, application.AuthorizationRequest{Scope: ScopeControlsWrite, ScopeOnly: true}, application.ErrUnauthorized},
		{"wrong credential scope", identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"controls:read"}}, application.AuthorizationRequest{Scope: ScopeControlsWrite, ScopeOnly: true}, application.ErrForbidden},
		{"key", identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{ScopeControlsWrite}}, application.AuthorizationRequest{Scope: ScopeControlsWrite, Resources: application.ResourceReferences{ProductID: "product"}}, nil},
		{"collector", identitydomain.Actor{TenantID: "tenant", CollectorID: "collector", Scopes: []string{ScopeControlsWrite}}, application.AuthorizationRequest{Scope: ScopeControlsWrite}, nil},
		{"human preflight", identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{ScopeControlsWrite}}, application.AuthorizationRequest{Scope: ScopeControlsWrite, ScopeOnly: true}, nil},
		{"removed human grant", identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{ScopeControlsWrite}}, application.AuthorizationRequest{Scope: ScopeControlsWrite, Resources: application.ResourceReferences{ProductID: "product"}}, application.ErrForbidden},
		{"scope-only references", identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{ScopeControlsWrite}}, application.AuthorizationRequest{Scope: ScopeControlsWrite, ScopeOnly: true, Resources: application.ResourceReferences{ProductID: "product"}}, application.ErrForbidden},
		{"unrelated references", identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{ScopeControlsWrite}}, application.AuthorizationRequest{Scope: ScopeControlsWrite, Resources: application.ResourceReferences{BuildID: "build"}}, application.ErrForbidden},
		{"unsupported action", identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"admin"}}, application.AuthorizationRequest{Scope: "controls:admin", ScopeOnly: true}, application.ErrForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := &controlArtifactGrantFake{}
			a, err := NewControlEvidenceWriteAuthorizer(f)
			if err != nil {
				t.Fatal(err)
			}
			err = a.Authorize(t.Context(), test.actor, test.request)
			if !errors.Is(err, test.want) || len(f.requests) != 0 {
				t.Fatal("authorization changed", err, f.requests)
			}
		})
	}
	for _, kind := range []string{"tenant", "product", "project", "release"} {
		actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{ScopeControlsWrite}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: kind, ResourceID: kind, Scopes: []string{ScopeControlsWrite}}}}
		a, _ := NewControlEvidenceWriteAuthorizer(&controlArtifactGrantFake{})
		request := application.AuthorizationRequest{Scope: ScopeControlsWrite, Resources: application.ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release"}}
		if err := a.Authorize(t.Context(), actor, request); err != nil {
			t.Fatal(kind, err)
		}
		actor.ResourceGrants[0].ResourceID = "other"
		if err := a.Authorize(t.Context(), actor, request); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("foreign grant allowed", kind, err)
		}
		actor.ResourceGrants[0].ResourceID = kind
		actor.ResourceGrants[0].Scopes = []string{"controls:read"}
		if err := a.Authorize(t.Context(), actor, request); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("wrong action grant allowed", kind, err)
		}
	}
}

func TestControlEvidenceArtifactAuthorizationCarriesScopeFiltersBeforeAssociationLimit(t *testing.T) {
	f := &controlArtifactGrantFake{visible: true}
	a, err := NewControlEvidenceWriteAuthorizer(f)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{ScopeControlsWrite}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project-b", Scopes: []string{ScopeControlsWrite}}, {ResourceType: "project", ResourceID: "project-a", Scopes: []string{ScopeControlsWrite}}, {ResourceType: "release", ResourceID: "foreign", Scopes: []string{"controls:read"}}}}
	r := application.AuthorizationRequest{Scope: ScopeControlsWrite, Resources: application.ResourceReferences{ArtifactID: "artifact", ProductID: "product", ReleaseID: "release"}}
	if err := a.Authorize(t.Context(), actor, r); err != nil {
		t.Fatal(err)
	}
	want := ControlEvidenceArtifactGrantRequest{TenantID: "tenant", ArtifactID: "artifact", ProductID: "product", ReleaseID: "release", AllowedProjectIDs: []string{"project-a", "project-b"}}
	if !reflect.DeepEqual(f.requests, []ControlEvidenceArtifactGrantRequest{want}) {
		t.Fatal("artifact filters or grants changed", f.requests)
	}
	f.visible = false
	if err := a.Authorize(t.Context(), actor, r); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("invisible artifact allowed", err)
	}
	f.err = errors.New("private storage error")
	if err := a.Authorize(t.Context(), actor, r); !errors.Is(err, f.err) {
		t.Fatal("storage failure ignored", err)
	}
	actor.ResourceGrants = nil
	before := len(f.requests)
	if err := a.Authorize(t.Context(), actor, r); !errors.Is(err, application.ErrForbidden) || len(f.requests) != before {
		t.Fatal("no grants triggered association read", err)
	}
	if _, err := NewControlEvidenceWriteAuthorizer(nil); !errors.Is(err, ErrValidation) {
		t.Fatal("missing artifact reader accepted", err)
	}
}
