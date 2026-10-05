package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestControlEvidenceLocalFreshRejectsForeignFramework(t *testing.T) {
	l, _, a := newReleaseEvidenceUnitOfWorkFixture(t, NewMemoryUnitOfWorkFactory())
	p, err := l.CreateProduct(t.Context(), a, "Product", "product")
	if err != nil {
		t.Fatal(err)
	}
	f, err := l.CreateControlFramework(t.Context(), a, CreateControlFrameworkInput{Name: "Framework", Version: "1"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := l.CreateSecurityControl(t.Context(), a, CreateSecurityControlInput{FrameworkID: f.ID, Code: "C", Title: "T", Objective: "O"})
	if err != nil {
		t.Fatal(err)
	}
	f.TenantID = "other"
	l.frameworks[f.ID] = f
	if v, err := l.LinkControlEvidence(t.Context(), a, c.ID, LinkControlEvidenceInput{EvidenceType: "sbom", SubjectType: "product", SubjectID: p.ID, Confidence: "high"}); !errors.Is(err, ErrNotFound) || v.ID != "" {
		t.Fatal("local link accepted foreign current framework", err)
	}
}

func TestControlEvidenceLocalHasCurrentReplayGuard(t *testing.T) {
	l, _, _ := newReleaseEvidenceUnitOfWorkFixture(t, NewMemoryUnitOfWorkFactory())
	if _, ok := any(l).(interface {
		AuthorizeControlEvidenceLink(context.Context, domain.Actor, string, LinkControlEvidenceInput) error
	}); !ok {
		t.Fatal("local linking has no current-scope replay guard")
	}
}

func TestControlEvidenceLocalProductGrantUsesActualSubject(t *testing.T) {
	l, _, a := newReleaseEvidenceUnitOfWorkFixture(t, NewMemoryUnitOfWorkFactory())
	p, err := l.CreateProduct(t.Context(), a, "Product", "product")
	if err != nil {
		t.Fatal(err)
	}
	f, err := l.CreateControlFramework(t.Context(), a, CreateControlFrameworkInput{Name: "Framework", Version: "1"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := l.CreateSecurityControl(t.Context(), a, CreateSecurityControlInput{FrameworkID: f.ID, Code: "C", Title: "T", Objective: "O"})
	if err != nil {
		t.Fatal(err)
	}
	human := domain.Actor{TenantID: a.TenantID, UserID: "human", Scopes: []string{ScopeControlsWrite, ScopeControlsRead}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: p.ID, Scopes: []string{ScopeControlsWrite, ScopeControlsRead}}}}
	in := LinkControlEvidenceInput{EvidenceType: "sbom", SubjectType: "product", SubjectID: p.ID, Confidence: "high"}
	if _, err := l.LinkControlEvidence(t.Context(), human, c.ID, in); err != nil {
		t.Fatal("local linking lost actual product grant", err)
	}
	links, err := l.ListControlEvidence(t.Context(), human, c.ID, "", "")
	if err != nil || len(links) != 1 {
		t.Fatal("local product link missing from same-grant read", err, len(links))
	}
}
