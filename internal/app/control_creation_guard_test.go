package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestControlCreationLocalRejectsNarrowGrantAndRawBudget(t *testing.T) {
	l, _, a := newReleaseEvidenceUnitOfWorkFixture(t, NewMemoryUnitOfWorkFactory())
	human := domain.Actor{TenantID: a.TenantID, UserID: "user", Scopes: []string{ScopeControlsAdmin}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{ScopeControlsAdmin}}}}
	if _, err := l.CreateControlFramework(t.Context(), human, CreateControlFrameworkInput{Name: "Denied", Version: "1"}); !errors.Is(err, ErrForbidden) {
		t.Fatal("local framework bypassed tenant grant", err)
	}
	if _, err := l.CreateControlFramework(t.Context(), a, CreateControlFrameworkInput{Name: "F", Slug: strings.Repeat(" ", 1025) + "f", Version: "1"}); !errors.Is(err, ErrValidation) {
		t.Fatal("local raw slug bypassed budget", err)
	}
}

func TestControlCreationLocalReplayGuardsAreReadOnlyAndCurrent(t *testing.T) {
	l, _, a := newReleaseEvidenceUnitOfWorkFixture(t, NewMemoryUnitOfWorkFactory())
	l.frameworks["parent"] = domain.ControlFramework{ID: "parent", TenantID: a.TenantID, Slug: "f", Version: "1", Name: strings.Repeat("private-", 1200000)}
	l.controls["existing"] = domain.SecurityControl{ID: "existing", TenantID: a.TenantID, FrameworkID: "parent", Code: "C", Objective: strings.Repeat("private-", 1200000)}
	l.now = func() time.Time { panic("guard read clock") }
	before := len(l.chain[a.TenantID])
	f := CreateControlFrameworkInput{Name: "F", Version: "1"}
	c := CreateSecurityControlInput{FrameworkID: "parent", Code: "C", Title: "T", Objective: "O"}
	if err := l.AuthorizeControlFrameworkCreation(t.Context(), a, f); err != nil {
		t.Fatal("guard consulted existing framework version", err)
	}
	if err := l.AuthorizeSecurityControlCreation(t.Context(), a, c); err != nil {
		t.Fatal("guard consulted duplicate control or metadata", err)
	}
	human := domain.Actor{TenantID: a.TenantID, UserID: "human", Scopes: []string{ScopeControlsAdmin}}
	if err := l.AuthorizeControlFrameworkCreation(t.Context(), human, f); !errors.Is(err, ErrForbidden) {
		t.Fatal("revoked human framework grant accepted", err)
	}
	if err := l.AuthorizeSecurityControlCreation(t.Context(), human, c); !errors.Is(err, ErrForbidden) {
		t.Fatal("revoked human control grant accepted", err)
	}
	parent := l.frameworks["parent"]
	parent.TenantID = "other"
	l.frameworks["parent"] = parent
	if err := l.AuthorizeSecurityControlCreation(t.Context(), a, c); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign current framework accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := l.AuthorizeControlFrameworkCreation(ctx, a, f); !errors.Is(err, context.Canceled) {
		t.Fatal("guard cancellation lost", err)
	}
	if len(l.chain[a.TenantID]) != before || len(l.frameworks) != 1 || len(l.controls) != 1 {
		t.Fatal("local control guard wrote effects")
	}
}

func TestControlCreationLocalHasCurrentReplayGuards(t *testing.T) {
	l, _, _ := newReleaseEvidenceUnitOfWorkFixture(t, NewMemoryUnitOfWorkFactory())
	if _, ok := any(l).(interface {
		AuthorizeControlFrameworkCreation(context.Context, domain.Actor, CreateControlFrameworkInput) error
		AuthorizeSecurityControlCreation(context.Context, domain.Actor, CreateSecurityControlInput) error
	}); !ok {
		t.Fatal("local manual creation has no read-only replay guards")
	}
}
