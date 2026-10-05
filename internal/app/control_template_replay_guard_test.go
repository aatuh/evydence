package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestControlTemplateLocalGuardUsesCurrentTenantAuthorityOnly(t *testing.T) {
	l, _, a := newReleaseEvidenceUnitOfWorkFixture(t, NewMemoryUnitOfWorkFactory())
	pack := builtinTemplatePacks()[0]
	l.frameworks["historical"] = domain.ControlFramework{ID: "historical", TenantID: a.TenantID, Slug: pack.Slug, Version: pack.Version, Name: strings.Repeat("private-", 1200000)}
	l.now = func() time.Time { panic("local replay read clock") }
	beforeFrameworks, beforeControls, beforeAudit := len(l.frameworks), len(l.controls), len(l.chain[a.TenantID])
	if err := l.AuthorizeControlTemplateInstallation(t.Context(), a, " "+pack.Slug+" "); err != nil {
		t.Fatal(err)
	}
	human := a
	human.UserID = "human"
	human.KeyID, human.CollectorID = "", ""
	human.Scopes = []string{ScopeControlsAdmin}
	for _, grant := range []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: a.TenantID, Scopes: []string{ScopeControlsAdmin}}, {ResourceType: "tenant", ResourceID: "other", Scopes: []string{ScopeControlsAdmin}}, {ResourceType: "product", ResourceID: "product", Scopes: []string{ScopeControlsAdmin}}} {
		human.ResourceGrants = []identitydomain.ResourceGrant{grant}
		want := ErrForbidden
		if grant.ResourceType == "tenant" && grant.ResourceID == a.TenantID {
			want = nil
		}
		if err := l.AuthorizeControlTemplateInstallation(t.Context(), human, pack.Slug); !errors.Is(err, want) {
			t.Fatal("local replay grant bypass", grant, err)
		}
	}
	for _, bad := range []string{" tenant", strings.Repeat("x", 1025), "bad\x00tenant", string([]byte{0xff})} {
		actor := a
		actor.TenantID = bad
		if err := l.AuthorizeControlTemplateInstallation(t.Context(), actor, pack.Slug); !errors.Is(err, ErrValidation) {
			t.Fatal("invalid local tenant coordinate", err)
		}
	}
	missing := a
	missing.TenantID = "missing"
	if err := l.AuthorizeControlTemplateInstallation(t.Context(), missing, pack.Slug); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing tenant accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := l.AuthorizeControlTemplateInstallation(ctx, a, pack.Slug); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	if err := l.AuthorizeControlTemplateInstallation(nil, a, pack.Slug); !errors.Is(err, context.Canceled) { //nolint:staticcheck // Deliberately test rejection of a nil caller context.
		t.Fatal("nil context accepted", err)
	}
	if len(l.frameworks) != beforeFrameworks || len(l.controls) != beforeControls || len(l.chain[a.TenantID]) != beforeAudit {
		t.Fatal("local replay changed effects")
	}
}

func TestControlTemplateLocalFreshInstallRejectsNarrowGrantAndRawBudget(t *testing.T) {
	l, _, a := newReleaseEvidenceUnitOfWorkFixture(t, NewMemoryUnitOfWorkFactory())
	pack := builtinTemplatePacks()[0]
	human := a
	human.UserID = "human"
	human.KeyID, human.CollectorID = "", ""
	human.Scopes = []string{ScopeControlsAdmin}
	human.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{ScopeControlsAdmin}}}
	if v, err := l.InstallControlFrameworkTemplatePack(t.Context(), human, pack.Slug); !errors.Is(err, ErrForbidden) || v.ID != "" {
		t.Fatal("local fresh install bypassed tenant admin", err)
	}
	if v, err := l.InstallControlFrameworkTemplatePack(t.Context(), a, strings.Repeat(" ", 1025)+pack.Slug); !errors.Is(err, ErrValidation) || v.ID != "" {
		t.Fatal("local fresh install bypassed raw budget", err)
	}
}
