package httpapi

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
)

func TestRepositoryIngestionScopeGuardsUseOneCurrentOwnershipOnlyTransaction(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	guardPhase := false
	at := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory, Now: func() time.Time {
		if guardPhase {
			panic("ownership guard read aggregate clock")
		}
		return at
	}})
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	foreign := seedOperationsFixtureScope(t, ledger, "Foreign")
	p := owner.product
	p.ID, p.Name, p.Slug = "repository-product", strings.Repeat("private", 10000), "repository-product"
	v := owner.release
	v.ID, v.ProductID, v.Version = "repository-release", p.ID, strings.Repeat("private", 10000)
	j := domain.Project{ID: "repository-project", TenantID: p.TenantID, ProductID: p.ID, Name: strings.Repeat("private", 10000), CreatedAt: at}
	if err := ledger.ExecuteUnitOfWork(t.Context(), func(ctx context.Context, r app.Repositories) error {
		if err := r.ReleaseCatalog.InsertProduct(ctx, p); err != nil {
			return err
		}
		if err := r.ReleaseCatalog.InsertProject(ctx, j); err != nil {
			return err
		}
		return r.ReleaseCatalog.InsertRelease(ctx, v)
	}); err != nil {
		t.Fatal(err)
	}
	commands := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, repositoryScope: true}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"evidence:write", "security:write"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: p.ID, Scopes: []string{"*"}}}}
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	guardPhase = true
	for _, tc := range []struct {
		name string
		run  func(context.Context, domain.Actor) error
	}{
		{"SBOM", func(ctx context.Context, a domain.Actor) error {
			return commands.AuthorizeUploadSBOM(ctx, a, evidenceapp.SBOMIngestionInput{ReleaseID: v.ID, Format: "cyclonedx"})
		}},
		{"VEX", func(ctx context.Context, a domain.Actor) error {
			return commands.AuthorizeUploadVEX(ctx, a, evidenceapp.VEXIngestionInput{ReleaseID: v.ID, Format: "openvex"})
		}},
		{"OpenAPI", func(ctx context.Context, a domain.Actor) error {
			return commands.AuthorizeUploadOpenAPIContract(ctx, a, evidenceapp.OpenAPIIngestionInput{ProductID: p.ID, ReleaseID: v.ID, Version: "1"})
		}},
		{"scan", func(ctx context.Context, a domain.Actor) error {
			return commands.AuthorizeUploadVulnerabilityScan(ctx, a, evidenceapp.VulnerabilityScanScope{ReleaseID: v.ID})
		}},
		{"security", func(ctx context.Context, a domain.Actor) error {
			return commands.AuthorizeUploadSecurityScan(ctx, a, evidenceapp.UploadSecurityScanInput{ProductID: p.ID, ReleaseID: v.ID, Category: "sast", Scanner: "fixture", TargetRef: "source", Raw: []byte("{}")})
		}},
		{"manual", func(ctx context.Context, a domain.Actor) error {
			return commands.AuthorizeUploadManualSecurityDocument(ctx, a, evidenceapp.UploadManualSecurityDocumentInput{ProductID: p.ID, ReleaseID: v.ID, DocumentType: "pen_test_report", Title: "Review", Sensitivity: "restricted", Raw: []byte("{}")})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			begins := factory.beginCalls
			if err := tc.run(t.Context(), human); err != nil {
				t.Fatal("guard selected catalog metadata/cache instead of owned IDs", err)
			}
			if factory.beginCalls != begins+1 {
				t.Fatal("scope validation and authorization did not share one transaction", factory.beginCalls-begins)
			}
			denied := human
			denied.ResourceGrants = nil
			if err := tc.run(t.Context(), denied); !errors.Is(err, application.ErrForbidden) {
				t.Fatal("current grant removal did not revoke guard", err)
			}
			denied = human
			denied.TenantID, denied.KeyID, denied.UserID = foreign.actor.TenantID, foreign.actor.KeyID, ""
			if err := tc.run(t.Context(), denied); !errors.Is(err, evidenceapp.ErrNotFound) {
				t.Fatal("foreign actor reached owned guard coordinates", err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			begins = factory.beginCalls
			if err := tc.run(ctx, human); !errors.Is(err, context.Canceled) || factory.beginCalls != begins {
				t.Fatal("cancelled guard opened a transaction", err)
			}
		})
	}
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("guard issued/wrote payload, evidence, audit, jobs, keys or replay state", err)
	}
}

func TestRepositoryIngestionScopeGuardDoesNotFallbackAfterCommitOrRepositoryFailure(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory})
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	commands := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, repositoryScope: true}
	input := evidenceapp.SBOMIngestionInput{ReleaseID: owner.release.ID, Format: "cyclonedx"}
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	factory.fail = true
	rollbacks := factory.rollbacks
	if err := commands.AuthorizeUploadSBOM(t.Context(), owner.actor, input); err == nil || !strings.Contains(err.Error(), "private-query-commit") || factory.rollbacks != rollbacks+1 {
		t.Fatal("failed guard commit passed or leaked transaction", err)
	}
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed guard commit wrote state", err)
	}
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: &configuredAuthenticator{actor: owner.actor}})
	if err != nil {
		t.Fatal(err)
	}
	server.bindRepositoryIngestionFixtureScope()
	body := postRaw(t, server, "fixture", "/v1/sboms", "failed-guard", []byte(`{"release_id":"`+owner.release.ID+`","payload":{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}}`), 500)
	if strings.Contains(body, "private-query") || strings.Contains(body, `"data"`) || strings.Contains(body, `"payload"`) {
		t.Fatal("failed guard exposed internal error or partial document", body)
	}
	after, err = factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed HTTP preflight reserved replay or wrote document effects", err)
	}
	// These parents genuinely exist in legacy caches. Explicit native mode
	// must still fail closed if its repository dependency is unavailable.
	legacy := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	legacyOwner := seedOperationsFixtureScope(t, legacy, "Legacy")
	commands = ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: legacy}, repositoryScope: true}
	input.ReleaseID = legacyOwner.release.ID
	if err := commands.AuthorizeUploadSBOM(t.Context(), legacyOwner.actor, input); !errors.Is(err, evidenceapp.ErrValidation) {
		t.Fatal("native guard silently accepted a legacy repository fallback", err)
	}
}

func TestRepositoryIngestionScopeBindingSurvivesRebindingAndPreservesExplicitPorts(t *testing.T) {
	first := newLegacyLedgerFixture(app.Config{UnitOfWork: app.NewMemoryUnitOfWorkFactory()})
	server, err := newLegacyServerFixture(first)
	if err != nil {
		t.Fatal(err)
	}
	server.bindRepositoryIngestionFixtureScope()
	second := newLegacyLedgerFixture(app.Config{UnitOfWork: app.NewMemoryUnitOfWorkFactory()})
	server.bindLegacyLedgerFixture(second)
	for _, port := range []any{server.sbomIngestionCommands, server.vexIngestionCommands, server.openAPIIngestionCommands, server.scanIngestionCommands, server.securityDocumentCommands} {
		f, ok := port.(ingestionFixtureCommands)
		if !ok || !f.repositoryScope || f.ledger != second {
			t.Fatal("rebind discarded explicit repository scope or retained old root")
		}
	}
	sbom := &struct{ SBOMIngestionCommands }{}
	vex := &struct{ VEXIngestionCommands }{}
	openapi := &struct{ OpenAPIIngestionCommands }{}
	scan := &struct {
		VulnerabilityScanIngestionCommands
	}{}
	security := &struct{ SecurityDocumentCommands }{}
	server.sbomIngestionCommands, server.vexIngestionCommands, server.openAPIIngestionCommands, server.scanIngestionCommands, server.securityDocumentCommands = sbom, vex, openapi, scan, security
	server.bindRepositoryIngestionFixtureScope()
	server.bindLegacyLedgerFixture(first)
	if server.sbomIngestionCommands != sbom || server.vexIngestionCommands != vex || server.openAPIIngestionCommands != openapi || server.scanIngestionCommands != scan || server.securityDocumentCommands != security {
		t.Fatal("fixture wiring replaced explicitly injected command ports")
	}
}
