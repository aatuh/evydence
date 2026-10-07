package httpapi

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type failingPackageFixtureCommands struct {
	packageFixtureCommands
	createdID string
	isolated  bool
}

func (f *failingPackageFixtureCommands) failAfterWrite(ctx context.Context, id string, err error) error {
	if err != nil {
		return err
	}
	f.createdID, f.isolated = id, f.commandLedger(ctx) != f.ledger
	return errors.New("private package fixture failure")
}
func (f *failingPackageFixtureCommands) CreateCustomReportTemplate(ctx context.Context, actor domain.Actor, input packageapp.CreateReportTemplateInput) (packagedomain.CustomReportTemplate, error) {
	value, err := f.packageFixtureCommands.CreateCustomReportTemplate(ctx, actor, input)
	return value, f.failAfterWrite(ctx, value.ID, err)
}
func (f *failingPackageFixtureCommands) RenderCustomReport(ctx context.Context, actor domain.Actor, input packageapp.RenderReportInput) (packagedomain.RenderedCustomReport, error) {
	value, err := f.packageFixtureCommands.RenderCustomReport(ctx, actor, input)
	return value, f.failAfterWrite(ctx, value.ID, err)
}
func (f *failingPackageFixtureCommands) ImportEvidenceBundle(ctx context.Context, actor domain.Actor, input packagedomain.EvidenceBundle) (packagedomain.EvidenceBundleImport, error) {
	value, err := f.packageFixtureCommands.ImportEvidenceBundle(ctx, actor, input)
	return value, f.failAfterWrite(ctx, value.ID, err)
}
func (f *failingPackageFixtureCommands) ExportEvidenceBundle(ctx context.Context, actor domain.Actor, release string, ids []string) (packagedomain.EvidenceBundle, error) {
	value, err := f.packageFixtureCommands.ExportEvidenceBundle(ctx, actor, release, ids)
	return value, f.failAfterWrite(ctx, value.ID, err)
}

func TestPackageFixtureCommandsRollBackAllEffectsAfterWriteFailure(t *testing.T) {
	for _, action := range []string{"template", "render", "import", "export"} {
		t.Run(action, func(t *testing.T) {
			factory := app.NewMemoryUnitOfWorkFactory()
			ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory})
			scope := seedEvidenceFixtureScope(t, ledger, "Fixture")
			path, body := "/v1/report-templates", `{"name":"Definition","version":"1","report_type":"metadata","allowed_fields":["subject_id"]}`
			switch action {
			case "render":
				template, err := ledger.CreateCustomReportTemplate(t.Context(), scope.actor, app.CreateReportTemplateInput{Name: "Definition", Version: "1", ReportType: "metadata", AllowedFields: []string{"subject_id"}})
				if err != nil {
					t.Fatal(err)
				}
				path, body = "/v1/report-templates/"+template.ID+"/render", `{"subject_type":"label","subject_id":"public-label"}`
			case "import":
				path, body = "/v1/evidence-bundles/import", bundleImportNativeBody(t)
			case "export":
				path, body = "/v1/evidence-bundles", `{}`
			}
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			// The actor was authenticated during seeding. Do not let unrelated
			// heartbeat writes confound the all-effects rollback assertion.
			server.authn = &configuredAuthenticator{actor: scope.actor}
			commands := &failingPackageFixtureCommands{packageFixtureCommands: packageFixtureCommands{catalogFixtureCommands{ledger: ledger}}}
			server.reportTemplateCommands, server.bundleImportCommand, server.evidenceBundleCommands = commands, commands, commands
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, server, scope.secret, path, "fixture-package-failure", []byte(body), 500)
			if commands.createdID == "" || !commands.isolated || strings.Contains(out, commands.createdID) || strings.Contains(out, `"data"`) || strings.Contains(out, "private package") {
				t.Fatal("failed package command bypassed isolation or exposed partial results")
			}
			after, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if len(after.Idempotency) != 1 {
				t.Fatal("failed package command lost its replay failure record")
			}
			for _, record := range after.Idempotency {
				if record.State != app.IdempotencyFailed || record.Response != nil || record.Status != 0 {
					t.Fatal("failed package command stored a partial response")
				}
			}
			// The failed replay record is intentional. All definition, render,
			// import, export, signature, audit and other effects must roll back.
			after.Idempotency = before.Idempotency
			if !reflect.DeepEqual(before, after) {
				t.Fatal("failed package command committed repository effects")
			}
			if action == "template" {
				err := ledger.AuthorizeReportRendering(t.Context(), scope.actor, packageapp.RenderReportInput{TemplateID: commands.createdID, SubjectType: "label", SubjectID: "public-label"})
				if !errors.Is(err, app.ErrNotFound) {
					t.Fatal("failed template was published to fixture authorization", err)
				}
			}
		})
	}
}

func TestPackageFixtureReplayCannotBypassSavedResponseAuthorization(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper"})
	scope := seedEvidenceFixtureScope(t, ledger, "Fixture")
	executor := catalogFixtureReplayExecutor{ledger: ledger}
	guards, replayGuards, runs := 0, 0, 0
	authorize := func(context.Context) error { guards++; return nil }
	run := func(context.Context) (int, any, error) {
		runs++
		return 201, map[string]any{"id": "saved-response"}, nil
	}
	if _, _, err := executor.WithBodyReplayAuthorization(t.Context(), scope.actor, "POST", "/fixture", "saved", []byte(`{}`), authorize, nil, run); !errors.Is(err, app.ErrValidation) || guards+runs != 0 {
		t.Fatal("missing replay guard was accepted or produced effects", err)
	}
	deny := false
	authorizeReplay := func(_ context.Context, response any) error {
		replayGuards++
		value, ok := response.(map[string]any)
		if !ok || value["id"] != "saved-response" {
			t.Fatal("fixture replay guard lost the original response")
		}
		if deny {
			return app.ErrForbidden
		}
		return nil
	}
	for i := range 3 {
		deny = i == 2
		status, response, err := executor.WithBodyReplayAuthorization(t.Context(), scope.actor, "POST", "/fixture", "saved", []byte(`{}`), authorize, authorizeReplay, run)
		if deny {
			if !errors.Is(err, app.ErrForbidden) || status != 0 || response != nil {
				t.Fatal("saved response escaped current replay authorization", err)
			}
		} else if err != nil || status != 201 || response == nil {
			t.Fatal("authorized fixture result was lost", err)
		}
	}
	if guards != 3 || replayGuards != 3 || runs != 1 {
		t.Fatal("fixture replay skipped a guard or repeated business work", guards, replayGuards, runs)
	}
}
