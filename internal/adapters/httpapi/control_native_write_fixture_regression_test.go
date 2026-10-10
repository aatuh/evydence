package httpapi

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func TestControlNativeWriteFixtureUsesCurrentParentsAndAtomicHumanAudits(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	factory := &operatorQueryFailureFactory{base: base}
	clock := &evidenceFlowFixtureClock{at: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	rebound := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("control write used aggregate clock") }})
	f := controlFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}, clock: clock}
	a := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"controls:admin", "controls:write"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: owner.actor.TenantID, Scopes: []string{"controls:admin"}}, {ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"controls:write"}}}}
	in := riskapp.CreateControlFrameworkInput{Name: " Manual ", Version: " 1 ", Description: " Guidance "}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AuthorizeControlFrameworkCreation(t.Context(), a, in); err != nil || clock.calls != 0 {
		t.Fatal("framework guard lost current tenant or used effects", err)
	}
	framework, err := f.CreateControlFramework(t.Context(), a, in)
	if err != nil || framework.ID == "" || framework.TenantID != a.TenantID || framework.Name != "Manual" || framework.Slug != "manual" || framework.Version != "1" || framework.Description != "Guidance" || framework.Status != "active" || framework.SchemaVersion != riskdomain.ControlFrameworkSchemaVersion || framework.CreatedAt != clock.at {
		t.Fatal("framework lost complete DTO/current tenant/time", err)
	}
	controlIn := riskapp.CreateSecurityControlInput{FrameworkID: framework.ID, Code: " BUILD ", Title: " Build review ", Objective: " Record evidence ", EvidenceRequirements: []riskdomain.ControlEvidenceRequirement{{Type: "build", Required: false, FreshnessDays: 30}}, Applicability: []string{" software ", "software"}, Limitations: []string{" Review ", " "}}
	if err := f.AuthorizeSecurityControlCreation(t.Context(), a, controlIn); err != nil || clock.calls != 1 {
		t.Fatal("control guard lost newly committed parent or used time", err)
	}
	control, err := f.CreateSecurityControl(t.Context(), a, controlIn)
	if err != nil || control.ID == "" || control.FrameworkID != framework.ID || control.TenantID != a.TenantID || control.Code != "BUILD" || control.Title != "Build review" || control.Objective != "Record evidence" || control.SchemaVersion != riskdomain.SecurityControlSchemaVersion || control.CreatedAt != clock.at || !reflect.DeepEqual(control.EvidenceRequirements, []riskdomain.ControlEvidenceRequirement{{Type: "build", Required: false, FreshnessDays: 30}}) || !reflect.DeepEqual(control.Applicability, []string{"software", "software"}) || !reflect.DeepEqual(control.Limitations, []string{"Review"}) {
		t.Fatal("control lost complete normalized definition", err)
	}
	linkIn := riskapp.LinkControlEvidenceInput{EvidenceType: "build", SubjectType: "evidence", SubjectID: owner.evidence.ID, ProductID: owner.product.ID, ReleaseID: owner.release.ID, Confidence: "high", Notes: " Reviewed "}
	if err := f.AuthorizeControlEvidenceLink(t.Context(), a, control.ID, linkIn); err != nil || clock.calls != 2 {
		t.Fatal("link guard lost current control/evidence or used time", err)
	}
	link, err := f.LinkControlEvidence(t.Context(), a, control.ID, linkIn)
	if err != nil || link.ID == "" || link.ControlID != control.ID || link.TenantID != a.TenantID || link.EvidenceType != "build" || link.SubjectType != "evidence" || link.SubjectID != owner.evidence.ID || link.ProductID != owner.product.ID || link.ReleaseID != owner.release.ID || link.Confidence != "high" || link.Notes != "Reviewed" || link.SchemaVersion != riskdomain.ControlEvidenceSchemaVersion || link.CreatedAt != clock.at || clock.calls != 3 {
		t.Fatal("link lost complete DTO/current subject/time", err)
	}
	if v, err := f.LinkControlEvidence(t.Context(), a, control.ID, linkIn); err != nil || v != link || clock.calls != 3 {
		t.Fatal("natural duplicate changed receipt or used time", err)
	}
	control.EvidenceRequirements[0].Type, control.Applicability[0], control.Limitations[0] = "modified", "modified", "modified"
	after, err := base.Snapshot()
	if err != nil || len(after.ControlFrameworks) != len(before.ControlFrameworks)+1 || len(after.SecurityControls) != len(before.SecurityControls)+1 || len(after.ControlEvidence) != len(before.ControlEvidence)+1 || len(after.AuditEntries[a.TenantID]) != len(before.AuditEntries[a.TenantID])+3 || after.SecurityControls[control.ID].EvidenceRequirements[0].Type != "build" || after.SecurityControls[control.ID].Applicability[0] != "software" || after.SecurityControls[control.ID].Limitations[0] != "Review" {
		t.Fatal("control effects were not atomic/detached", err)
	}
	for _, entry := range after.AuditEntries[a.TenantID][len(before.AuditEntries[a.TenantID]):] {
		if entry.ActorType != "human_user" || entry.ActorID != a.UserID {
			t.Fatal("human control audit attribution lost")
		}
	}
	if err := f.AuthorizeControlFrameworkCreation(t.Context(), a, in); err != nil {
		t.Fatal("historical replay guard checked duplicate metadata", err)
	}
	if _, err := f.CreateControlFramework(t.Context(), a, in); !errors.Is(err, app.ErrConflict) {
		t.Fatal("duplicate framework version accepted", err)
	}
	if _, err := f.CreateSecurityControl(t.Context(), a, controlIn); !errors.Is(err, app.ErrConflict) {
		t.Fatal("duplicate control code accepted", err)
	}
	factory.fail = true
	in.Version = "2"
	controlIn.Code = "NEW"
	linkIn.SubjectType, linkIn.SubjectID = "release", owner.release.ID
	if v, err := f.CreateControlFramework(t.Context(), a, in); err == nil || v != (riskdomain.ControlFramework{}) {
		t.Fatal("failed commit exposed framework", err)
	}
	if v, err := f.CreateSecurityControl(t.Context(), a, controlIn); err == nil || !reflect.DeepEqual(v, riskdomain.SecurityControl{}) {
		t.Fatal("failed commit exposed control", err)
	}
	if v, err := f.LinkControlEvidence(t.Context(), a, control.ID, linkIn); err == nil || v != (riskdomain.ControlEvidence{}) {
		t.Fatal("failed commit exposed link", err)
	}
	factory.fail = false
	failed, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, failed) {
		t.Fatal("duplicate/failed control writes changed state", err)
	}
}

func TestControlNativeWriteFixtureInstallsCompleteTemplateAtomically(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	clock := &evidenceFlowFixtureClock{at: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	factory := &operatorQueryFailureFactory{base: base}
	f := controlFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("template used aggregate clock") }})}, clock: clock}
	pack := riskdomain.BuiltinTemplatePacks()[0]
	if err := f.AuthorizeControlTemplateInstallation(t.Context(), owner.actor, pack.Slug); err != nil || clock.calls != 0 {
		t.Fatal("template guard used effects or lost current tenant", err)
	}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.InstallControlFrameworkTemplatePack(t.Context(), owner.actor, pack.Slug)
	if err != nil || v.ID == "" || v.Name != pack.Name || v.Slug != pack.Slug || v.Version != pack.Version || v.Description != pack.Description || v.TenantID != owner.actor.TenantID || v.Status != "active" || v.SchemaVersion != riskdomain.ControlFrameworkSchemaVersion || v.CreatedAt != clock.at {
		t.Fatal("template framework lost complete DTO", err)
	}
	after, err := base.Snapshot()
	if err != nil || len(after.SecurityControls) != len(before.SecurityControls)+len(pack.Controls) || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+1 {
		t.Fatal("template children/audit did not commit together", err)
	}
	for _, expected := range pack.Controls {
		found := false
		for _, c := range after.SecurityControls {
			if c.FrameworkID != v.ID || c.Code != expected.Code {
				continue
			}
			actual := fixtureSecurityControl(c)
			expected.ID, expected.TenantID, expected.FrameworkID, expected.SchemaVersion, expected.CreatedAt = actual.ID, owner.actor.TenantID, v.ID, riskdomain.SecurityControlSchemaVersion, clock.at
			if !reflect.DeepEqual(actual, expected) {
				t.Fatal("template child lost definition")
			}
			found = true
		}
		if !found {
			t.Fatal("template child missing")
		}
	}
	if err := f.AuthorizeControlTemplateInstallation(t.Context(), owner.actor, pack.Slug); err != nil {
		t.Fatal("template replay guard checked installed version", err)
	}
	if _, err := f.InstallControlFrameworkTemplatePack(t.Context(), owner.actor, pack.Slug); !errors.Is(err, app.ErrConflict) {
		t.Fatal("duplicate template version accepted", err)
	}
	factory.fail = true
	other := riskdomain.BuiltinTemplatePacks()[1]
	if result, err := f.InstallControlFrameworkTemplatePack(t.Context(), owner.actor, other.Slug); err == nil || result != (riskdomain.ControlFramework{}) {
		t.Fatal("failed template transaction exposed result", err)
	}
	factory.fail = false
	failed, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, failed) {
		t.Fatal("failed template published children/audit", err)
	}
}

func TestControlNativeWriteFixtureRejectsForeignReferencesRevokedGrantsAndMissingPorts(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedControlFixtureScope(t, ledger, "Owner")
	foreign := seedControlFixtureScope(t, ledger, "Foreign")
	f := controlFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: base})}, clock: &evidenceFlowFixtureClock{at: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if v, err := f.CreateSecurityControl(t.Context(), owner.actor, riskapp.CreateSecurityControlInput{FrameworkID: foreign.framework.ID, Code: "C", Title: "Title", Objective: "Record"}); !errors.Is(err, app.ErrNotFound) || !reflect.DeepEqual(v, riskdomain.SecurityControl{}) {
		t.Fatal("foreign framework accepted", err)
	}
	for _, pair := range []struct{ control, evidence string }{{foreign.control.ID, owner.evidence.ID}, {owner.control.ID, foreign.evidence.ID}} {
		if v, err := f.LinkControlEvidence(t.Context(), owner.actor, pair.control, riskapp.LinkControlEvidenceInput{EvidenceType: "build", SubjectType: "evidence", SubjectID: pair.evidence, Confidence: "high"}); !errors.Is(err, app.ErrNotFound) || v != (riskdomain.ControlEvidence{}) {
			t.Fatal("foreign link reference accepted", err)
		}
	}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"controls:admin", "controls:write"}}
	if _, err := f.CreateControlFramework(t.Context(), human, riskapp.CreateControlFrameworkInput{Name: "Denied", Version: "1"}); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("revoked admin grant accepted", err)
	}
	if _, err := f.InstallControlFrameworkTemplatePack(t.Context(), human, riskdomain.BuiltinTemplatePacks()[0].Slug); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("revoked template grant accepted", err)
	}
	if _, err := f.LinkControlEvidence(t.Context(), human, owner.control.ID, riskapp.LinkControlEvidenceInput{EvidenceType: "build", SubjectType: "evidence", SubjectID: owner.evidence.ID, Confidence: "high"}); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("revoked subject grant accepted", err)
	}
	bare := controlFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture"})}}
	if _, err := bare.CreateControlFramework(t.Context(), owner.actor, riskapp.CreateControlFrameworkInput{Name: "No repository", Version: "1"}); !errors.Is(err, app.ErrValidation) {
		t.Fatal("missing repository restored aggregate write", err)
	}
	var nilContext context.Context
	if _, err := f.CreateControlFramework(nilContext, owner.actor, riskapp.CreateControlFrameworkInput{Name: "Nil", Version: "1"}); !errors.Is(err, context.Canceled) {
		t.Fatal("nil control context accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.CreateSecurityControl(ctx, owner.actor, riskapp.CreateSecurityControlInput{FrameworkID: owner.framework.ID, Code: "C", Title: "Title", Objective: "Record"}); !errors.Is(err, context.Canceled) {
		t.Fatal("control cancellation lost", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("denied control operations changed state", err)
	}
	explicit := &controlCreationHTTPFake{}
	s := &Server{controlCommands: explicit, controlTemplateCommands: f, controlEvidenceCommands: f}
	s.bindControlFixtureCommands(ledger)
	if s.controlCommands != explicit || s.controlTemplateCommands.(controlFixtureCommands).clock != f.clock || s.controlEvidenceCommands.(controlFixtureCommands).clock != f.clock {
		t.Fatal("rebind replaced explicit port or clock")
	}
}
