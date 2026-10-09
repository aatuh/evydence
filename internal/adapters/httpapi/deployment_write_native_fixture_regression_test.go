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
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

func TestDeploymentWriteNativeFixturesUseCurrentStateExplicitTimeAndAtomicEffects(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("deployment command used aggregate clock") }})
	clock := &evidenceFlowFixtureClock{at: time.Date(2026, 10, 9, 12, 0, 0, 123456000, time.UTC)}
	f := deploymentFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}, clock: clock}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"deployment:write"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"deployment:write"}}}}
	input := operationsapp.CreateEnvironmentInput{ProductID: owner.product.ID, Name: " Production ", Kind: " production "}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AuthorizeEnvironmentCreation(t.Context(), human, input); err != nil {
		t.Fatal("environment guard used stale aggregate ownership", err)
	}
	guarded, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, guarded) || clock.calls != 0 {
		t.Fatal("preflight performed metadata/effects/time", err)
	}
	env, err := f.CreateDeploymentEnvironment(t.Context(), human, input)
	if err != nil || env.ID == "" || env.ProductID != owner.product.ID || env.TenantID != human.TenantID || env.Name != "Production" || env.Kind != "production" || env.SchemaVersion != operationsdomain.DeploymentEnvironmentVersion || env.CreatedAt != clock.at || clock.calls != 1 {
		t.Fatal("environment command lost explicit resources or full DTO", err)
	}
	afterEnv, err := base.Snapshot()
	if err != nil || len(afterEnv.DeploymentEnvironments) != len(before.DeploymentEnvironments)+1 || len(afterEnv.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+1 {
		t.Fatal("environment/audit did not commit together", err)
	}
	input.Kind = "staging"
	if reused, err := f.CreateDeploymentEnvironment(t.Context(), human, input); err != nil || reused != env || clock.calls != 1 {
		t.Fatal("natural reuse amended metadata or allocated time", err)
	}
	finished := clock.at.Add(time.Hour)
	deploy := operationsapp.RecordDeploymentInput{EnvironmentID: env.ID, ReleaseID: owner.release.ID, Status: "succeeded", FinishedAt: &finished}
	if err := f.AuthorizeDeploymentRecording(t.Context(), human, deploy); err != nil || clock.calls != 1 {
		t.Fatal("deployment preflight used caches/time/effects", err)
	}
	event, err := f.RecordDeployment(t.Context(), human, deploy)
	if err != nil || event.ID == "" || event.EnvironmentID != env.ID || event.ReleaseID != owner.release.ID || event.TenantID != human.TenantID || event.Status != "succeeded" || event.StartedAt != clock.at || event.CreatedAt != clock.at || event.FinishedAt == nil || *event.FinishedAt != finished || event.EvidenceID == "" || event.SchemaVersion != operationsdomain.DeploymentEventSchemaVersion || clock.calls != 2 {
		t.Fatal("deployment command lost public fields/time", err)
	}
	after, err := base.Snapshot()
	if err != nil || len(after.DeploymentEvents) != len(before.DeploymentEvents)+1 || len(after.Evidence) != len(before.Evidence)+1 || len(after.AuditEntries[human.TenantID]) != len(afterEnv.AuditEntries[human.TenantID])+2 || !reflect.DeepEqual(after.OutboxJobs, before.OutboxJobs) {
		t.Fatal("event/evidence/audit effects were not atomic or queued extra work", err)
	}
	evidence := after.Evidence[event.EvidenceID]
	if evidence.DeploymentID != event.ID || evidence.ProductID != env.ProductID || evidence.ReleaseID != event.ReleaseID || evidence.Type != "deployment" || evidence.Subtype != "event" || evidence.CanonicalHash == "" || evidence.ChainEntryID == "" || len(evidence.Limitations) == 0 {
		t.Fatal("fixed-shape evidence back-reference or limitations lost")
	}
	canonical, err := application.NormalizedJSONHash(domain.EvidenceFromContextModel(evidencedomain.CanonicalEvidenceFields(domain.EvidenceToContextModel(evidence))))
	if err != nil || canonical != evidence.CanonicalHash {
		t.Fatal("deployment evidence canonical commitment is not reproducible", err)
	}
	for _, entry := range after.AuditEntries[human.TenantID][len(before.AuditEntries[human.TenantID]):] {
		if entry.ActorType != "human_user" || entry.ActorID != human.UserID {
			t.Fatal("human audit attribution lost")
		}
	}
	factory.fail = true
	input.Name = "Failed"
	if v, err := f.CreateDeploymentEnvironment(t.Context(), human, input); err == nil || v != (operationsdomain.DeploymentEnvironment{}) {
		t.Fatal("failed commit returned environment", err)
	}
	if v, err := f.RecordDeployment(t.Context(), human, deploy); err == nil || !reflect.DeepEqual(v, operationsdomain.DeploymentEvent{}) {
		t.Fatal("failed commit returned deployment", err)
	}
	factory.fail = false
	failed, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, failed) {
		t.Fatal("failed write commit published partial state", err)
	}
}

func TestDeploymentWriteNativeFixturesDenyForeignAndRevokedScopeAndPreserveBindings(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	foreign := seedOperationsFixtureScope(t, ledger, "Foreign")
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: base, Now: func() time.Time { panic("native deployment used aggregate clock") }})
	clock := &evidenceFlowFixtureClock{at: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	f := deploymentFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}, clock: clock}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	input := operationsapp.CreateEnvironmentInput{ProductID: foreign.product.ID, Name: "Production", Kind: "production"}
	if err := f.AuthorizeEnvironmentCreation(t.Context(), owner.actor, input); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("foreign environment product accepted", err)
	}
	if v, err := f.CreateDeploymentEnvironment(t.Context(), owner.actor, input); !errors.Is(err, app.ErrNotFound) || v != (operationsdomain.DeploymentEnvironment{}) {
		t.Fatal("foreign product was written", err)
	}
	input.ProductID = owner.product.ID
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"deployment:write"}}
	if err := f.AuthorizeEnvironmentCreation(t.Context(), human, input); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("revoked environment grant accepted", err)
	}
	if _, err := f.CreateDeploymentEnvironment(t.Context(), human, input); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("revoked environment grant wrote", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) || clock.calls != 0 {
		t.Fatal("denial allocated time or wrote state", err)
	}
	explicit := &deploymentHTTPFake{}
	s := &Server{deploymentEnvironmentCommands: deploymentFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, clock: clock}, deploymentCommands: explicit}
	s.bindDeploymentFixturePorts(rebound)
	bound, ok := s.deploymentEnvironmentCommands.(deploymentFixtureCommands)
	if !ok || bound.ledger != rebound || bound.clock != clock || s.deploymentCommands != explicit {
		t.Fatal("rebind discarded explicit clock or replaced injected command")
	}
	bare := deploymentFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture"})}}
	if v, err := bare.CreateDeploymentEnvironment(t.Context(), owner.actor, input); !errors.Is(err, app.ErrValidation) || v != (operationsdomain.DeploymentEnvironment{}) {
		t.Fatal("missing repositories restored cached creation", err)
	}
	if err := bare.AuthorizeEnvironmentCreation(t.Context(), owner.actor, input); !errors.Is(err, app.ErrValidation) {
		t.Fatal("missing repositories restored environment preflight", err)
	}
	deployment := operationsapp.RecordDeploymentInput{EnvironmentID: "environment", ReleaseID: owner.release.ID, Status: "succeeded"}
	if err := bare.AuthorizeDeploymentRecording(t.Context(), owner.actor, deployment); !errors.Is(err, app.ErrValidation) {
		t.Fatal("missing repositories restored deployment preflight", err)
	}
	if v, err := bare.RecordDeployment(t.Context(), owner.actor, deployment); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v, operationsdomain.DeploymentEvent{}) {
		t.Fatal("missing repositories restored deployment writes", err)
	}
	var missingContext context.Context
	if _, err := f.CreateDeploymentEnvironment(missingContext, owner.actor, input); !errors.Is(err, app.ErrValidation) {
		t.Fatal("nil environment context accepted", err)
	}
	if _, err := f.RecordDeployment(missingContext, owner.actor, deployment); !errors.Is(err, app.ErrValidation) {
		t.Fatal("nil deployment context accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.CreateDeploymentEnvironment(ctx, owner.actor, input); !errors.Is(err, context.Canceled) {
		t.Fatal("environment cancellation lost", err)
	}
	if _, err := f.RecordDeployment(ctx, owner.actor, deployment); !errors.Is(err, context.Canceled) {
		t.Fatal("deployment cancellation lost", err)
	}
}

func TestDeploymentWriteNativeFixturesBindArtifactRollbackAndCurrentReleaseScope(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	foreign := seedOperationsFixtureScope(t, ledger, "Foreign")
	artifact, err := ledger.RegisterArtifact(t.Context(), owner.actor, "Owned", "application/octet-stream", "sha256:"+strings.Repeat("a", 64), 1)
	if err != nil {
		t.Fatal(err)
	}
	foreignArtifact, err := ledger.RegisterArtifact(t.Context(), foreign.actor, "Foreign", "application/octet-stream", "sha256:"+strings.Repeat("b", 64), 1)
	if err != nil {
		t.Fatal(err)
	}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: base, Now: func() time.Time { panic("deployment reference checks used aggregate clock") }})
	f := deploymentFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}}
	env, err := f.CreateDeploymentEnvironment(t.Context(), owner.actor, operationsapp.CreateEnvironmentInput{ProductID: owner.product.ID, Name: "Production", Kind: "production"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := f.CreateDeploymentEnvironment(t.Context(), owner.actor, operationsapp.CreateEnvironmentInput{ProductID: owner.product.ID, Name: "Staging", Kind: "staging"})
	if err != nil {
		t.Fatal(err)
	}
	foreignEnv, err := f.CreateDeploymentEnvironment(t.Context(), foreign.actor, operationsapp.CreateEnvironmentInput{ProductID: foreign.product.ID, Name: "Foreign", Kind: "production"})
	if err != nil {
		t.Fatal(err)
	}
	otherProduct, err := ledger.CreateProduct(t.Context(), owner.actor, "Other", "other")
	if err != nil {
		t.Fatal(err)
	}
	otherRelease, err := ledger.CreateRelease(t.Context(), owner.actor, otherProduct.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	input := operationsapp.RecordDeploymentInput{EnvironmentID: env.ID, ReleaseID: owner.release.ID, Status: "succeeded", ArtifactIDs: []string{artifact.ID}}
	original, err := f.RecordDeployment(t.Context(), owner.actor, input)
	if err != nil {
		t.Fatal(err)
	}
	input.RollbackOf, input.Status = original.ID, "rolled_back"
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"deployment:write"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "release", ResourceID: owner.release.ID, Scopes: []string{"deployment:write"}}}}
	if err := f.AuthorizeDeploymentRecording(t.Context(), human, input); err != nil {
		t.Fatal("release grant denied owned rollback preflight", err)
	}
	rolled, err := f.RecordDeployment(t.Context(), human, input)
	if err != nil || rolled.RollbackOf != original.ID || rolled.ID == original.ID || !reflect.DeepEqual(rolled.ArtifactIDs, input.ArtifactIDs) {
		t.Fatal("rollback changed original event or lost artifact coordinates", err)
	}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		actor  domain.Actor
		change func(*operationsapp.RecordDeploymentInput)
		want   error
	}{
		{"foreign environment", owner.actor, func(v *operationsapp.RecordDeploymentInput) { v.EnvironmentID = foreignEnv.ID }, app.ErrNotFound},
		{"foreign release", owner.actor, func(v *operationsapp.RecordDeploymentInput) { v.ReleaseID = foreign.release.ID }, app.ErrNotFound},
		{"cross-product release", owner.actor, func(v *operationsapp.RecordDeploymentInput) { v.ReleaseID = otherRelease.ID }, app.ErrNotFound},
		{"foreign artifact", owner.actor, func(v *operationsapp.RecordDeploymentInput) { v.ArtifactIDs = []string{foreignArtifact.ID} }, app.ErrNotFound},
		{"rollback other environment", owner.actor, func(v *operationsapp.RecordDeploymentInput) { v.EnvironmentID = other.ID }, app.ErrNotFound},
		{"missing rollback", owner.actor, func(v *operationsapp.RecordDeploymentInput) { v.RollbackOf = "missing" }, app.ErrNotFound},
		{"revoked grant", domain.Actor{TenantID: human.TenantID, UserID: human.UserID, Scopes: human.Scopes}, func(*operationsapp.RecordDeploymentInput) {}, app.ErrForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := input
			tc.change(&v)
			if err := f.AuthorizeDeploymentRecording(t.Context(), tc.actor, v); !errors.Is(err, tc.want) {
				t.Fatal("unsafe reference/grant accepted by preflight", err)
			}
			if result, err := f.RecordDeployment(t.Context(), tc.actor, v); !errors.Is(err, tc.want) || !reflect.DeepEqual(result, operationsdomain.DeploymentEvent{}) {
				t.Fatal("unsafe reference/grant wrote deployment", err)
			}
		})
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("denied deployment references changed state", err)
	}
}
