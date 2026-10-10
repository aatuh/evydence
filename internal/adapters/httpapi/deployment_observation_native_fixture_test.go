package httpapi

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
)

func TestDeploymentObservationNativeFixtureReadsCurrentScopeAndFailsClosed(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	foreign := seedOperationsFixtureScope(t, ledger, "Foreign")
	commands := deploymentFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	env, err := commands.CreateDeploymentEnvironment(t.Context(), owner.actor, operationsapp.CreateEnvironmentInput{ProductID: owner.product.ID, Name: "Production", Kind: "production"})
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := commands.RecordDeployment(t.Context(), owner.actor, operationsapp.RecordDeploymentInput{EnvironmentID: env.ID, ReleaseID: owner.release.ID, Status: "succeeded"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := releaseSetup(ledger).RegisterArtifact(t.Context(), owner.actor, "Artifact", "text/plain", "sha256:"+strings.Repeat("a", 64), 1)
	if err != nil {
		t.Fatal(err)
	}
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("observation used aggregate clock") }})
	f := evidenceCreationNativeFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"evidence:write"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "release", ResourceID: owner.release.ID, Scopes: []string{"evidence:write"}}}}
	input := evidenceapp.CreateEvidenceInput{ProductID: owner.product.ID, ReleaseID: owner.release.ID, DeploymentID: deployment.ID, Type: "deployment", Subtype: "observation", Title: "Deployment observation", PayloadHash: artifact.Digest}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AuthorizeEvidenceCreation(t.Context(), human, input); err != nil {
		t.Fatal("observation guard lost repository-only deployment", err)
	}
	artifactInput := input
	artifactInput.SubjectRefs = []evidencedomain.SubjectRef{{Type: "artifact", ID: artifact.ID}}
	if err := f.AuthorizeEvidenceCreation(t.Context(), owner.actor, artifactInput); err != nil {
		t.Fatal("artifact identity preflight lost current subject", err)
	}
	guarded, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, guarded) {
		t.Fatal("observation preflight wrote state", err)
	}
	v, err := f.CreateEvidence(t.Context(), human, input)
	if err != nil || v.ID == "" || v.TenantID != human.TenantID || v.ProductID != owner.product.ID || v.ReleaseID != owner.release.ID || v.DeploymentID != deployment.ID || v.Type != input.Type || v.Subtype != input.Subtype || v.Title != input.Title || v.PayloadHash != input.PayloadHash || v.CanonicalHash == "" || v.ChainEntryID == "" {
		t.Fatal("observation creation used caches or lost public fields", err)
	}
	after, err := base.Snapshot()
	if err != nil || len(after.Evidence) != len(before.Evidence)+1 || len(after.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+1 {
		t.Fatal("observation/audit effects did not commit together", err)
	}
	foreignInput := input
	foreignInput.ReleaseID = foreign.release.ID
	if err := f.AuthorizeEvidenceCreation(t.Context(), owner.actor, foreignInput); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("foreign observation parent accepted", err)
	}
	human.ResourceGrants = nil
	if err := f.AuthorizeEvidenceCreation(t.Context(), human, input); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("revoked observation grant accepted", err)
	}
	factory.fail = true
	if v, err := f.CreateEvidence(t.Context(), owner.actor, input); err == nil || !reflect.DeepEqual(v, evidencedomain.EvidenceItem{}) {
		t.Fatal("failed observation transaction exposed evidence", err)
	}
	factory.fail = false
	failed, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, failed) {
		t.Fatal("denied/failed observation changed state", err)
	}
	bare := evidenceCreationNativeFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture"})}}
	if v, err := bare.CreateEvidence(t.Context(), owner.actor, input); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v, evidencedomain.EvidenceItem{}) {
		t.Fatal("missing repository restored observation caches", err)
	}
}
