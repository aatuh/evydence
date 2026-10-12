package httpapi

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

func TestCollectorNativeFixturePreflightUsesCurrentRepositoryWithoutEffects(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedIntegrationFixtureScope(t, ledger, "Owner")
	foreign := seedIntegrationFixtureScope(t, ledger, "Foreign")
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("collector preflight used aggregate clock") }})
	f := integrationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}}
	in := integrationapp.RecordCollectorReleaseInput{CollectorID: owner.collector.ID, Version: "2", ArtifactDigest: "sha256:" + strings.Repeat("b", 64), Pinned: true}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AuthorizeRecordCollectorRelease(t.Context(), owner.actor, in); err != nil {
		t.Fatal("current owned collector missing from release preflight", err)
	}
	in.CollectorID = foreign.collector.ID
	if err := f.AuthorizeRecordCollectorRelease(t.Context(), owner.actor, in); !errors.Is(err, integrationapp.ErrNotFound) {
		t.Fatal("foreign collector accepted by release preflight", err)
	}
	factory.fail = true
	in.CollectorID = owner.collector.ID
	if err := f.AuthorizeRecordCollectorRelease(t.Context(), owner.actor, in); err == nil {
		t.Fatal("preflight accepted a failed read commit")
	}
	factory.fail = false
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("release preflight published repository effects", err)
	}
}

func TestCollectorNativeFixturePinsAndHumanAuditCommitTogether(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedIntegrationFixtureScope(t, ledger, "Owner")
	foreign := seedIntegrationFixtureScope(t, ledger, "Foreign")
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("collector release used aggregate clock") }})
	f := integrationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"collector:admin", "collector:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: owner.actor.TenantID, Scopes: []string{"collector:admin", "collector:read"}}}}
	in := integrationapp.RecordCollectorReleaseInput{CollectorID: owner.collector.ID, Version: "2", ArtifactDigest: "sha256:" + strings.Repeat("b", 64), Pinned: true}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.RecordCollectorRelease(t.Context(), human, in)
	if err != nil || v.ID == "" || v.CollectorID != owner.collector.ID || !v.Pinned || v.VerificationStatus != "recorded" || v.HealthStatus != "needs_evidence" {
		t.Fatal("current collector command lost recorded release fields", err)
	}
	after, err := base.Snapshot()
	if err != nil || len(after.CollectorReleases) != len(before.CollectorReleases)+1 || len(after.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+1 || after.CollectorReleases[owner.release.ID].Pinned || !after.CollectorReleases[v.ID].Pinned || !after.CollectorReleases[foreign.release.ID].Pinned {
		t.Fatal("release, scoped pin replacement and audit did not commit together", err)
	}
	entry := after.AuditEntries[human.TenantID][len(after.AuditEntries[human.TenantID])-1]
	if entry.EntryType != "collector_release.recorded" || entry.SubjectID != owner.collector.ID || entry.ActorType != "human_user" || entry.ActorID != human.UserID || entry.PayloadHash != in.ArtifactDigest {
		t.Fatal("release audit lost human principal or digest binding")
	}
	v.Limitations[0] = "modified"
	factory.fail = true
	in.Version = "3"
	failed, err := f.RecordCollectorRelease(t.Context(), human, in)
	if err == nil || !reflect.DeepEqual(failed, integrationdomain.CollectorRelease{}) {
		t.Fatal("failed commit exposed a release", err)
	}
	factory.fail = false
	denied := human
	denied.ResourceGrants = nil
	if v, err := f.RecordCollectorRelease(t.Context(), denied, in); !errors.Is(err, app.ErrForbidden) || v.ID != "" {
		t.Fatal("revoked human grants accepted a release", err)
	}
	in.CollectorID = foreign.collector.ID
	if v, err := f.RecordCollectorRelease(t.Context(), human, in); !errors.Is(err, app.ErrNotFound) || v.ID != "" {
		t.Fatal("foreign collector accepted a release", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := f.RecordCollectorRelease(cancelled, human, in); !errors.Is(err, context.Canceled) || v.ID != "" {
		t.Fatal("cancelled command accepted a release", err)
	}
	final, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, final) {
		t.Fatal("failed, denied or detached result changed pin, release or audit state", err)
	}
}

func TestCollectorNativeFixtureHealthUsesCurrentRepositoryAndDiscardsFailedRead(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedIntegrationFixtureScope(t, ledger, "Owner")
	foreign := seedIntegrationFixtureScope(t, ledger, "Foreign")
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("collector health used aggregate clock") }})
	f := collectorHealthFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}, now: func() time.Time { return owner.collector.CreatedAt }}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.Report(t.Context(), owner.actor, owner.collector.ID)
	if err != nil || !reflect.DeepEqual(collectorHealthFromQuery(v), expectedSeedCollectorHealth(owner)) {
		t.Fatal("current health report lost independently enumerated public fields", err)
	}
	v.LatestRelease.Limitations[0] = "modified"
	v.Checks[0].Detail = "modified"
	factory.fail = true
	v, err = f.Report(t.Context(), owner.actor, owner.collector.ID)
	if err == nil || !reflect.DeepEqual(v, integrationdomain.CollectorHealthReport{}) {
		t.Fatal("failed read commit exposed a health report", err)
	}
	factory.fail = false
	if v, err := f.Report(t.Context(), owner.actor, foreign.collector.ID); !errors.Is(err, app.ErrNotFound) || !reflect.DeepEqual(v, integrationdomain.CollectorHealthReport{}) {
		t.Fatal("health query exposed foreign collector", err)
	}
	denied := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"collector:read"}}
	if v, err := f.Report(t.Context(), denied, owner.collector.ID); !errors.Is(err, app.ErrForbidden) || !reflect.DeepEqual(v, integrationdomain.CollectorHealthReport{}) {
		t.Fatal("health query accepted a human without tenant grant", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("health reads or result mutation changed repository state", err)
	}
}
