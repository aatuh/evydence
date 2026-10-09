package httpapi

import (
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func TestPackageReportNativeFixturesRetainClockAndDiscardProjectionOnCommitFailure(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory})
	owner := seedPackageReportFixtureScope(t, ledger, "Owner")
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	clock := &evidenceFlowFixtureClock{at: owner.release.CreatedAt}
	server.bindPackageReportFixtureClock(clock.Now)
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory, Now: func() time.Time { panic("native report consulted aggregate clock") }})
	server.bindLegacyLedgerFixture(rebound)
	coverage, err := server.controlCoverageQuery.CRAReadiness(t.Context(), owner.actor, owner.product.ID, owner.release.ID)
	if err != nil || len(coverage.AcceptedExceptions) != 1 || !coverage.GeneratedAt.Equal(clock.at) {
		t.Fatal("coverage rebinding lost native rows or explicit clock", coverage, err)
	}
	handling, err := server.craVulnerabilityQuery.Report(t.Context(), owner.actor, owner.product.ID, owner.release.ID)
	if err != nil || len(handling.AcceptedExceptions) != 1 || !handling.GeneratedAt.Equal(clock.at) || clock.calls != 2 {
		t.Fatal("handling rebinding lost native rows or explicit clock", handling, err)
	}
	update, err := server.securityUpdateEvidenceQuery.Report(t.Context(), owner.actor, owner.product.ID, owner.release.ID)
	if err != nil || len(update.FixedDecisions) != 1 || len(update.Incidents) != 1 || len(update.RemediationTasks) != 1 || !update.GeneratedAt.Equal(clock.at) || clock.calls != 3 {
		t.Fatal("security-update rebinding lost current native rows or explicit clock", update, err)
	}
	readiness, err := server.releaseReadinessReportQuery.Report(t.Context(), owner.actor, owner.release.ID)
	if err != nil || len(readiness.AcceptedExceptions) != 1 || len(readiness.Checks) == 0 || !readiness.GeneratedAt.Equal(clock.at) || clock.calls != 4 {
		t.Fatal("readiness rebinding lost current native details or explicit clock", readiness, err)
	}
	missing, err := server.missingEvidenceQuery.Report(t.Context(), owner.actor, owner.release.ID)
	if err != nil || missing["release_id"] != owner.release.ID || missing["result"] != readiness.Result {
		t.Fatal("missing-evidence rebinding lost current readiness facts", missing, err)
	}
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	factory.fail = true
	rollbacks := factory.rollbacks
	coverage, err = server.controlCoverageQuery.CRAReadiness(t.Context(), owner.actor, owner.product.ID, owner.release.ID)
	if err == nil || !reflect.DeepEqual(coverage, packagedomain.CRAReadinessReport{}) {
		t.Fatal("failed coverage commit returned a partial report", coverage, err)
	}
	handling, err = server.craVulnerabilityQuery.Report(t.Context(), owner.actor, owner.product.ID, owner.release.ID)
	if err == nil || !reflect.DeepEqual(handling, packagedomain.CRAVulnerabilityHandlingReport{}) || factory.rollbacks != rollbacks+2 {
		t.Fatal("failed handling commit returned partial data or retained transaction", handling, err)
	}
	clockCalls := clock.calls
	update, err = server.securityUpdateEvidenceQuery.Report(t.Context(), owner.actor, owner.product.ID, owner.release.ID)
	if err == nil || !reflect.DeepEqual(update, packagedomain.SecurityUpdateEvidenceReport{}) || factory.rollbacks != rollbacks+3 || clock.calls != clockCalls {
		t.Fatal("failed security-update commit returned partial data, retained transaction or reached clock", update, err)
	}
	readiness, err = server.releaseReadinessReportQuery.Report(t.Context(), owner.actor, owner.release.ID)
	if err == nil || !reflect.DeepEqual(readiness, packagedomain.ReleaseReadinessReport{}) || factory.rollbacks != rollbacks+4 {
		t.Fatal("failed readiness commit returned partial report or retained transaction", readiness, err)
	}
	missing, err = server.missingEvidenceQuery.Report(t.Context(), owner.actor, owner.release.ID)
	if err == nil || missing != nil || factory.rollbacks != rollbacks+5 {
		t.Fatal("failed readiness preview commit returned partial missing-evidence report", missing, err)
	}
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed report commit changed repository state", err)
	}
	coveragePort, handlingPort, updatePort := &controlReportHTTPFake{}, &craVulnerabilityHTTPFake{}, &securityUpdateHTTPFake{}
	server.controlCoverageQuery, server.craVulnerabilityQuery, server.securityUpdateEvidenceQuery = coveragePort, handlingPort, updatePort
	server.bindLegacyLedgerFixture(rebound)
	server.bindPackageReportFixtureClock(clock.Now)
	if server.controlCoverageQuery != coveragePort || server.craVulnerabilityQuery != handlingPort || server.securityUpdateEvidenceQuery != updatePort {
		t.Fatal("fixture rebinding replaced explicit report ports")
	}
}
