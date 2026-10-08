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
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed report commit changed repository state", err)
	}
	coveragePort, handlingPort := &controlReportHTTPFake{}, &craVulnerabilityHTTPFake{}
	server.controlCoverageQuery, server.craVulnerabilityQuery = coveragePort, handlingPort
	server.bindLegacyLedgerFixture(rebound)
	server.bindPackageReportFixtureClock(clock.Now)
	if server.controlCoverageQuery != coveragePort || server.craVulnerabilityQuery != handlingPort {
		t.Fatal("fixture rebinding replaced explicit report ports")
	}
}
