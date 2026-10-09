package httpapi

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func TestReadinessNativeFixturesKeepFailedCommitsPrivateAndRequireRepositories(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory})
	owner := seedPackageReportFixtureScope(t, ledger, "Owner")
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: &configuredAuthenticator{actor: owner.actor}})
	if err != nil {
		t.Fatal(err)
	}
	clock := &evidenceFlowFixtureClock{at: owner.release.CreatedAt}
	server.bindPackageReportFixtureClock(clock.Now)
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	factory.fail = true
	for _, route := range []string{"release-readiness", "missing-evidence"} {
		rollbacks, begins := factory.rollbacks, factory.beginCalls
		body := getRaw(t, server, "fixture", "/v1/reports/"+route+"?release_id="+owner.release.ID, http.StatusInternalServerError).Body.String()
		if factory.rollbacks != rollbacks+1 || factory.beginCalls != begins+1 {
			t.Fatal("failed readiness read retained transaction or used extra reads", route)
		}
		for _, private := range []string{"private-query-commit-secret", "private-triage", "accepted_exceptions", "blocking_findings", `"data"`} {
			if strings.Contains(body, private) {
				t.Fatal("failed readiness commit disclosed private error or partial data", body)
			}
		}
	}
	readiness := server.releaseReadinessReportQuery.(packageReadinessFixtureQuery)
	preview := server.missingEvidenceQuery.(packageMissingFixture)
	if value, err := readiness.ReadReleaseReadinessReportSnapshot(t.Context(), owner.actor.TenantID, owner.release.ID, clock.at); err == nil || !reflect.DeepEqual(value, packagequery.ReleaseReadinessReportSnapshot{}) {
		t.Fatal("failed readiness reader exposed partial details", value, err)
	}
	if value, err := preview.ReadReleaseReadinessSnapshot(t.Context(), owner.actor.TenantID, owner.release.ID); err == nil || !reflect.DeepEqual(value, riskapp.ReadinessSnapshot{}) {
		t.Fatal("failed preview reader exposed partial readiness facts", value, err)
	}
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed readiness reads changed repository state", err)
	}
	missingRepository := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	readiness.catalogFixtureCommands, preview.catalogFixtureCommands = catalogFixtureCommands{ledger: missingRepository}, catalogFixtureCommands{ledger: missingRepository}
	if value, err := readiness.Report(t.Context(), owner.actor, owner.release.ID); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(value, packagedomain.ReleaseReadinessReport{}) {
		t.Fatal("missing readiness repository fell back to aggregate state", value, err)
	}
	if value, err := preview.Report(t.Context(), owner.actor, owner.release.ID); !errors.Is(err, app.ErrValidation) || value != nil {
		t.Fatal("missing preview repository fell back to aggregate state", value, err)
	}
	var absent context.Context
	if _, err := readiness.ReadReleaseReadinessReportSnapshot(absent, owner.actor.TenantID, owner.release.ID, clock.at); !errors.Is(err, packagequery.ErrReleaseReadinessValidation) {
		t.Fatal("nil report context accepted", err)
	}
	if _, err := preview.ReadReleaseReadinessSnapshot(absent, owner.actor.TenantID, owner.release.ID); !errors.Is(err, riskapp.ErrValidation) {
		t.Fatal("nil preview context accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := readiness.Report(ctx, owner.actor, owner.release.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("report ignored cancellation", err)
	}
	if _, err := preview.Report(ctx, owner.actor, owner.release.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("preview ignored cancellation", err)
	}
	readinessPort, previewPort := &readinessReportHTTPFake{}, &missingEvidenceHTTPFake{}
	server.releaseReadinessReportQuery, server.missingEvidenceQuery = readinessPort, previewPort
	server.bindLegacyLedgerFixture(missingRepository)
	server.bindPackageReportFixtureClock(clock.Now)
	if server.releaseReadinessReportQuery != readinessPort || server.missingEvidenceQuery != previewPort {
		t.Fatal("rebinding replaced explicit readiness ports")
	}
}
