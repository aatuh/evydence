package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func TestParsedPointFixturePreservesCompletedEmptyContractFromUpload(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedEvidenceReadFixtureScope(t, ledger, "Owner")
	contract, err := ledger.UploadOpenAPIContract(t.Context(), owner.actor, owner.product.ID, owner.release.ID, "empty", []byte(`{"openapi":"3.1.0","info":{"title":"API","version":"empty"},"paths":{}}`))
	if err != nil || contract.Operations == nil || len(contract.Operations) != 0 {
		t.Fatal("upload did not preserve completed empty operations", err)
	}
	snapshot, err := factory.Snapshot()
	if err != nil || snapshot.OpenAPIContracts[contract.ID].Operations == nil {
		t.Fatal("upload transaction discarded completed empty operations", err)
	}
	if err := ledger.ExecuteUnitOfWork(t.Context(), func(ctx context.Context, r app.Repositories) error {
		value, err := r.Evidence.GetOpenAPIContract(ctx, owner.actor.TenantID, contract.ID)
		if err != nil || value.Operations == nil {
			t.Fatal("repository read discarded completed empty operations", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	read := evidenceReadFixture{catalogFixtureCommands{ledger: ledger}}
	value, err := read.GetOpenAPIContract(t.Context(), owner.actor, contract.ID)
	if err != nil || value.Operations == nil || len(value.Operations) != 0 {
		t.Fatal("native query discarded completed empty operations", err)
	}
	diffs := ingestionDiffFixture{catalogFixtureCommands{ledger: ledger}}
	input := evidenceapp.CreateContractDiffInput{BaseContractID: owner.contract.ID, TargetContractID: contract.ID, ReleaseID: owner.release.ID}
	if err := diffs.AuthorizeCreateContractDiff(t.Context(), owner.actor, input); err != nil {
		t.Fatal("diff guard rejected the completed empty contract", err)
	}
	if _, err := diffs.CreateContractDiff(t.Context(), owner.actor, input); err != nil {
		t.Fatal("diff command rejected the completed empty contract", err)
	}
	_, _, err = (catalogFixtureReplayExecutor{ledger: ledger}).WithBody(t.Context(), owner.actor, "POST", "/fixture-diff", "completed-empty-diff", []byte(`{}`), func(ctx context.Context) error {
		return diffs.AuthorizeCreateContractDiff(ctx, owner.actor, input)
	}, func(ctx context.Context) (int, any, error) {
		v, err := read.GetOpenAPIContract(ctx, owner.actor, contract.ID)
		if err != nil || v.Operations == nil {
			t.Fatal("isolated replay read discarded completed empty operations", err)
		}
		result, err := diffs.CreateContractDiff(ctx, owner.actor, input)
		if err != nil {
			t.Fatal("isolated diff execution failed before commit", err)
		}
		return 201, result, err
	})
	if err != nil {
		t.Fatal("isolated diff command rejected the completed empty contract", err)
	}
}

func TestParsedPointFixturesUseRepositoryRowsAndDiscardFailedCommits(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	at := time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC)
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory, Now: func() time.Time { return at }})
	owner := seedEvidenceReadFixtureScope(t, ledger, "Owner")
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory, Now: func() time.Time { panic("parsed point consulted aggregate clock") }})
	server.bindLegacyLedgerFixture(rebound)
	server.authn = &configuredAuthenticator{actor: owner.actor}
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	requests := []struct {
		path string
		want any
	}{{"/v1/sboms/" + owner.sbom.ID, owner.sbom}, {"/v1/vulnerability-scans/" + owner.scan.ID, owner.scan}, {"/v1/openapi-contracts/" + owner.contract.ID, owner.contract}}
	for _, request := range requests {
		begins := factory.beginCalls
		response := getRaw(t, server, "fixture", request.path, http.StatusOK)
		want, err := json.Marshal(map[string]any{"data": request.want, "meta": map[string]string{"api_version": "v1"}})
		if err != nil {
			t.Fatal(err)
		}
		assertPackageReportFixtureResponse(t, request.path, string(want), response.Body.String())
		if factory.beginCalls != begins+1 {
			t.Fatal("parsed point did not read exactly one repository view", request.path)
		}
	}
	factory.fail = true
	for _, request := range requests {
		begins, rollbacks := factory.beginCalls, factory.rollbacks
		body := getRaw(t, server, "fixture", request.path, http.StatusInternalServerError).Body.String()
		if factory.beginCalls != begins+1 || factory.rollbacks != rollbacks+1 {
			t.Fatal("failed parsed read retained its transaction", request.path)
		}
		for _, private := range []string{"private-query-commit-secret", `"data"`, `"findings"`, `"operations"`, `"components"`} {
			if strings.Contains(body, private) {
				t.Fatal("failed point commit exposed diagnostics or partial data", body)
			}
		}
	}
	read := evidenceReadFixture{catalogFixtureCommands{ledger: rebound}}
	if value, err := read.GetSBOM(t.Context(), owner.actor, owner.sbom.ID); err == nil || !reflect.DeepEqual(value, evidencedomain.SBOM{}) {
		t.Fatal("failed SBOM commit returned a partial projection", value, err)
	}
	if value, err := read.GetVulnerabilityScan(t.Context(), owner.actor, owner.scan.ID); err == nil || !reflect.DeepEqual(value, evidencedomain.VulnerabilityScan{}) {
		t.Fatal("failed scan commit returned a partial projection", value, err)
	}
	if value, err := read.GetOpenAPIContract(t.Context(), owner.actor, owner.contract.ID); err == nil || !reflect.DeepEqual(value, evidencedomain.OpenAPIContract{}) {
		t.Fatal("failed contract commit returned a partial projection", value, err)
	}
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("parsed reads or failed commits changed recorded rows", err)
	}
	read.ledger = newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	if _, err := read.GetSBOM(t.Context(), owner.actor, owner.sbom.ID); !errors.Is(err, app.ErrValidation) {
		t.Fatal("missing SBOM repository used an aggregate fallback", err)
	}
	if _, err := read.GetVulnerabilityScan(t.Context(), owner.actor, owner.scan.ID); !errors.Is(err, app.ErrValidation) {
		t.Fatal("missing scan repository used an aggregate fallback", err)
	}
	if _, err := read.GetOpenAPIContract(t.Context(), owner.actor, owner.contract.ID); !errors.Is(err, app.ErrValidation) {
		t.Fatal("missing contract repository used an aggregate fallback", err)
	}
	sbom, scan, contract := &sbomPointQueryFake{}, &scanPointQueryFake{}, &openAPIContractPointQueryFake{}
	server.sbomPointQuery, server.vulnerabilityScanPointQuery, server.openAPIContractPointQuery = sbom, scan, contract
	server.bindLegacyLedgerFixture(ledger)
	if server.sbomPointQuery != sbom || server.vulnerabilityScanPointQuery != scan || server.openAPIContractPointQuery != contract {
		t.Fatal("rebinding replaced explicit parsed point ports")
	}
}
