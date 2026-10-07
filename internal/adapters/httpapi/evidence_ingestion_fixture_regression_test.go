package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

type failingIngestionFixture struct {
	ingestionFixtureCommands
	diffs     ingestionDiffFixture
	changedID string
	isolated  bool
}

func (f *failingIngestionFixture) failure(ctx context.Context, id string, err error) error {
	if err != nil {
		return err
	}
	f.changedID, f.isolated = id, f.commandLedger(ctx) != f.ledger
	return errors.New("private ingestion fixture failure after write")
}
func (f *failingIngestionFixture) UploadSBOMPayload(ctx context.Context, a domain.Actor, in evidenceapp.SBOMIngestionInput, source evidenceapp.PayloadSource) (evidencedomain.SBOM, error) {
	v, err := f.ingestionFixtureCommands.UploadSBOMPayload(ctx, a, in, source)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingIngestionFixture) UploadVEXPayload(ctx context.Context, a domain.Actor, in evidenceapp.VEXIngestionInput, source evidenceapp.PayloadSource) (evidencedomain.VEXDocument, error) {
	v, err := f.ingestionFixtureCommands.UploadVEXPayload(ctx, a, in, source)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingIngestionFixture) UploadVulnerabilityScanPayload(ctx context.Context, a domain.Actor, in evidenceapp.VulnerabilityScanScope, source evidenceapp.PayloadSource) (evidencedomain.VulnerabilityScan, error) {
	v, err := f.ingestionFixtureCommands.UploadVulnerabilityScanPayload(ctx, a, in, source)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingIngestionFixture) UploadOpenAPIContractPayload(ctx context.Context, a domain.Actor, in evidenceapp.OpenAPIIngestionInput, source evidenceapp.PayloadSource) (evidencedomain.OpenAPIContract, error) {
	v, err := f.ingestionFixtureCommands.UploadOpenAPIContractPayload(ctx, a, in, source)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingIngestionFixture) UploadSecurityScan(ctx context.Context, a domain.Actor, in evidenceapp.UploadSecurityScanInput) (evidencedomain.SecurityScan, error) {
	v, err := f.ingestionFixtureCommands.UploadSecurityScan(ctx, a, in)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingIngestionFixture) UploadManualSecurityDocument(ctx context.Context, a domain.Actor, in evidenceapp.UploadManualSecurityDocumentInput) (evidencedomain.ManualSecurityDocument, error) {
	v, err := f.ingestionFixtureCommands.UploadManualSecurityDocument(ctx, a, in)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingIngestionFixture) AuthorizeCreateSBOMDiff(ctx context.Context, a domain.Actor, in evidenceapp.CreateSBOMDiffInput) error {
	return f.diffs.AuthorizeCreateSBOMDiff(ctx, a, in)
}
func (f *failingIngestionFixture) AuthorizeCreateContractDiff(ctx context.Context, a domain.Actor, in evidenceapp.CreateContractDiffInput) error {
	return f.diffs.AuthorizeCreateContractDiff(ctx, a, in)
}
func (f *failingIngestionFixture) CreateSBOMDiff(ctx context.Context, a domain.Actor, in evidenceapp.CreateSBOMDiffInput) (evidencedomain.SBOMDiff, error) {
	v, err := f.diffs.CreateSBOMDiff(ctx, a, in)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingIngestionFixture) CreateContractDiff(ctx context.Context, a domain.Actor, in evidenceapp.CreateContractDiffInput) (evidencedomain.ContractDiff, error) {
	v, err := f.diffs.CreateContractDiff(ctx, a, in)
	return v, f.failure(ctx, v.ID, err)
}

type ingestionFixtureRequest struct{ name, path, body string }

func ingestionFixtureRequests(t *testing.T, ledger *app.Ledger, scope evidenceReadFixtureScope) []ingestionFixtureRequest {
	t.Helper()
	target, err := ledger.UploadSBOM(t.Context(), scope.actor, scope.release.ID, "", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"next","purl":"pkg:generic/next@2"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	contract, err := ledger.UploadOpenAPIContract(t.Context(), scope.actor, scope.product.ID, scope.release.ID, "2", []byte(`{"openapi":"3.1.0","info":{"title":"API","version":"2"},"paths":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	encode := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	return []ingestionFixtureRequest{
		{"cyclonedx", "/v1/sboms", encode(map[string]any{"release_id": scope.release.ID, "payload": json.RawMessage(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`)})},
		{"spdx", "/v1/sboms/spdx", encode(map[string]any{"release_id": scope.release.ID, "payload": json.RawMessage(`{"spdxVersion":"SPDX-2.3","packages":[{"name":"library","versionInfo":"1"}]}`)})},
		{"openvex", "/v1/vex", encode(map[string]any{"release_id": scope.release.ID, "payload": json.RawMessage(scope.payload)})},
		{"cyclonedx-vex", "/v1/vex/cyclonedx", encode(map[string]any{"release_id": scope.release.ID, "payload": json.RawMessage(`{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[{"id":"CVE-2026-1","analysis":{"state":"resolved","justification":"code_not_present","detail":"fixed","response":["update"]}}]}`)})},
		{"scanner", "/v1/vulnerability-scans", encode(map[string]any{"release_id": scope.release.ID, "scanner": "generic", "target_ref": "pkg:oci/api", "findings": []any{}})},
		{"openapi", "/v1/openapi-contracts", encode(map[string]any{"product_id": scope.product.ID, "release_id": scope.release.ID, "version": "3", "spec": json.RawMessage(`{"openapi":"3.1.0","info":{"title":"API","version":"3"},"paths":{}}`)})},
		{"security-scan", "/v1/security-scans", encode(map[string]any{"product_id": scope.product.ID, "release_id": scope.release.ID, "category": "secret_scan", "scanner": "fixture", "target_ref": "pkg:oci/api", "format": "generic", "payload": map[string]any{"findings": []map[string]any{{"severity": "high"}}}})},
		{"api-security", "/v1/api-security-scans", encode(map[string]any{"product_id": scope.product.ID, "release_id": scope.release.ID, "scanner": "fixture", "target_ref": "openapi", "format": "generic", "payload": map[string]any{"findings": []any{}}})},
		{"manual", "/v1/security-documents", encode(map[string]any{"product_id": scope.product.ID, "release_id": scope.release.ID, "document_type": "pen_test_report", "title": "Review", "sensitivity": "restricted", "payload": map[string]any{"note": "reviewed"}})},
		{"sbom-diff", "/v1/sbom-diffs", encode(map[string]any{"base_sbom_id": scope.sbom.ID, "target_sbom_id": target.ID, "release_id": scope.release.ID})},
		{"contract-diff", "/v1/openapi-diffs", encode(map[string]any{"base_contract_id": scope.contract.ID, "target_contract_id": contract.ID, "release_id": scope.release.ID})},
	}
}

func TestIngestionFixturesRollBackEveryDocumentPayloadAuditJobAndDiffEffect(t *testing.T) {
	for _, name := range []string{"cyclonedx", "spdx", "openvex", "cyclonedx-vex", "scanner", "openapi", "security-scan", "api-security", "manual", "sbom-diff", "contract-diff"} {
		t.Run(name, func(t *testing.T) {
			factory := app.NewMemoryUnitOfWorkFactory()
			ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory, Now: func() time.Time { return time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC) }})
			owner := seedEvidenceReadFixtureScope(t, ledger, "Owner")
			var request ingestionFixtureRequest
			for _, candidate := range ingestionFixtureRequests(t, ledger, owner) {
				if candidate.name == name {
					request = candidate
				}
			}
			if request.path == "" {
				t.Fatal("missing ingestion test case")
			}
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			server.authn = &configuredAuthenticator{actor: owner.actor}
			base := catalogFixtureCommands{ledger: ledger}
			commands := &failingIngestionFixture{ingestionFixtureCommands: ingestionFixtureCommands{base}, diffs: ingestionDiffFixture{base}}
			server.sbomIngestionCommands, server.vexIngestionCommands, server.scanIngestionCommands, server.openAPIIngestionCommands, server.securityDocumentCommands, server.sbomDiffCommands, server.contractDiffCommands = commands, commands, commands, commands, commands, commands, commands
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, server, owner.secret, request.path, "ingestion-failure", []byte(request.body), 500)
			if commands.changedID == "" || !commands.isolated || strings.Contains(out, `"data"`) || strings.Contains(out, commands.changedID) || strings.Contains(out, "private ingestion") {
				t.Fatal("failed ingestion bypassed isolation or disclosed partial results")
			}
			after, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if len(after.Idempotency) != 1 {
				t.Fatal("failed ingestion lost its failure record")
			}
			for _, record := range after.Idempotency {
				if record.State != app.IdempotencyFailed || record.Status != 0 || record.Response != nil {
					t.Fatal("failed ingestion cached partial success")
				}
			}
			after.Idempotency = before.Idempotency
			if !reflect.DeepEqual(before, after) {
				t.Fatal("failed ingestion committed document, evidence, payload, audit, outbox or diff effects")
			}
		})
	}
}

func TestIngestionFixturesRecheckCurrentGrantsAndNeverReapplyCompletedEffects(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory, Now: func() time.Time { return time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC) }})
	owner := seedEvidenceReadFixtureScope(t, ledger, "Owner")
	foreign := seedEvidenceReadFixtureScope(t, ledger, "Foreign")
	requests := ingestionFixtureRequests(t, ledger, owner)
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{app.ScopeEvidenceRead, app.ScopeEvidenceWrite, app.ScopeSecurityWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"*"}}}}
	auth := &configuredAuthenticator{actor: human}
	server.authn = auth
	for _, request := range requests {
		t.Run(request.name, func(t *testing.T) {
			original := postRaw(t, server, owner.secret, request.path, request.name, []byte(request.body), 201)
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			replay := postRaw(t, server, owner.secret, request.path, request.name, []byte(request.body), 201)
			assertTrustHTTPReplay(t, original, replay)
			for _, grants := range [][]domain.ResourceGrant{nil, {{ResourceType: "product", ResourceID: foreign.product.ID, Scopes: []string{"*"}}}} {
				auth.actor.ResourceGrants = grants
				postRaw(t, server, owner.secret, request.path, request.name, []byte(request.body), 403)
			}
			auth.actor = human
			postRaw(t, server, owner.secret, request.path, request.name, []byte(request.body+" "), 409)
			after, err := factory.Snapshot()
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("completed or rejected ingestion replay reapplied effects", request.name, err)
			}
		})
	}
}
