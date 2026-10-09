package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	application "github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var errIngestionWriteFailure = errors.New("ingestion write failed")
var errUnexpectedEvidenceWrite = errors.New("unexpected evidence write authorization")

func TestUploadSecurityScanCommitsEvidencePayloadScanAndAuditsAtomically(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.reader.artifacts["art_1"] = fixture.actor.TenantID
	fixture.transactions.state.artifactTenants["art_1"] = fixture.actor.TenantID

	scan, err := fixture.service.UploadSecurityScan(context.Background(), fixture.actor, UploadSecurityScanInput{
		ProductID: " prod_1 ", ReleaseID: " rel_1 ", ArtifactID: " art_1 ", Category: " secret_scan ",
		Format: " generic ", Scanner: " scanner ", TargetRef: " source:main ",
		Raw: []byte(`{"findings":[{"severity":"critical"},{"severity":""}]}`),
	})
	if err != nil {
		t.Fatalf("UploadSecurityScan: %v", err)
	}
	if scan.ID != "secscan_1" || scan.EvidenceID != "ev_1" || scan.ProductID != "prod_1" || scan.ReleaseID != "rel_1" || scan.ArtifactID != "art_1" {
		t.Fatalf("scan = %#v", scan)
	}
	if !scan.Redacted || !scan.Quarantined || scan.FindingCount != 2 || !reflect.DeepEqual(scan.Summary, map[string]int{"critical": 1, "unknown": 1}) {
		t.Fatalf("secret-scan handling = %#v", scan)
	}
	state := fixture.transactions.state
	if len(state.evidence) != 1 || len(state.securityScans) != 1 || len(state.payloads) != 1 || len(state.outbox) != 1 || len(state.audit) != 2 || fixture.transactions.commits != 1 {
		t.Fatalf("state=%#v transactions=%#v", state, fixture.transactions)
	}
	if state.audit[0].EntryType != "evidence.created" || state.audit[1].EntryType != "security_scan.uploaded" || state.audit[1].PayloadHash != scan.PayloadHash {
		t.Fatalf("audit = %#v", state.audit)
	}
	if fixture.objects.stageCalls != 1 || fixture.objects.calls != 1 {
		t.Fatalf("object calls: stage=%d validate=%d", fixture.objects.stageCalls, fixture.objects.calls)
	}
	item := state.evidence[scan.EvidenceID]
	if len(item.SubjectRefs) != 3 || item.SubjectRefs[0].ID != "art_1" || item.SubjectRefs[1].ID != "prod_1" || item.SubjectRefs[2].ID != "rel_1" {
		t.Fatalf("trimmed artifact subject was not preserved: %#v", item.SubjectRefs)
	}
	if !containsAuthorizationRequest(fixture.authorizer.requests, ScopeSecurityWrite, application.ResourceReferences{ArtifactID: "art_1"}) {
		t.Fatalf("artifact-only authorization missing: %#v", fixture.authorizer.requests)
	}
	for _, request := range fixture.authorizer.requests {
		if request.Scope == ScopeEvidenceWrite {
			t.Fatalf("security-owned command requested undocumented evidence scope: %#v", fixture.authorizer.requests)
		}
	}
}

func TestUploadSecurityScanRejectsTargetBeforeParsingPayload(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.reader.scopeErr = ErrNotFound
	_, err := fixture.service.UploadSecurityScan(context.Background(), fixture.actor, UploadSecurityScanInput{
		ProductID: "prod_missing", Category: "sast", Scanner: "scanner", TargetRef: "target", Raw: []byte(`not-json`),
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("UploadSecurityScan error = %v, want target not found before payload validation", err)
	}
	if fixture.objects.stageCalls != 0 || fixture.transactions.commits != 0 {
		t.Fatalf("unauthorized target reached effects: objects=%#v tx=%#v", fixture.objects, fixture.transactions)
	}
}

func TestUploadSecurityScanRejectsArtifactOnlyAuthorizationBeforeParserOrStager(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.reader.artifacts["art_1"] = fixture.actor.TenantID
	fixture.reader.artifactDigests["art_1"] = testDigest('a')
	fixture.transactions.state.artifactTenants["art_1"] = fixture.actor.TenantID
	fixture.transactions.state.artifactDigests["art_1"] = testDigest('a')
	fixture.authorizer.authorize = func(request application.AuthorizationRequest) error {
		if request.Resources == (application.ResourceReferences{ArtifactID: "art_1"}) {
			return errAuthorizationFailure
		}
		return nil
	}

	_, err := fixture.service.UploadSecurityScan(context.Background(), fixture.actor, UploadSecurityScanInput{
		ProductID: "prod_1", ReleaseID: "rel_1", ArtifactID: "art_1", Category: "sast",
		Format: "generic", Scanner: "scanner", TargetRef: "source:main", Raw: []byte(`not-json`),
	})
	if !errors.Is(err, errAuthorizationFailure) {
		t.Fatalf("UploadSecurityScan error = %v, want authorization failure", err)
	}
	if fixture.objects.stageCalls != 0 || fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 0 {
		t.Fatalf("denied artifact reached stager or transaction: objects=%#v transactions=%#v", fixture.objects, fixture.transactions)
	}
	if !containsAuthorizationRequest(fixture.authorizer.requests, ScopeSecurityWrite, application.ResourceReferences{ArtifactID: "art_1"}) {
		t.Fatalf("artifact-only authorization missing: %#v", fixture.authorizer.requests)
	}
}

func TestUploadSecurityScanUsesDocumentedSecurityWriteForCompositeEvidence(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.reader.artifacts["art_1"] = fixture.actor.TenantID
	fixture.transactions.state.artifactTenants["art_1"] = fixture.actor.TenantID
	authorizer := &splitSecurityScanGrantAuthorizer{}
	fixture.service.authorizer = authorizer

	scan, err := fixture.service.UploadSecurityScan(context.Background(), fixture.actor, UploadSecurityScanInput{
		ProductID: "prod_1", ReleaseID: "rel_1", ArtifactID: "art_1", Category: "sast",
		Format: "generic", Scanner: "scanner", TargetRef: "source:main", Raw: []byte(`{"findings":[]}`),
	})
	if err != nil {
		t.Fatalf("UploadSecurityScan error = %v", err)
	}
	if scan.ArtifactID != "art_1" || fixture.objects.stageCalls != 1 || fixture.transactions.commits != 1 {
		t.Fatalf("security-owned composite result=%#v objects=%#v tx=%#v", scan, fixture.objects, fixture.transactions)
	}
	for _, request := range authorizer.requests {
		if request.Scope == ScopeEvidenceWrite {
			t.Fatalf("undocumented evidence:write authorization requested: %#v", authorizer.requests)
		}
	}
}

type splitSecurityScanGrantAuthorizer struct {
	requests []application.AuthorizationRequest
}

func (a *splitSecurityScanGrantAuthorizer) Authorize(_ context.Context, _ identitydomain.Actor, request application.AuthorizationRequest) error {
	a.requests = append(a.requests, request)
	if request.Scope == ScopeEvidenceWrite {
		return errUnexpectedEvidenceWrite
	}
	return nil
}

func TestUploadAPISecurityScanOverridesCallerCategoryAndRejectsMalformedPayload(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	scan, err := fixture.service.UploadAPISecurityScan(context.Background(), fixture.actor, UploadSecurityScanInput{
		Category: "not-a-category", Format: "generic", Scanner: "api-scanner", TargetRef: "https://service.test",
		Raw: []byte(`{"findings":[]}`),
	})
	if err != nil {
		t.Fatalf("UploadAPISecurityScan: %v", err)
	}
	if scan.Category != "api_security" || scan.Redacted || scan.Quarantined {
		t.Fatalf("scan = %#v", scan)
	}

	fixture = newEvidenceServiceFixture(t)
	_, err = fixture.service.UploadSecurityScan(context.Background(), fixture.actor, UploadSecurityScanInput{
		Category: "sast", Format: "generic", Scanner: "scanner", TargetRef: "target",
		Raw: []byte(`{"findings":[],"unexpected":true}`),
	})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("malformed scan error = %v", err)
	}
	if fixture.objects.stageCalls != 0 || fixture.transactions.commits != 0 {
		t.Fatalf("malformed input reached effects: objects=%#v tx=%#v", fixture.objects, fixture.transactions)
	}
}

func TestUploadSecurityScanRollsBackEvidencePayloadAndAuditsWhenOwnedRecordFails(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.transactions.ingestionWriteErr = errIngestionWriteFailure
	_, err := fixture.service.UploadSecurityScan(context.Background(), fixture.actor, UploadSecurityScanInput{
		Category: "sast", Scanner: "scanner", TargetRef: "target", Raw: []byte(`{"findings":[]}`),
	})
	if !errors.Is(err, errIngestionWriteFailure) {
		t.Fatalf("UploadSecurityScan error = %v", err)
	}
	state := fixture.transactions.state
	if len(state.evidence) != 0 || len(state.securityScans) != 0 || len(state.payloads) != 0 || len(state.outbox) != 0 || len(state.audit) != 0 || fixture.transactions.rollbacks != 1 {
		t.Fatalf("partial state after rollback: state=%#v tx=%#v", state, fixture.transactions)
	}
}

func TestUploadManualSecurityDocumentCommitsOneUnitAndUsesDefaultMediaType(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	document, err := fixture.service.UploadManualSecurityDocument(context.Background(), fixture.actor, UploadManualSecurityDocumentInput{
		ProductID: "prod_1", ReleaseID: "rel_1", DocumentType: " security_review ", Title: " Review ",
		Sensitivity: " restricted ", Raw: []byte("private review"),
	})
	if err != nil {
		t.Fatalf("UploadManualSecurityDocument: %v", err)
	}
	if document.ID != "msd_1" || document.EvidenceID != "ev_1" || document.DocumentType != "security_review" || document.Title != "Review" || document.Sensitivity != "restricted" {
		t.Fatalf("document = %#v", document)
	}
	state := fixture.transactions.state
	if len(state.evidence) != 1 || len(state.manualDocs) != 1 || len(state.payloads) != 1 || len(state.outbox) != 1 || len(state.audit) != 2 || state.payloads[0].MediaType != "application/octet-stream" {
		t.Fatalf("state = %#v", state)
	}
	if state.audit[1].EntryType != "manual_security_document.uploaded" || state.audit[1].PayloadHash != document.PayloadHash {
		t.Fatalf("audit = %#v", state.audit)
	}
}

func TestUploadManualSecurityDocumentRollsBackOnSecondAuditFailure(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.transactions.auditFailAt = 2
	_, err := fixture.service.UploadManualSecurityDocument(context.Background(), fixture.actor, UploadManualSecurityDocumentInput{
		DocumentType: "threat_model", Title: "Model", Sensitivity: "internal", Raw: []byte("model"),
	})
	if !errors.Is(err, errAuditFailure) {
		t.Fatalf("UploadManualSecurityDocument error = %v", err)
	}
	state := fixture.transactions.state
	if len(state.evidence) != 0 || len(state.manualDocs) != 0 || len(state.payloads) != 0 || len(state.outbox) != 0 || len(state.audit) != 0 || fixture.transactions.rollbacks != 1 {
		t.Fatalf("partial state after rollback: state=%#v tx=%#v", state, fixture.transactions)
	}
}

func TestCreateSBOMDiffUsesTransactionSnapshotAndCommitsAudit(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	base := evidencedomain.SBOM{ID: "sbom_base", TenantID: fixture.actor.TenantID, ReleaseID: "rel_base", ArtifactID: "art_base", Components: []evidencedomain.SBOMComponent{{Name: "same", Version: "1"}, {Name: "removed", Version: "1"}}}
	target := evidencedomain.SBOM{ID: "sbom_target", TenantID: fixture.actor.TenantID, ReleaseID: "rel_target", ArtifactID: "art_target", Components: []evidencedomain.SBOMComponent{{Name: "same", Version: "1"}, {Name: "added", Version: "2"}}}
	fixture.reader.sboms[base.ID], fixture.reader.sboms[target.ID] = base, target
	fixture.transactions.state.sboms[base.ID], fixture.transactions.state.sboms[target.ID] = base, target

	diff, err := fixture.service.CreateSBOMDiff(context.Background(), fixture.actor, CreateSBOMDiffInput{BaseSBOMID: " sbom_base ", TargetSBOMID: " sbom_target ", ReleaseID: " rel_target "})
	if err != nil {
		t.Fatalf("CreateSBOMDiff: %v", err)
	}
	if diff.ID != "sdiff_1" || diff.ReleaseID != "rel_target" || diff.UnchangedCount != 1 || len(diff.AddedComponents) != 1 || diff.AddedComponents[0].Name != "added" || len(diff.RemovedComponents) != 1 || diff.RemovedComponents[0].Name != "removed" || len(diff.DependencyChanges) != 2 {
		t.Fatalf("diff = %#v", diff)
	}
	if diff.DependencyChanges[0].CreatedAt != fixture.now || diff.DependencyChanges[1].CreatedAt != fixture.now {
		t.Fatalf("dependency timestamps = %#v", diff.DependencyChanges)
	}
	if len(fixture.transactions.state.sbomDiffs) != 1 || len(fixture.transactions.state.audit) != 1 || fixture.transactions.state.audit[0].EntryType != "sbom.diffed" || fixture.transactions.commits != 1 {
		t.Fatalf("state=%#v tx=%#v", fixture.transactions.state, fixture.transactions)
	}
	if !containsAuthorizationRequest(fixture.authorizer.requests, ScopeEvidenceRead, application.ResourceReferences{ReleaseID: base.ReleaseID, ArtifactID: base.ArtifactID}) ||
		!containsAuthorizationRequest(fixture.authorizer.requests, ScopeEvidenceRead, application.ResourceReferences{ReleaseID: target.ReleaseID, ArtifactID: target.ArtifactID}) {
		t.Fatalf("diff read authorization missing: %#v", fixture.authorizer.requests)
	}
	for _, request := range fixture.authorizer.requests {
		if request.Scope != ScopeEvidenceRead {
			t.Fatalf("read-derived diff requested incompatible scope: %#v", fixture.authorizer.requests)
		}
	}
}

func TestDiffCommandsRequireEvidenceReadBeforeRepositoryReads(t *testing.T) {
	tests := []struct {
		name string
		run  func(*Service, identitydomain.Actor) error
	}{
		{name: "sbom", run: func(service *Service, actor identitydomain.Actor) error {
			_, err := service.CreateSBOMDiff(context.Background(), actor, CreateSBOMDiffInput{BaseSBOMID: "base", TargetSBOMID: "target"})
			return err
		}},
		{name: "contract", run: func(service *Service, actor identitydomain.Actor) error {
			_, err := service.CreateContractDiff(context.Background(), actor, CreateContractDiffInput{BaseContractID: "base", TargetContractID: "target"})
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newEvidenceServiceFixture(t)
			fixture.authorizer.err = errAuthorizationFailure
			fixture.authorizer.errAt = 1
			if err := test.run(fixture.service, fixture.actor); !errors.Is(err, errAuthorizationFailure) {
				t.Fatalf("diff error = %v, want evidence read denial", err)
			}
			if fixture.authorizer.calls != 1 || fixture.authorizer.requests[0].Scope != ScopeEvidenceRead || !fixture.authorizer.requests[0].ScopeOnly {
				t.Fatalf("authorization order = %#v", fixture.authorizer.requests)
			}
			if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 0 {
				t.Fatalf("denied diff reached transaction: %#v", fixture.transactions)
			}
		})
	}
}

func TestDiffCommandsRejectMismatchedReaderCoordinates(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.service.reader = hostileRiskReader{
		Reader: fixture.reader,
		sbom:   evidencedomain.SBOM{ID: "wrong", TenantID: fixture.actor.TenantID},
	}
	if _, err := fixture.service.CreateSBOMDiff(context.Background(), fixture.actor, CreateSBOMDiffInput{BaseSBOMID: "base", TargetSBOMID: "target"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("mismatched SBOM reader error = %v, want not found", err)
	}

	fixture = newEvidenceServiceFixture(t)
	fixture.service.reader = hostileRiskReader{
		Reader:   fixture.reader,
		contract: evidencedomain.OpenAPIContract{ID: "base", TenantID: "ten_foreign", ProductID: "prod_1"},
	}
	if _, err := fixture.service.CreateContractDiff(context.Background(), fixture.actor, CreateContractDiffInput{BaseContractID: "base", TargetContractID: "target"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign contract reader error = %v, want not found", err)
	}
	if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 0 {
		t.Fatalf("mismatched reads reached transaction: %#v", fixture.transactions)
	}
}

type hostileRiskReader struct {
	Reader
	sbom     evidencedomain.SBOM
	contract evidencedomain.OpenAPIContract
}

func (r hostileRiskReader) GetSBOM(context.Context, string, string) (evidencedomain.SBOM, error) {
	return r.sbom, nil
}

func (r hostileRiskReader) GetOpenAPIContract(context.Context, string, string) (evidencedomain.OpenAPIContract, error) {
	return r.contract, nil
}

func TestDiffComponentsKeepsFormatSpecificIdentity(t *testing.T) {
	base := []evidencedomain.SBOMComponent{{Identity: "spdx:SPDXRef-Package", Name: "api", Version: "1.0.0"}}
	target := []evidencedomain.SBOMComponent{{Identity: "cyclonedx:pkg-ref", Name: "api", Version: "1.0.0"}}
	added, removed, unchanged := diffComponents(base, target)
	if len(added) != 1 || len(removed) != 1 || unchanged != 0 || added[0].Identity == "" || removed[0].Identity == "" {
		t.Fatalf("added=%#v removed=%#v unchanged=%d", added, removed, unchanged)
	}
}

func TestCreateSBOMDiffRejectsUnrelatedReleaseReference(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	base := evidencedomain.SBOM{ID: "sbom_base", TenantID: fixture.actor.TenantID, ReleaseID: "rel_base"}
	target := evidencedomain.SBOM{ID: "sbom_target", TenantID: fixture.actor.TenantID, ReleaseID: "rel_target"}
	fixture.reader.sboms[base.ID], fixture.reader.sboms[target.ID] = base, target
	fixture.transactions.state.sboms[base.ID], fixture.transactions.state.sboms[target.ID] = base, target

	_, err := fixture.service.CreateSBOMDiff(context.Background(), fixture.actor, CreateSBOMDiffInput{
		BaseSBOMID: base.ID, TargetSBOMID: target.ID, ReleaseID: "rel_unrelated",
	})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("CreateSBOMDiff error = %v", err)
	}
	if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 0 {
		t.Fatalf("unrelated release reached transaction: %#v", fixture.transactions)
	}
}

func TestCreateSBOMDiffRejectsTransactionScopeDrift(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	visible := evidencedomain.SBOM{ID: "sbom_base", TenantID: fixture.actor.TenantID, ReleaseID: "rel_visible", Components: []evidencedomain.SBOMComponent{{Name: "component", Version: "1"}}}
	target := evidencedomain.SBOM{ID: "sbom_target", TenantID: fixture.actor.TenantID, ReleaseID: "rel_visible", Components: []evidencedomain.SBOMComponent{{Name: "component", Version: "2"}}}
	fixture.reader.sboms[visible.ID], fixture.reader.sboms[target.ID] = visible, target
	drifted := visible
	drifted.ReleaseID = "rel_drifted"
	fixture.transactions.state.sboms[drifted.ID], fixture.transactions.state.sboms[target.ID] = drifted, target

	_, err := fixture.service.CreateSBOMDiff(context.Background(), fixture.actor, CreateSBOMDiffInput{BaseSBOMID: visible.ID, TargetSBOMID: target.ID})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("CreateSBOMDiff error = %v", err)
	}
	if len(fixture.transactions.state.sbomDiffs) != 0 || len(fixture.transactions.state.audit) != 0 || fixture.transactions.rollbacks != 1 {
		t.Fatalf("partial state after drift: state=%#v tx=%#v", fixture.transactions.state, fixture.transactions)
	}
}

func TestCreateContractDiffPreservesBreakingChangeSemanticsAndAtomicAudit(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.actor.KeyID = ""
	fixture.actor.UserID = "usr_1"
	base := evidencedomain.OpenAPIContract{
		ID: "contract_base", TenantID: fixture.actor.TenantID, ProductID: "prod_1", ReleaseID: "rel_base", Hash: testDigest('a'), PathCount: 1,
		Operations: []evidencedomain.OpenAPIOperation{{Path: "/items", Method: "GET", ResponseStatuses: []string{"200", "404"}}},
	}
	target := evidencedomain.OpenAPIContract{
		ID: "contract_target", TenantID: fixture.actor.TenantID, ProductID: "prod_1", ReleaseID: "rel_target", Hash: testDigest('b'), PathCount: 0,
		Operations: []evidencedomain.OpenAPIOperation{},
	}
	fixture.reader.contracts[base.ID], fixture.reader.contracts[target.ID] = base, target
	fixture.transactions.state.contracts[base.ID], fixture.transactions.state.contracts[target.ID] = base, target

	diff, err := fixture.service.CreateContractDiff(context.Background(), fixture.actor, CreateContractDiffInput{BaseContractID: base.ID, TargetContractID: target.ID, ReleaseID: "rel_target"})
	if err != nil {
		t.Fatalf("CreateContractDiff: %v", err)
	}
	if diff.ID != "cdiff_1" || diff.ProductID != "prod_1" || diff.Result != "breaking" || !reflect.DeepEqual(diff.BreakingChanges, []string{"target contract has fewer paths than base contract"}) {
		t.Fatalf("diff = %#v", diff)
	}
	if len(fixture.transactions.state.contractDiffs) != 1 || len(fixture.transactions.state.audit) != 1 || fixture.transactions.state.audit[0].EntryType != "openapi_contract.diffed" || fixture.transactions.commits != 1 {
		t.Fatalf("state=%#v tx=%#v", fixture.transactions.state, fixture.transactions)
	}
	if audit := fixture.transactions.state.audit[0]; audit.ActorType != "human_user" || audit.ActorID != fixture.actor.UserID {
		t.Fatalf("audit actor = %#v", audit)
	}
	for _, request := range fixture.authorizer.requests {
		if request.Scope != ScopeEvidenceRead {
			t.Fatalf("read-derived diff requested incompatible scope: %#v", fixture.authorizer.requests)
		}
	}
}

func TestCreateContractDiffRejectsRequestedReleaseOutsideBaseProduct(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	base := evidencedomain.OpenAPIContract{ID: "contract_base", TenantID: fixture.actor.TenantID, ProductID: "prod_1", ReleaseID: "rel_base", Hash: testDigest('a')}
	target := evidencedomain.OpenAPIContract{ID: "contract_target", TenantID: fixture.actor.TenantID, ProductID: "prod_1", ReleaseID: "rel_target", Hash: testDigest('b')}
	fixture.reader.contracts[base.ID], fixture.reader.contracts[target.ID] = base, target
	fixture.transactions.state.contracts[base.ID], fixture.transactions.state.contracts[target.ID] = base, target
	fixture.reader.scopeErr = ErrNotFound

	_, err := fixture.service.CreateContractDiff(context.Background(), fixture.actor, CreateContractDiffInput{
		BaseContractID: base.ID, TargetContractID: target.ID, ReleaseID: "rel_foreign_product",
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("CreateContractDiff error = %v", err)
	}
	if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 0 {
		t.Fatalf("foreign release reached transaction: %#v", fixture.transactions)
	}
}

func containsAuthorizationRequest(requests []application.AuthorizationRequest, scope string, resources application.ResourceReferences) bool {
	for _, request := range requests {
		if request.Scope == scope && request.Resources == resources {
			return true
		}
	}
	return false
}

type fakeIngestionRepository struct{ tx *fakeEvidenceTransaction }

func (f fakeIngestionRepository) ValidateArtifactReference(_ context.Context, tenantID, artifactID, digest string) error {
	if artifactID == "" {
		return nil
	}
	f.tx.validatedArtifacts = append(f.tx.validatedArtifacts, artifactID)
	if f.tx.state.artifactTenants[artifactID] != tenantID || (digest != "" && !strings.EqualFold(f.tx.state.artifactDigests[artifactID], digest)) {
		return ErrNotFound
	}
	return nil
}

func (f fakeIngestionRepository) InsertSBOM(_ context.Context, value evidencedomain.SBOM) error {
	if f.tx.ingestionWriteErr != nil {
		return f.tx.ingestionWriteErr
	}
	f.tx.state.sboms[value.ID] = cloneSBOM(value)
	return nil
}

func (f fakeIngestionRepository) InsertVulnerabilityScan(_ context.Context, value evidencedomain.VulnerabilityScan) error {
	if f.tx.ingestionWriteErr != nil {
		return f.tx.ingestionWriteErr
	}
	f.tx.state.scans[value.ID] = cloneVulnerabilityScan(value)
	return nil
}

func (f fakeIngestionRepository) InsertOpenAPIContract(_ context.Context, value evidencedomain.OpenAPIContract) error {
	if f.tx.ingestionWriteErr != nil {
		return f.tx.ingestionWriteErr
	}
	f.tx.state.contracts[value.ID] = cloneOpenAPIContract(value)
	return nil
}

func (f fakeIngestionRepository) InsertVEXDocument(_ context.Context, value evidencedomain.VEXDocument) error {
	if f.tx.ingestionWriteErr != nil {
		return f.tx.ingestionWriteErr
	}
	f.tx.state.vexDocuments[value.ID] = cloneVEXDocument(value)
	return nil
}

func (f fakeIngestionRepository) InsertVEXImportReport(_ context.Context, value evidencedomain.VEXImportReport) error {
	if f.tx.ingestionWriteErr != nil {
		return f.tx.ingestionWriteErr
	}
	f.tx.state.vexImportReports[value.ID] = cloneVEXImportReport(value)
	return nil
}

func (f fakeIngestionRepository) GetSBOM(_ context.Context, tenantID, id string) (evidencedomain.SBOM, error) {
	value, ok := f.tx.state.sboms[id]
	if !ok || value.TenantID != tenantID {
		return evidencedomain.SBOM{}, ErrNotFound
	}
	return cloneSBOM(value), nil
}

func (f fakeIngestionRepository) GetOpenAPIContract(_ context.Context, tenantID, id string) (evidencedomain.OpenAPIContract, error) {
	value, ok := f.tx.state.contracts[id]
	if !ok || value.TenantID != tenantID {
		return evidencedomain.OpenAPIContract{}, ErrNotFound
	}
	return cloneOpenAPIContract(value), nil
}

func (f fakeIngestionRepository) InsertSecurityScan(_ context.Context, value evidencedomain.SecurityScan) error {
	if f.tx.ingestionWriteErr != nil {
		return f.tx.ingestionWriteErr
	}
	f.tx.state.securityScans[value.ID] = cloneSecurityScan(value)
	return nil
}

func (f fakeIngestionRepository) InsertManualSecurityDocument(_ context.Context, value evidencedomain.ManualSecurityDocument) error {
	if f.tx.ingestionWriteErr != nil {
		return f.tx.ingestionWriteErr
	}
	f.tx.state.manualDocs[value.ID] = value
	return nil
}

func (f fakeIngestionRepository) InsertSBOMDiff(_ context.Context, value evidencedomain.SBOMDiff) error {
	if f.tx.ingestionWriteErr != nil {
		return f.tx.ingestionWriteErr
	}
	f.tx.state.sbomDiffs[value.ID] = cloneSBOMDiff(value)
	return nil
}

func (f fakeIngestionRepository) InsertContractDiff(_ context.Context, value evidencedomain.ContractDiff) error {
	if f.tx.ingestionWriteErr != nil {
		return f.tx.ingestionWriteErr
	}
	f.tx.state.contractDiffs[value.ID] = cloneContractDiff(value)
	return nil
}
