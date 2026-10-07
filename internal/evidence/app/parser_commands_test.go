package app

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	application "github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestUploadSBOMPayloadAuthorizesTargetsBeforeParserOrStager(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.reader.scopeErr = ErrNotFound
	source := testPayloadSource(`{"bomFormat":"CycloneDX"}`)

	_, err := fixture.service.UploadSBOMPayload(context.Background(), fixture.actor, " rel_missing ", " art_missing ", source)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("UploadSBOMPayload error = %v, want not found", err)
	}
	if fixture.parser.sbomCalls != 0 || fixture.objects.sourceStageCalls != 0 {
		t.Fatalf("attacker bytes reached parser/stager before target rejection: parser=%d stager=%d", fixture.parser.sbomCalls, fixture.objects.sourceStageCalls)
	}
}

func TestUploadSBOMPayloadRejectsArtifactOnlyAuthorizationBeforeParserOrStager(t *testing.T) {
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

	_, err := fixture.service.UploadSBOMPayload(context.Background(), fixture.actor, "rel_1", "art_1", testPayloadSource(`{"bomFormat":"CycloneDX"}`))
	if !errors.Is(err, errAuthorizationFailure) {
		t.Fatalf("UploadSBOMPayload error = %v, want authorization failure", err)
	}
	if fixture.parser.sbomCalls != 0 || fixture.objects.sourceStageCalls != 0 || fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 0 {
		t.Fatalf("denied artifact reached parser, stager, or transaction: parser=%d stager=%d transactions=%#v", fixture.parser.sbomCalls, fixture.objects.sourceStageCalls, fixture.transactions)
	}
	if !containsAuthorizationRequest(fixture.authorizer.requests, ScopeEvidenceWrite, application.ResourceReferences{ArtifactID: "art_1"}) {
		t.Fatalf("artifact-only authorization missing: %#v", fixture.authorizer.requests)
	}
}

func TestUploadSBOMPayloadPersistsParserProjectionAndJobsAtomically(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.reader.artifacts["art_1"] = fixture.actor.TenantID
	fixture.transactions.state.artifactTenants["art_1"] = fixture.actor.TenantID
	fixture.parser.sbom = ParsedSBOM{
		Format: "cyclonedx", SpecVersion: "1.6", ParserVersion: "cyclonedx-json.v1",
		Components: []evidencedomain.SBOMComponent{{Identity: "purl:pkg:generic/api@1", Name: "api", Version: "1", PURL: "pkg:generic/api@1"}},
		Metadata:   map[string]any{"component_count": 1}, Limitations: []string{"raw-only fields retained"},
	}
	source := testPayloadSource(`{"bomFormat":"CycloneDX"}`)

	sbom, err := fixture.service.UploadSBOMPayload(context.Background(), fixture.actor, " rel_1 ", " art_1 ", source)
	if err != nil {
		t.Fatalf("UploadSBOMPayload: %v", err)
	}
	if sbom.ReleaseID != "rel_1" || sbom.ArtifactID != "art_1" || sbom.ComponentCount != 1 || len(sbom.Components) != 1 {
		t.Fatalf("returned SBOM = %#v", sbom)
	}
	state := fixture.transactions.state
	if len(state.evidence) != 1 || len(state.sboms) != 1 || len(state.payloads) != 1 || len(state.audit) != 2 || len(state.outbox) != 2 {
		t.Fatalf("atomic state evidence=%d sboms=%d payloads=%d audit=%d outbox=%d", len(state.evidence), len(state.sboms), len(state.payloads), len(state.audit), len(state.outbox))
	}
	if state.outbox[0].Kind != "finalize_payload" || state.outbox[1].Kind != "parse_sbom" || state.outbox[1].Payload["parser_version"] != "cyclonedx-json.v1" {
		t.Fatalf("outbox = %#v", state.outbox)
	}
	item := state.evidence[sbom.EvidenceID]
	if len(item.SubjectRefs) != 2 || item.SubjectRefs[0].ID != "art_1" || item.SubjectRefs[1] != (evidencedomain.SubjectRef{Type: "release", ID: "rel_1"}) || item.Metadata["component_count"] != 1 {
		t.Fatalf("evidence item = %#v", item)
	}
	if got := fixture.transactions.validatedArtifacts; len(got) != 1 || got[0] != "art_1" {
		t.Fatalf("transaction artifact rechecks = %#v", got)
	}
	if !containsAuthorizationRequest(fixture.authorizer.requests, ScopeEvidenceWrite, application.ResourceReferences{ArtifactID: "art_1"}) {
		t.Fatalf("artifact-only authorization missing: %#v", fixture.authorizer.requests)
	}
}

func TestUploadSPDXSBOMPayloadRollsBackAllRowsAndJobs(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.parser.sbom = ParsedSBOM{Format: "spdx", SpecVersion: "SPDX-2.3", ParserVersion: "spdx-json.v2", Metadata: map[string]any{"component_count": 0}}
	fixture.transactions.auditFailAt = 2

	_, err := fixture.service.UploadSPDXSBOMPayload(context.Background(), fixture.actor, "rel_1", "", testPayloadSource(`{"spdxVersion":"SPDX-2.3"}`))
	if !errors.Is(err, errAuditFailure) {
		t.Fatalf("UploadSPDXSBOMPayload error = %v, want audit failure", err)
	}
	state := fixture.transactions.state
	if len(state.evidence) != 0 || len(state.sboms) != 0 || len(state.payloads) != 0 || len(state.audit) != 0 || len(state.outbox) != 0 || fixture.transactions.rollbacks != 1 {
		t.Fatalf("partial state survived rollback: %#v", state)
	}
}

func TestUploadVulnerabilityScanPayloadPreservesCompletedEmptyArray(t *testing.T) {
	for _, workerOwned := range []bool{false, true} {
		fixture := newEvidenceServiceFixture(t)
		fixture.service.workerOwnedParsers = workerOwned
		fixture.parser.scan = ParsedVulnerabilityScan{
			ReleaseID: "rel_1", Scanner: "generic", Adapter: "generic", AdapterVersion: "scanner.v1",
			SourceSchema: "generic-vulnerability-scan-json.v1", TargetRef: "pkg:oci/api", Summary: map[string]int{},
		}
		scan, err := fixture.service.UploadVulnerabilityScanPayload(t.Context(), fixture.actor, testPayloadSource(`{"release_id":"rel_1"}`))
		if err != nil {
			t.Fatal(err)
		}
		if scan.Findings == nil || len(scan.Findings) != 0 {
			t.Fatal("completed empty scan returned null findings")
		}
		stored := fixture.transactions.state.scans[scan.ID]
		if workerOwned {
			if stored.Findings != nil || stored.Summary != nil || stored.Scanner != "" {
				t.Fatal("pending projection was represented as completed")
			}
		} else if stored.Findings == nil || len(stored.Findings) != 0 {
			t.Fatal("completed empty scan persisted null findings")
		}
	}
}

func TestUploadVulnerabilityScanPayloadUsesDynamicHumanAuditActor(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.actor = identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", SessionID: "ses_1", Scopes: []string{"*"}}
	fixture.parser.scan = ParsedVulnerabilityScan{
		ReleaseID: "rel_1", Scanner: "grype", Adapter: "grype", AdapterVersion: "scanner.v1", SourceSchema: "grype-json.v1", TargetRef: "pkg:oci/api",
		Summary: map[string]int{"high": 1}, Findings: []evidencedomain.VulnerabilityFinding{{Vulnerability: "CVE-2026-0001", Severity: "high"}}, Metadata: map[string]any{"scanner": "grype"},
	}

	scan, err := fixture.service.UploadVulnerabilityScanPayload(context.Background(), fixture.actor, testPayloadSource(`{"scanner":"grype"}`))
	if err != nil {
		t.Fatalf("UploadVulnerabilityScanPayload: %v", err)
	}
	if len(scan.Findings) != 1 || scan.Findings[0].ID != scan.ID+":finding:1" {
		t.Fatalf("scan finding IDs = %#v", scan.Findings)
	}
	for _, event := range fixture.transactions.state.audit {
		if event.ActorType != "human_user" || event.ActorID != "usr_1" {
			t.Fatalf("audit actor = %#v", event)
		}
	}
}

func TestUploadVulnerabilityScanPayloadAuthorizesProbedReleaseBeforeFullParser(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	events := []string{}
	fixture.scanScopeProber.scope = VulnerabilityScanScope{ReleaseID: " rel_1 "}
	fixture.scanScopeProber.events = &events
	fixture.reader.events = &events
	fixture.authorizer.events = &events
	fixture.parser.events = &events
	fixture.parser.scan = ParsedVulnerabilityScan{
		ReleaseID: "rel_1", Scanner: "generic", Adapter: "generic", AdapterVersion: "scanner.v1",
		SourceSchema: "generic-vulnerability-scan-json.v1", TargetRef: "pkg:oci/api",
	}

	if _, err := fixture.service.UploadVulnerabilityScanPayload(context.Background(), fixture.actor, testPayloadSource(`{"release_id":"rel_1"}`)); err != nil {
		t.Fatalf("UploadVulnerabilityScanPayload: %v", err)
	}
	wantPrefix := []string{"authorize_base", "probe_scan_scope", "validate_scope", "authorize_scope", "parse_scan"}
	if len(events) < len(wantPrefix) || !reflect.DeepEqual(events[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("command order = %#v, want prefix %#v", events, wantPrefix)
	}
}

func TestUploadVulnerabilityScanPayloadRejectsDeniedProbedReleaseBeforeFullParserOrStager(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.scanScopeProber.scope = VulnerabilityScanScope{ReleaseID: " rel_forbidden "}
	fixture.reader.scopeErr = ErrNotFound

	_, err := fixture.service.UploadVulnerabilityScanPayload(context.Background(), fixture.actor, testPayloadSource(`{"release_id":"rel_forbidden","findings":[]}`))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("UploadVulnerabilityScanPayload error = %v, want not found", err)
	}
	if fixture.scanScopeProber.calls != 1 || fixture.parser.scanCalls != 0 || fixture.objects.sourceStageCalls != 0 {
		t.Fatalf("denied payload progression: probes=%d parser=%d stager=%d", fixture.scanScopeProber.calls, fixture.parser.scanCalls, fixture.objects.sourceStageCalls)
	}
}

func TestUploadVulnerabilityScanPayloadRejectsResourceAuthorizationBeforeFullParserOrStager(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.scanScopeProber.scope = VulnerabilityScanScope{ReleaseID: "rel_denied"}
	fixture.authorizer.err = errAuthorizationFailure
	fixture.authorizer.errAt = 2

	_, err := fixture.service.UploadVulnerabilityScanPayload(context.Background(), fixture.actor, testPayloadSource(`{"release_id":"rel_denied","findings":[]}`))
	if !errors.Is(err, errAuthorizationFailure) {
		t.Fatalf("UploadVulnerabilityScanPayload error = %v, want authorization failure", err)
	}
	if fixture.scanScopeProber.calls != 1 || fixture.parser.scanCalls != 0 || fixture.objects.sourceStageCalls != 0 {
		t.Fatalf("denied payload progression: probes=%d parser=%d stager=%d", fixture.scanScopeProber.calls, fixture.parser.scanCalls, fixture.objects.sourceStageCalls)
	}
}

func TestUploadVulnerabilityScanPayloadRejectsScopeDriftBetweenProbeAndFullParser(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.scanScopeProber.scope = VulnerabilityScanScope{ReleaseID: "rel_1"}
	fixture.parser.scan = ParsedVulnerabilityScan{
		ReleaseID: "rel_other", Scanner: "generic", Adapter: "generic", AdapterVersion: "scanner.v1",
		SourceSchema: "generic-vulnerability-scan-json.v1", TargetRef: "pkg:oci/api",
	}

	_, err := fixture.service.UploadVulnerabilityScanPayload(context.Background(), fixture.actor, testPayloadSource(`{"release_id":"rel_1"}`))
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("UploadVulnerabilityScanPayload error = %v, want validation", err)
	}
	if fixture.parser.scanCalls != 1 || fixture.objects.sourceStageCalls != 0 || fixture.transactions.commits != 0 {
		t.Fatalf("scope drift progression: parser=%d stager=%d commits=%d", fixture.parser.scanCalls, fixture.objects.sourceStageCalls, fixture.transactions.commits)
	}
}

func TestUploadOpenAPIContractPayloadWorkerOwnedProjectionAndTransactionScopeRecheck(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.service.workerOwnedParsers = true
	fixture.parser.contract = ParsedOpenAPIContract{
		ParserVersion: "openapi-json.v1", SourceSchema: "openapi-3.1.0", PathCount: 1,
		Operations: []evidencedomain.OpenAPIOperation{{Path: "/health", Method: "GET"}}, Metadata: map[string]any{"path_count": 1},
	}
	source := testPayloadSource(`{"openapi":"3.1.0"}`)

	contract, err := fixture.service.UploadOpenAPIContractPayload(context.Background(), fixture.actor, " prod_1 ", " rel_1 ", " v1 ", source)
	if err != nil {
		t.Fatalf("UploadOpenAPIContractPayload: %v", err)
	}
	if contract.ProductID != "prod_1" || contract.ReleaseID != "rel_1" || contract.Version != "v1" || contract.PathCount != 1 || len(contract.Operations) != 1 {
		t.Fatalf("returned contract = %#v", contract)
	}
	persisted := fixture.transactions.state.contracts[contract.ID]
	if persisted.PathCount != 0 || persisted.Operations != nil || persisted.Hash != source.Digest {
		t.Fatalf("worker-owned persisted contract = %#v", persisted)
	}
	if got := fixture.transactions.validatedScopes; len(got) == 0 || got[len(got)-1] != (EvidenceScope{ProductID: "prod_1", ReleaseID: "rel_1"}) {
		t.Fatalf("transaction scope rechecks = %#v", got)
	}
}

func TestWorkerOwnedParserCommandsKeepParsedProjectionWithoutReplayableObject(t *testing.T) {
	t.Run("sbom", func(t *testing.T) {
		fixture := newEvidenceServiceFixture(t)
		fixture.service.workerOwnedParsers = true
		fixture.objects.noObject = true
		fixture.parser.sbom = ParsedSBOM{
			Format: "cyclonedx", SpecVersion: "1.6", ParserVersion: "cyclonedx-json.v1",
			Components: []evidencedomain.SBOMComponent{{Name: "api", Version: "1"}},
		}
		sbom, err := fixture.service.UploadSBOMPayload(context.Background(), fixture.actor, "rel_1", "", testPayloadSource(`{"bomFormat":"CycloneDX"}`))
		if err != nil {
			t.Fatalf("upload SBOM: %v", err)
		}
		persisted := fixture.transactions.state.sboms[sbom.ID]
		if persisted.SpecVersion != "1.6" || persisted.ComponentCount != 1 || len(persisted.Components) != 1 {
			t.Fatalf("no-object SBOM projection = %#v", persisted)
		}
	})

	t.Run("vulnerability scan", func(t *testing.T) {
		fixture := newEvidenceServiceFixture(t)
		fixture.service.workerOwnedParsers = true
		fixture.objects.noObject = true
		fixture.parser.scan = ParsedVulnerabilityScan{
			ReleaseID: "rel_1", Scanner: "generic", Adapter: "generic", AdapterVersion: "scanner.v1",
			SourceSchema: "generic-vulnerability-scan-json.v1", TargetRef: "pkg:oci/api",
			Summary: map[string]int{"high": 1}, Findings: []evidencedomain.VulnerabilityFinding{{Vulnerability: "CVE-1", Severity: "high"}},
		}
		scan, err := fixture.service.UploadVulnerabilityScanPayload(context.Background(), fixture.actor, testPayloadSource(`{"release_id":"rel_1"}`))
		if err != nil {
			t.Fatalf("upload scan: %v", err)
		}
		persisted := fixture.transactions.state.scans[scan.ID]
		if persisted.Scanner != "generic" || persisted.TargetRef != "pkg:oci/api" || len(persisted.Findings) != 1 || persisted.Summary["high"] != 1 {
			t.Fatalf("no-object scan projection = %#v", persisted)
		}
	})

	t.Run("openapi", func(t *testing.T) {
		fixture := newEvidenceServiceFixture(t)
		fixture.service.workerOwnedParsers = true
		fixture.objects.noObject = true
		fixture.parser.contract = ParsedOpenAPIContract{
			ParserVersion: "openapi-json.v1", SourceSchema: "openapi-3.1.0", PathCount: 1,
			Operations: []evidencedomain.OpenAPIOperation{{Path: "/health", Method: "GET"}},
		}
		contract, err := fixture.service.UploadOpenAPIContractPayload(context.Background(), fixture.actor, "prod_1", "rel_1", "v1", testPayloadSource(`{"openapi":"3.1.0"}`))
		if err != nil {
			t.Fatalf("upload OpenAPI: %v", err)
		}
		persisted := fixture.transactions.state.contracts[contract.ID]
		if persisted.PathCount != 1 || len(persisted.Operations) != 1 {
			t.Fatalf("no-object OpenAPI projection = %#v", persisted)
		}
	})
}

func TestUploadParserCommandRejectsInvalidSourceWithoutOpeningIt(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	opens := 0
	_, err := fixture.service.UploadSBOMPayload(context.Background(), fixture.actor, "rel_1", "", PayloadSource{
		Digest: "invalid", Size: 1, Open: func() (io.ReadCloser, error) { opens++; return io.NopCloser(strings.NewReader("x")), nil },
	})
	if !errors.Is(err, ErrValidation) || opens != 0 || fixture.parser.sbomCalls != 0 || fixture.objects.sourceStageCalls != 0 {
		t.Fatalf("invalid source error=%v opens=%d parser=%d stager=%d", err, opens, fixture.parser.sbomCalls, fixture.objects.sourceStageCalls)
	}
}

func testPayloadSource(raw string) PayloadSource {
	return BytesPayloadSource([]byte(raw))
}

type fakeEvidenceParser struct {
	sbomCalls     int
	scanCalls     int
	contractCalls int
	vexCalls      int
	sbom          ParsedSBOM
	scan          ParsedVulnerabilityScan
	contract      ParsedOpenAPIContract
	vex           ParsedVEX
	err           error
	events        *[]string
}

func (f *fakeEvidenceParser) ParseSBOM(context.Context, string, PayloadSource) (ParsedSBOM, error) {
	f.sbomCalls++
	return f.sbom, f.err
}

func (f *fakeEvidenceParser) ParseVulnerabilityScan(context.Context, PayloadSource) (ParsedVulnerabilityScan, error) {
	f.scanCalls++
	if f.events != nil {
		*f.events = append(*f.events, "parse_scan")
	}
	return f.scan, f.err
}

func (f *fakeEvidenceParser) ParseOpenAPIContract(context.Context, PayloadSource) (ParsedOpenAPIContract, error) {
	f.contractCalls++
	return f.contract, f.err
}

func (f *fakeEvidenceParser) ParseVEX(context.Context, string, PayloadSource) (ParsedVEX, error) {
	f.vexCalls++
	return f.vex, f.err
}

var _ application.OutboxEnqueuer = fakeEvidenceOutbox{}

type fakeVulnerabilityScanScopeProber struct {
	calls  int
	scope  VulnerabilityScanScope
	err    error
	events *[]string
}

func (f *fakeVulnerabilityScanScopeProber) ProbeVulnerabilityScanScope(context.Context, PayloadSource) (VulnerabilityScanScope, error) {
	f.calls++
	if f.events != nil {
		*f.events = append(*f.events, "probe_scan_scope")
	}
	return f.scope, f.err
}
