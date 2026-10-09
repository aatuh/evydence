package httpapi

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func nativeScanFixturePayload(release string) []byte {
	return []byte(fmt.Sprintf(`{"scanner":"generic","target_ref":"pkg:oci/example","release_id":%q,"findings":[{"vulnerability":"CVE-2026-0001","component":"pkg:golang/example.com/demo@1.0.0","severity":"high","state":"open","severity_source":"operator","fix_version":"1.0.1","identity":{"cve":"CVE-2026-0001","purl":"pkg:golang/example.com/demo@1.0.0"}}]}`, release))
}
func TestScanIngestionNativeFixtureUsesCurrentScopeExplicitResourcesAndAtomicNormalizedEffects(t *testing.T) {
	ledger, base, objects := signatureRegressionLedger(t)
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	release, err := ledger.CreateRelease(t.Context(), owner.actor, owner.product.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("scan ingestion used aggregate clock") }})
	clock := &diffFixtureClock{at: time.Date(2026, 10, 9, 16, 0, 0, 0, time.UTC)}
	f := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}, objects: objects, clock: clock}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{app.ScopeEvidenceWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{app.ScopeEvidenceWrite}}}}
	raw := nativeScanFixturePayload(release.ID)
	source, opens, closes := documentFixtureSource(raw)
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	in, err := f.ProbeVulnerabilityScanScope(t.Context(), human, source)
	if err != nil || in != (evidenceapp.VulnerabilityScanScope{ReleaseID: release.ID}) || *opens != 1 || *closes != 1 {
		t.Fatal("bounded digest-bound scope probe changed", in, err)
	}
	if err := f.AuthorizeUploadVulnerabilityScan(t.Context(), human, in); err != nil {
		t.Fatal("current repository guard rejected", err)
	}
	guarded, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, guarded) || *opens != 1 || clock.calls != 0 || objects.stages != 0 {
		t.Fatal("preflight normalized findings/staged/wrote/time", err)
	}
	scan, err := f.UploadVulnerabilityScanPayload(t.Context(), human, in, source)
	if err != nil {
		t.Fatal(err)
	}
	want := evidencedomain.VulnerabilityScan{ID: scan.ID, TenantID: human.TenantID, EvidenceID: scan.EvidenceID, ReleaseID: release.ID, Scanner: "generic", Adapter: "generic", AdapterVersion: app.ParserVersionScannerAdaptersJSON, SourceSchema: "generic-vulnerability-scan-json.v1", TargetRef: "pkg:oci/example", Summary: map[string]int{"high": 1}, Findings: []evidencedomain.VulnerabilityFinding{{ID: scan.ID + ":finding:1", Vulnerability: "CVE-2026-0001", Component: "pkg:golang/example.com/demo@1.0.0", Severity: "high", State: "open", SeveritySource: "operator", FixVersion: "1.0.1", Identity: evidencedomain.VulnerabilityIdentity{CVE: "CVE-2026-0001", PURL: "pkg:golang/example.com/demo@1.0.0"}}}, CreatedAt: clock.at}
	if scan.ID == "" || scan.EvidenceID == "" || !reflect.DeepEqual(scan, want) || *opens != *closes {
		t.Fatal("scan lost complete normalized DTO or leaked source", scan, want, err)
	}
	scan.Summary["high"], scan.Findings[0].Identity.CVE = 99, "mutated"
	after, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after.VulnerabilityScans[want.ID], domain.VulnerabilityScanFromContext(want)) || len(after.VulnerabilityScans) != len(before.VulnerabilityScans)+1 || len(after.Evidence) != len(before.Evidence)+1 || len(after.ObjectPayloads) != len(before.ObjectPayloads)+1 || len(after.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+2 || len(after.OutboxJobs) != len(before.OutboxJobs)+2 || objects.stages != 1 {
		t.Fatal("scan/evidence/payload/audit/jobs not atomic or result aliased")
	}
	e := after.Evidence[want.EvidenceID]
	p := e.Metadata["parser"].(map[string]any)
	if e.Type != "vulnerability_scan" || e.Subtype != "generic" || e.ReleaseID != release.ID || e.PayloadHash != source.Digest || e.PayloadSize != source.Size || e.PayloadMediaType != evidenceapp.ScannerMediaType || p["version"] != app.ParserVersionScannerAdaptersJSON || e.Metadata["adapter"] != "generic" || e.CanonicalHash == "" || e.ChainEntryID == "" {
		t.Fatal("scan evidence lost digest/provenance/current scope")
	}
	for _, entry := range after.AuditEntries[human.TenantID][len(before.AuditEntries[human.TenantID]):] {
		if entry.ActorID != human.UserID || entry.ActorType != "human_user" || entry.OccurredAt != clock.at || entry.PayloadHash != source.Digest {
			t.Fatal("scan audit lost caller/time/digest")
		}
	}
	found := false
	for _, job := range after.OutboxJobs {
		if job.SubjectID == want.ID {
			found = true
			if job.Kind != "parse_vulnerability_scan" || job.Payload["parser_version"] != app.ParserVersionScannerAdaptersJSON || job.Payload["payload_hash"] != source.Digest || job.Payload["payload_ref"] != e.PayloadRef {
				t.Fatal("scan parser job incomplete")
			}
		}
	}
	if !found {
		t.Fatal("missing scan parser job")
	}
	staging, final, err := app.CanonicalObjectPayloadKeys(human.TenantID, source.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if obj, err := objects.Get(t.Context(), staging); err != nil || !reflect.DeepEqual(obj.Bytes, raw) {
		t.Fatal("scan staging lost exact bytes", err)
	}
	if _, err := objects.Get(t.Context(), final); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("scan finalized before job", err)
	}
	factory.fail = true
	failedRaw := append(append([]byte{}, raw...), ' ')
	failedSource := evidenceapp.BytesPayloadSource(failedRaw)
	if v, err := f.UploadVulnerabilityScanPayload(t.Context(), human, in, failedSource); err == nil || !reflect.DeepEqual(v, evidencedomain.VulnerabilityScan{}) {
		t.Fatal("failed scan commit returned data", err)
	}
	last, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, last) || objects.stages != 2 {
		t.Fatal("failed scan commit published effects", err)
	}
	staging, final, err = app.CanonicalObjectPayloadKeys(human.TenantID, failedSource.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if obj, err := objects.Get(t.Context(), staging); err != nil || !reflect.DeepEqual(obj.Bytes, failedRaw) {
		t.Fatal("failed scan did not exercise exact staging", err)
	}
	if _, err := objects.Get(t.Context(), final); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("failed scan finalized bytes", err)
	}
}

func TestScanIngestionNativeFixtureRejectsForeignRevokedAndIncoherentScopesBeforeEffects(t *testing.T) {
	ledger, base, objects := signatureRegressionLedger(t)
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	foreign := seedEvidenceFixtureScope(t, ledger, "Foreign")
	release, err := ledger.CreateRelease(t.Context(), owner.actor, owner.product.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	foreignRelease, err := ledger.CreateRelease(t.Context(), foreign.actor, foreign.product.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	other, err := ledger.CreateRelease(t.Context(), owner.actor, owner.product.ID, "2")
	if err != nil {
		t.Fatal(err)
	}
	clock := &diffFixtureClock{at: time.Date(2026, 10, 9, 16, 0, 0, 0, time.UTC)}
	f := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, objects: objects, clock: clock}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{app.ScopeEvidenceWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{app.ScopeEvidenceWrite}}}}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{foreignRelease.ID, "missing"} {
		in := evidenceapp.VulnerabilityScanScope{ReleaseID: id}
		source, opens, closes := documentFixtureSource(nativeScanFixturePayload(id))
		if err := f.AuthorizeUploadVulnerabilityScan(t.Context(), human, in); !errors.Is(err, evidenceapp.ErrNotFound) {
			t.Fatal("foreign scope guard", err)
		}
		if v, err := f.UploadVulnerabilityScanPayload(t.Context(), human, in, source); !errors.Is(err, app.ErrNotFound) || !reflect.DeepEqual(v, evidencedomain.VulnerabilityScan{}) || *opens != 0 || *closes != 0 {
			t.Fatal("foreign scan parsed or returned effects", err)
		}
	}
	in := evidenceapp.VulnerabilityScanScope{ReleaseID: release.ID}
	source, opens, closes := documentFixtureSource(nativeScanFixturePayload(release.ID))
	revoked := human
	revoked.ResourceGrants = nil
	if err := f.AuthorizeUploadVulnerabilityScan(t.Context(), revoked, in); !errors.Is(err, evidenceapp.ErrForbidden) {
		t.Fatal("revoked scan guard", err)
	}
	if _, err := f.UploadVulnerabilityScanPayload(t.Context(), revoked, in, source); !errors.Is(err, app.ErrForbidden) || *opens != 0 {
		t.Fatal("revoked scan parsed", err)
	}
	if v, err := f.UploadVulnerabilityScanPayload(t.Context(), human, evidenceapp.VulnerabilityScanScope{ReleaseID: other.ID}, source); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v, evidencedomain.VulnerabilityScan{}) {
		t.Fatal("parsed release differs from authorized scope", err)
	}
	for _, bad := range []evidenceapp.PayloadSource{{Digest: source.Digest, Size: source.Size}, {Digest: source.Digest, Size: app.EvidenceDocumentLimit + 1, Open: source.Open}, {Digest: "sha256:" + strings.Repeat("f", 64), Size: source.Size, Open: source.Open}, evidenceapp.BytesPayloadSource([]byte(`[]`)), evidenceapp.BytesPayloadSource([]byte(`{}`))} {
		if v, err := f.ProbeVulnerabilityScanScope(t.Context(), human, bad); !errors.Is(err, evidenceapp.ErrValidation) || v != (evidenceapp.VulnerabilityScanScope{}) {
			t.Fatal("bad bounded probe returned scope", err)
		}
		if v, err := f.UploadVulnerabilityScanPayload(t.Context(), human, in, bad); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v, evidencedomain.VulnerabilityScan{}) {
			t.Fatal("bad scan source returned data", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.UploadVulnerabilityScanPayload(ctx, human, in, source); !errors.Is(err, context.Canceled) {
		t.Fatal("scan cancellation lost", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) || objects.stages != 0 || clock.calls != 0 || *opens != *closes {
		t.Fatal("denied/malformed scan published effects or leaked stream", err)
	}
}

func TestScanIngestionNativeFixtureKeepsExplicitWorkerPolicyAndNoStorageOnRebind(t *testing.T) {
	for _, storage := range []bool{false, true} {
		mode := "metadata-only"
		if storage {
			mode = "worker-owned"
		}
		t.Run(mode, func(t *testing.T) {
			ledger, base, objects := signatureRegressionLedger(t)
			owner := seedEvidenceFixtureScope(t, ledger, "Owner")
			release, err := ledger.CreateRelease(t.Context(), owner.actor, owner.product.ID, "1")
			if err != nil {
				t.Fatal(err)
			}
			clock := &diffFixtureClock{at: time.Date(2026, 10, 9, 16, 0, 0, 0, time.UTC)}
			f := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, clock: clock, workerOwnedParsers: true, repositoryScope: true}
			if storage {
				f.objects = objects
			}
			s := &Server{scanIngestionCommands: f}
			rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: base, Now: func() time.Time { panic("rebound scan used aggregate clock") }})
			s.bindIngestionFixturePorts(rebound)
			bound, ok := s.scanIngestionCommands.(ingestionFixtureCommands)
			if !ok || bound.ledger != rebound || bound.objects != f.objects || bound.clock != clock || !bound.workerOwnedParsers || !bound.repositoryScope {
				t.Fatal("scan rebind lost explicit resources/policy")
			}
			before, err := base.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			source := evidenceapp.BytesPayloadSource(nativeScanFixturePayload(release.ID))
			in := evidenceapp.VulnerabilityScanScope{ReleaseID: release.ID}
			v, err := bound.UploadVulnerabilityScanPayload(t.Context(), owner.actor, in, source)
			if err != nil || v.CreatedAt != clock.at || v.Scanner != "generic" || len(v.Findings) != 1 || v.Summary["high"] != 1 {
				t.Fatal("scan lost complete response DTO", err)
			}
			after, err := base.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			p, e := after.VulnerabilityScans[v.ID], after.Evidence[v.EvidenceID]
			if len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+2 {
				t.Fatal("scan policy lost audits")
			}
			action := "vulnerability_scan.parsed"
			if storage {
				action = "vulnerability_scan.accepted"
				if p.Scanner != "" || p.Adapter != "" || p.AdapterVersion != "" || p.SourceSchema != "" || p.TargetRef != "" || p.Summary != nil || p.Findings != nil || e.PayloadRef == "" || objects.stages != 1 || len(after.ObjectPayloads) != len(before.ObjectPayloads)+1 || len(after.OutboxJobs) != len(before.OutboxJobs)+2 {
					t.Fatal("worker-owned scan committed parser projection or lost staging/jobs")
				}
			} else {
				if p.Scanner != "generic" || p.AdapterVersion != app.ParserVersionScannerAdaptersJSON || p.Summary["high"] != 1 || len(p.Findings) != 1 || e.PayloadRef != "" || objects.stages != 0 || len(after.ObjectPayloads) != len(before.ObjectPayloads) || len(after.OutboxJobs) != len(before.OutboxJobs)+1 {
					t.Fatal("no-storage scan recovered hidden storage or falsely deferred projection")
				}
			}
			entries := after.AuditEntries[owner.actor.TenantID][len(before.AuditEntries[owner.actor.TenantID]):]
			if entries[0].EntryType != "evidence.created" || entries[1].EntryType != action || entries[1].ActorID != owner.actor.KeyID || entries[1].ActorType != "api_key" || entries[1].OccurredAt != clock.at {
				t.Fatal("scan policy audit lost action/caller/time")
			}
		})
	}
	explicit := &scanIngestionHTTPFake{}
	s := &Server{scanIngestionCommands: explicit}
	s.bindIngestionFixturePorts(nil)
	s.bindDocumentIngestionFixtureResources(nil, nil, true)
	if s.scanIngestionCommands != explicit {
		t.Fatal("rebind replaced injected scan port")
	}
}

func TestScanIngestionNativeFixtureHTTPFailureRollsBackAndMissingRepositoryFailsClosed(t *testing.T) {
	ledger, base, objects := signatureRegressionLedger(t)
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	release, err := ledger.CreateRelease(t.Context(), owner.actor, owner.product.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	clock := &diffFixtureClock{at: time.Date(2026, 10, 9, 16, 0, 0, 0, time.UTC)}
	f := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, objects: objects, clock: clock}
	s, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	s.authn = &configuredAuthenticator{actor: owner.actor}
	failure := &failingIngestionFixture{ingestionFixtureCommands: f}
	s.scanIngestionCommands = failure
	raw := nativeScanFixturePayload(release.ID)
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	body := postRaw(t, s, owner.secret, "/v1/vulnerability-scans", "native-scan-failure", raw, 500)
	if failure.changedID == "" || !failure.isolated || objects.stages != 1 {
		t.Fatal("scan failure did not exercise isolated native writes/staging")
	}
	for _, private := range []string{failure.changedID, `"data"`, "CVE-2026-0001", "example.com/demo", "private ingestion"} {
		if strings.Contains(body, private) {
			t.Fatal("failed scan leaked result/raw/internal error", body)
		}
	}
	after, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Idempotency) != 1 {
		t.Fatal("scan failure lost replay failure record")
	}
	for _, record := range after.Idempotency {
		if record.State != app.IdempotencyFailed || record.Status != 0 || record.Response != nil {
			t.Fatal("scan cached failed response as success")
		}
	}
	after.Idempotency = before.Idempotency
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failed HTTP scan committed evidence/findings/payload/audit/jobs")
	}
	missing := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture"})}, objects: objects, clock: clock}
	in := evidenceapp.VulnerabilityScanScope{ReleaseID: release.ID}
	source := evidenceapp.BytesPayloadSource(raw)
	if err := missing.AuthorizeUploadVulnerabilityScan(t.Context(), owner.actor, in); !errors.Is(err, evidenceapp.ErrValidation) {
		t.Fatal("missing repository scan guard fell back", err)
	}
	if v, err := missing.UploadVulnerabilityScanPayload(t.Context(), owner.actor, in, source); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v, evidencedomain.VulnerabilityScan{}) {
		t.Fatal("missing repository scan write fell back", err)
	}
	var nilCtx context.Context
	if v, err := f.ProbeVulnerabilityScanScope(nilCtx, owner.actor, source); !errors.Is(err, evidenceapp.ErrValidation) || v != (evidenceapp.VulnerabilityScanScope{}) {
		t.Fatal("nil context scope probe accepted", err)
	}
}
