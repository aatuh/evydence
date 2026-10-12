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

const nativeOpenVEXFixture = `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex/native","author":"security@example.test","timestamp":"2026-10-09T16:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-2026-0001"},"products":[{"@id":"pkg:generic/one@1"}],"status":"affected","justification":"reviewed","impact_statement":"impact","action_statement":"update"}]}`
const nativeCycloneDXVEXFixture = `{"bomFormat":"CycloneDX","specVersion":"1.4","version":1,"vulnerabilities":[{"id":"CVE-2026-0001","affects":[{"ref":"pkg:generic/one@1"}],"analysis":{"state":"exploitable","detail":"impact","response":["update"]}}]}`

func TestVEXIngestionNativeFixtureUsesCurrentScopeAndAtomicAcceptedWorkerHandoff(t *testing.T) {
	for _, tc := range []struct{ format, raw, media, parser, author, version, justification string }{{"openvex", nativeOpenVEXFixture, evidenceapp.OpenVEXMediaType, app.ParserVersionOpenVEXJSON, "security@example.test", "1", "reviewed"}, {"cyclonedx", nativeCycloneDXVEXFixture, evidenceapp.CycloneDXMediaType, app.ParserVersionCycloneDXVEXJSON, "cyclonedx", "1.4", ""}} {
		t.Run(tc.format, func(t *testing.T) {
			ledger, base, objects := signatureRegressionLedger(t)
			owner := seedSignatureFixtureScope(t, ledger, "Owner")
			release, err := releaseSetup(ledger).CreateRelease(t.Context(), owner.actor, owner.product.ID, "1")
			if err != nil {
				t.Fatal(err)
			}
			factory := &operatorQueryFailureFactory{base: base}
			rebound := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("VEX ingestion used aggregate clock") }})
			clock := &diffFixtureClock{at: time.Date(2026, 10, 9, 17, 0, 0, 0, time.UTC)}
			f := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}, objects: objects, clock: clock}
			human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{app.ScopeEvidenceWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{app.ScopeEvidenceWrite}}}}
			in := evidenceapp.VEXIngestionInput{ReleaseID: release.ID, ArtifactID: owner.artifact.ID, Format: tc.format}
			source, opens, closes := documentFixtureSource([]byte(tc.raw))
			before, err := base.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if err := f.AuthorizeUploadVEX(t.Context(), human, in); err != nil {
				t.Fatal("current VEX guard", err)
			}
			guarded, err := base.Snapshot()
			if err != nil || !reflect.DeepEqual(before, guarded) || *opens != 0 || objects.stages != 0 || clock.calls != 0 {
				t.Fatal("VEX preflight parsed/staged/wrote/time", err)
			}
			v, err := f.UploadVEXPayload(t.Context(), human, in, source)
			if err != nil {
				t.Fatal(err)
			}
			want := evidencedomain.VEXDocument{ID: v.ID, TenantID: human.TenantID, EvidenceID: v.EvidenceID, ReleaseID: release.ID, ArtifactID: owner.artifact.ID, Format: tc.format, Author: tc.author, Version: tc.version, StatementCount: 1, StatusSummary: map[string]int{"affected": 1}, SchemaVersion: evidencedomain.VEXDocumentSchemaVersion, CreatedAt: clock.at}
			if v.ID == "" || v.EvidenceID == "" || !reflect.DeepEqual(v, want) || *opens != *closes {
				t.Fatal("VEX lost full normalized DTO or stream closure", v, want)
			}
			v.StatusSummary["affected"] = 99
			after, err := base.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if len(after.VEXDocuments) != len(before.VEXDocuments)+1 || len(after.VEXImportReports) != len(before.VEXImportReports)+1 || len(after.Evidence) != len(before.Evidence)+1 || len(after.ObjectPayloads) != len(before.ObjectPayloads)+1 || len(after.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+2 || len(after.OutboxJobs) != len(before.OutboxJobs)+2 || len(after.Decisions) != len(before.Decisions) || objects.stages != 1 || !reflect.DeepEqual(after.VEXDocuments[want.ID], domain.VEXDocumentFromContext(want)) {
				t.Fatal("VEX acceptance effects incomplete/aliased or decisions synchronously mutated")
			}
			var report domain.VEXImportReport
			for _, p := range after.VEXImportReports {
				if p.VEXDocumentID == want.ID {
					if report.ID != "" {
						t.Fatal("ambiguous import report")
					}
					report = p
				}
			}
			expected := domain.VEXImportReport{ID: report.ID, TenantID: human.TenantID, VEXDocumentID: want.ID, EvidenceID: want.EvidenceID, ReleaseID: release.ID, ArtifactID: owner.artifact.ID, ParserVersion: tc.parser, Status: "accepted", StatementCount: 1, Warnings: []string{evidenceapp.VEXAsyncDecisionWarning}, SchemaVersion: evidencedomain.VEXImportReportSchemaVersion, CreatedAt: clock.at, UpdatedAt: clock.at}
			if report.ID == "" {
				t.Fatal("missing import report")
			}
			assertEvidenceFixtureJSON(t, report, expected)
			e := after.Evidence[want.EvidenceID]
			provenance := e.Metadata["parser"].(map[string]any)
			if e.Type != "vex" || e.Subtype != tc.format || e.ReleaseID != release.ID || e.PayloadHash != source.Digest || e.PayloadSize != source.Size || e.PayloadMediaType != tc.media || provenance["version"] != tc.parser || e.CanonicalHash == "" || e.ChainEntryID == "" {
				t.Fatal("VEX evidence lost digest/provenance/identity")
			}
			found := false
			for _, job := range after.OutboxJobs {
				if job.SubjectID != want.ID {
					continue
				}
				found = true
				if job.Kind != "parse_vex" {
					t.Fatal("wrong VEX worker kind")
				}
				assertEvidenceFixtureJSON(t, job.Payload, map[string]any{"payload_ref": e.PayloadRef, "payload_hash": source.Digest, "parser_version": tc.parser, "payload_lifecycle": evidenceapp.PayloadLifecycleVersion, "payload_digest": source.Digest, "worker_create_decisions": true, "decision_request_schema": evidenceapp.VEXDecisionRequestSchemaVersion, "decision_statements": []map[string]any{{"statement_index": 1, "vulnerability": "CVE-2026-0001", "products": []string{"pkg:generic/one@1"}, "status": "affected", "justification": tc.justification, "impact_statement": "impact", "action_statement": "update"}}, "actor_type": "human_user", "actor_id": human.UserID, "evidence_id": want.EvidenceID, "release_id": release.ID, "artifact_id": owner.artifact.ID, "import_report_id": report.ID, "decisions_created": 0})
			}
			if !found {
				t.Fatal("missing exact normalized worker request")
			}
			for _, a := range after.AuditEntries[human.TenantID][len(before.AuditEntries[human.TenantID]):] {
				if a.ActorID != human.UserID || a.ActorType != "human_user" || a.PayloadHash != source.Digest || a.OccurredAt != clock.at {
					t.Fatal("VEX acceptance audit lost caller/digest/time")
				}
			}
			factory.fail = true
			failedSource := evidenceapp.BytesPayloadSource([]byte(tc.raw + " "))
			if v, err := f.UploadVEXPayload(t.Context(), human, in, failedSource); err == nil || !reflect.DeepEqual(v, evidencedomain.VEXDocument{}) {
				t.Fatal("failed VEX commit returned partial document", err)
			}
			last, err := base.Snapshot()
			if err != nil || !reflect.DeepEqual(after, last) || objects.stages != 2 {
				t.Fatal("failed VEX commit published effects", err)
			}
			staging, final, err := app.CanonicalObjectPayloadKeys(human.TenantID, failedSource.Digest)
			if err != nil {
				t.Fatal(err)
			}
			if obj, err := objects.Get(t.Context(), staging); err != nil || string(obj.Bytes) != tc.raw+" " {
				t.Fatal("failed VEX did not stage exact bytes", err)
			}
			if _, err := objects.Get(t.Context(), final); !errors.Is(err, app.ErrNotFound) {
				t.Fatal("failed VEX finalized bytes", err)
			}
		})
	}
}

func TestVEXIngestionNativeFixtureRejectsForeignScopesRevocationAndMalformedStreams(t *testing.T) {
	ledger, base, objects := signatureRegressionLedger(t)
	owner := seedSignatureFixtureScope(t, ledger, "Owner")
	foreign := seedSignatureFixtureScope(t, ledger, "Foreign")
	release, err := releaseSetup(ledger).CreateRelease(t.Context(), owner.actor, owner.product.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	fr, err := releaseSetup(ledger).CreateRelease(t.Context(), foreign.actor, foreign.product.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	clock := &diffFixtureClock{at: time.Date(2026, 10, 9, 17, 0, 0, 0, time.UTC)}
	f := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, objects: objects, clock: clock}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{app.ScopeEvidenceWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{app.ScopeEvidenceWrite}}}}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"openvex", "cyclonedx"} {
		raw := nativeOpenVEXFixture
		if format == "cyclonedx" {
			raw = nativeCycloneDXVEXFixture
		}
		source, opens, closes := documentFixtureSource([]byte(raw))
		in := evidenceapp.VEXIngestionInput{ReleaseID: fr.ID, ArtifactID: owner.artifact.ID, Format: format}
		if v, err := f.UploadVEXPayload(t.Context(), human, in, source); !errors.Is(err, app.ErrNotFound) || !reflect.DeepEqual(v, evidencedomain.VEXDocument{}) || *opens != 0 {
			t.Fatal("foreign release VEX parsed", err)
		}
		in.ReleaseID, in.ArtifactID = release.ID, foreign.artifact.ID
		if _, err := f.UploadVEXPayload(t.Context(), human, in, source); !errors.Is(err, app.ErrForbidden) || *opens != 0 {
			t.Fatal("foreign artifact VEX parsed", err)
		}
		if _, err := f.UploadVEXPayload(t.Context(), owner.actor, in, source); !errors.Is(err, app.ErrNotFound) || *opens != 0 {
			t.Fatal("tenant-wide VEX accepted foreign artifact", err)
		}
		in.ArtifactID = owner.artifact.ID
		revoked := human
		revoked.ResourceGrants = nil
		if err := f.AuthorizeUploadVEX(t.Context(), revoked, in); !errors.Is(err, evidenceapp.ErrForbidden) {
			t.Fatal("revoked VEX guard", err)
		}
		if _, err := f.UploadVEXPayload(t.Context(), revoked, in, source); !errors.Is(err, app.ErrForbidden) || *opens != 0 {
			t.Fatal("revoked VEX parsed", err)
		}
		for _, bad := range []evidenceapp.PayloadSource{{Digest: source.Digest, Size: source.Size}, {Digest: "sha256:" + strings.Repeat("f", 64), Size: source.Size, Open: source.Open}, {Digest: source.Digest, Size: app.EvidenceDocumentLimit + 1, Open: source.Open}, evidenceapp.BytesPayloadSource([]byte(`{}`)), evidenceapp.BytesPayloadSource([]byte(`[]`))} {
			if v, err := f.UploadVEXPayload(t.Context(), human, in, bad); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v, evidencedomain.VEXDocument{}) {
				t.Fatal("bad VEX stream returned document", err)
			}
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := f.UploadVEXPayload(ctx, human, in, source); !errors.Is(err, context.Canceled) {
			t.Fatal("VEX cancellation lost", err)
		}
		if *opens != *closes {
			t.Fatal("VEX leaked malformed stream")
		}
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) || objects.stages != 0 || clock.calls != 0 {
		t.Fatal("denied/malformed VEX published effects", err)
	}
}

func TestVEXIngestionNativeFixturePreservesExplicitNoStorageResourcesAndSafeHTTPFailure(t *testing.T) {
	ledger, base, objects := signatureRegressionLedger(t)
	owner := seedSignatureFixtureScope(t, ledger, "Owner")
	release, err := releaseSetup(ledger).CreateRelease(t.Context(), owner.actor, owner.product.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	clock := &diffFixtureClock{at: time.Date(2026, 10, 9, 17, 0, 0, 0, time.UTC)}
	f := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, clock: clock}
	s := &Server{vexIngestionCommands: f}
	rebound := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: base, Now: func() time.Time { panic("rebound VEX used aggregate clock") }})
	s.bindIngestionFixturePorts(rebound)
	bound, ok := s.vexIngestionCommands.(ingestionFixtureCommands)
	if !ok || bound.objects != nil || bound.clock != clock || bound.ledger != rebound {
		t.Fatal("VEX rebind lost explicit no-storage resources")
	}
	in := evidenceapp.VEXIngestionInput{ReleaseID: release.ID, ArtifactID: owner.artifact.ID, Format: "openvex"}
	source := evidenceapp.BytesPayloadSource([]byte(nativeOpenVEXFixture))
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	v, err := bound.UploadVEXPayload(t.Context(), owner.actor, in, source)
	if err != nil || v.CreatedAt != clock.at || v.Author != "security@example.test" || v.StatementCount != 1 {
		t.Fatal("no-storage VEX acceptance changed", err)
	}
	after, err := base.Snapshot()
	if err != nil || len(after.Evidence) != len(before.Evidence)+1 || len(after.VEXDocuments) != len(before.VEXDocuments)+1 || len(after.VEXImportReports) != len(before.VEXImportReports)+1 || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+2 || len(after.OutboxJobs) != len(before.OutboxJobs)+1 || len(after.ObjectPayloads) != len(before.ObjectPayloads) || len(after.Decisions) != len(before.Decisions) || objects.stages != 0 || after.Evidence[v.EvidenceID].PayloadRef != "" {
		t.Fatal("no-storage VEX recovered hidden storage or synchronous decision path", err)
	}
	for _, r := range after.VEXImportReports {
		if r.VEXDocumentID == v.ID && (r.Status != "accepted" || r.DecisionsCreated != 0 || r.DecisionsSuperseded != 0) {
			t.Fatal("no-storage report pretended worker completion")
		}
	}
	s.bindDocumentIngestionFixtureResources(objects, clock, false)
	bound, ok = s.vexIngestionCommands.(ingestionFixtureCommands)
	if !ok || bound.objects != objects || bound.clock != clock {
		t.Fatal("explicit VEX resources not applied")
	}
	s, err = newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	s.authn = &configuredAuthenticator{actor: owner.actor}
	f.objects = objects
	failure := &failingIngestionFixture{ingestionFixtureCommands: f}
	s.vexIngestionCommands = failure
	body := fmt.Sprintf(`{"release_id":%q,"artifact_id":%q,"payload":%s}`, release.ID, owner.artifact.ID, nativeOpenVEXFixture)
	before = after
	response := postRaw(t, s, owner.secret, "/v1/vex", "vex-native-failure", []byte(body), 500)
	if failure.changedID == "" || !failure.isolated || objects.stages != 1 {
		t.Fatal("VEX failure skipped native writes/isolation/staging")
	}
	for _, private := range []string{failure.changedID, `"data"`, "security@example.test", "CVE-2026-0001", "private ingestion"} {
		if strings.Contains(response, private) {
			t.Fatal("failed VEX disclosed data or internal error", response)
		}
	}
	after, err = base.Snapshot()
	if err != nil || len(after.Idempotency) != 1 {
		t.Fatal("VEX failure lost replay state", err)
	}
	for _, record := range after.Idempotency {
		if record.State != app.IdempotencyFailed || record.Status != 0 || record.Response != nil {
			t.Fatal("failed VEX response cached as success")
		}
	}
	after.Idempotency = before.Idempotency
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failed HTTP VEX committed evidence/document/report/payload/audit/jobs")
	}
	explicit := &vexIngestionHTTPFake{}
	s.vexIngestionCommands = explicit
	s.bindIngestionFixturePorts(rebound)
	s.bindDocumentIngestionFixtureResources(objects, clock, false)
	if s.vexIngestionCommands != explicit {
		t.Fatal("VEX rebind replaced injected port")
	}
	missing := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture"})}}
	if err := missing.AuthorizeUploadVEX(t.Context(), owner.actor, in); !errors.Is(err, evidenceapp.ErrValidation) {
		t.Fatal("missing VEX repository guard fell back", err)
	}
	if v, err := missing.UploadVEXPayload(t.Context(), owner.actor, in, source); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v, evidencedomain.VEXDocument{}) {
		t.Fatal("missing VEX repository write fell back", err)
	}
}
