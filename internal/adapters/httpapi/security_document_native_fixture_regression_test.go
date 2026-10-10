package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func TestSecurityDocumentNativeFixtureUsesCurrentScopeExplicitObjectsAndAtomicEffects(t *testing.T) {
	ledger, base, objects := signatureRegressionLedger(t)
	owner := seedSignatureFixtureScope(t, ledger, "Owner")
	ownerRelease, err := releaseSetup(ledger).CreateRelease(t.Context(), owner.actor, owner.product.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	factory := &operatorQueryFailureFactory{base: base}
	clock := &evidenceFlowFixtureClock{at: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("security document used aggregate clock") }})
	f := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}, objects: objects, clock: clock}
	a := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"security:write"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"security:write"}}}}
	scanIn := evidenceapp.UploadSecurityScanInput{ProductID: owner.product.ID, ReleaseID: ownerRelease.ID, ArtifactID: owner.artifact.ID, Category: "secret_scan", Format: "generic", Scanner: "fixture", TargetRef: owner.artifact.Digest, Raw: []byte(`{"findings":[{"severity":"high"}]}`)}
	manualIn := evidenceapp.UploadManualSecurityDocumentInput{ProductID: owner.product.ID, ReleaseID: ownerRelease.ID, DocumentType: "security_review", Title: " Review ", Sensitivity: "restricted", MediaType: "application/json", Raw: []byte(`{"note":"private-document-body"}`)}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AuthorizeUploadSecurityScan(t.Context(), a, scanIn); err != nil || clock.calls != 0 || objects.stages != 0 {
		t.Fatal("scan preflight used cache/effects or required evidence-write", err)
	}
	if err := f.AuthorizeUploadManualSecurityDocument(t.Context(), a, manualIn); err != nil || clock.calls != 0 || objects.stages != 0 {
		t.Fatal("manual preflight used cache/effects", err)
	}
	scan, err := f.UploadSecurityScan(t.Context(), a, scanIn)
	wantHash := fmt.Sprintf("sha256:%x", sha256.Sum256(scanIn.Raw))
	if err != nil || scan.ID == "" || scan.EvidenceID == "" || scan.TenantID != a.TenantID || scan.ProductID != scanIn.ProductID || scan.ReleaseID != scanIn.ReleaseID || scan.ArtifactID != scanIn.ArtifactID || scan.Category != "secret_scan" || scan.Format != "generic" || scan.Scanner != "fixture" || scan.TargetRef != scanIn.TargetRef || scan.PayloadHash != wantHash || scan.PayloadRef == "" || scan.FindingCount != 1 || !reflect.DeepEqual(scan.Summary, map[string]int{"high": 1}) || !scan.Redacted || !scan.Quarantined || scan.SchemaVersion != evidencedomain.SecurityScanSchemaVersion || scan.CreatedAt != clock.at {
		t.Fatalf("scan lost complete DTO/current scope: err=%v stages=%d clock_calls=%d", err, objects.stages, clock.calls)
	}
	manual, err := f.UploadManualSecurityDocument(t.Context(), a, manualIn)
	if err != nil || manual.ID == "" || manual.EvidenceID == "" || manual.TenantID != a.TenantID || manual.ProductID != manualIn.ProductID || manual.ReleaseID != manualIn.ReleaseID || manual.DocumentType != "security_review" || manual.Title != "Review" || manual.Sensitivity != "restricted" || manual.PayloadHash != fmt.Sprintf("sha256:%x", sha256.Sum256(manualIn.Raw)) || manual.PayloadRef == "" || manual.SchemaVersion != evidencedomain.ManualSecurityDocSchemaVersion || manual.CreatedAt != clock.at {
		t.Fatal("manual lost complete DTO/digest/current scope", err)
	}
	scan.Summary["high"] = 99
	after, err := base.Snapshot()
	if err != nil || len(after.SecurityScans) != len(before.SecurityScans)+1 || len(after.ManualSecurityDocuments) != len(before.ManualSecurityDocuments)+1 || len(after.Evidence) != len(before.Evidence)+2 || len(after.ObjectPayloads) != len(before.ObjectPayloads)+2 || len(after.AuditEntries[a.TenantID]) != len(before.AuditEntries[a.TenantID])+4 || len(after.OutboxJobs) != len(before.OutboxJobs)+2 || objects.stages != 2 || after.SecurityScans[scan.ID].Summary["high"] != 1 {
		t.Fatal("document/evidence/payload/audit/job effects not atomic or summary aliased", err)
	}
	for _, entry := range after.AuditEntries[a.TenantID][len(before.AuditEntries[a.TenantID]):] {
		if entry.ActorType != "human_user" || entry.ActorID != a.UserID {
			t.Fatal("document human audit attribution lost")
		}
	}
	for _, pair := range []struct {
		evidence, digest string
		raw              []byte
	}{{scan.EvidenceID, scan.PayloadHash, scanIn.Raw}, {manual.EvidenceID, manual.PayloadHash, manualIn.Raw}} {
		e := after.Evidence[pair.evidence]
		var p app.ObjectPayload
		for _, payload := range after.ObjectPayloads {
			if payload.TenantID == a.TenantID && payload.Digest == pair.digest {
				p = payload
				break
			}
		}
		if e.PayloadHash != pair.digest || e.CanonicalHash == "" || e.PayloadRef != p.Reference() || p.Status != app.ObjectPayloadStaged || p.Size != int64(len(pair.raw)) {
			t.Fatal("immutable evidence/payload identity lost")
		}
		obj, err := objects.Get(t.Context(), p.StagingKey)
		if err != nil || !reflect.DeepEqual(obj.Bytes, pair.raw) {
			t.Fatal("real staging lost original bytes", err)
		}
		if _, err := objects.Get(t.Context(), p.FinalKey); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("fixture finalized before durable job", err)
		}
		encoded, err := json.Marshal(e)
		if err != nil || strings.Contains(string(encoded), `"findings"`) || strings.Contains(string(encoded), "private-document-body") {
			t.Fatal("evidence metadata included raw private bytes", err)
		}
	}
	factory.fail = true
	scanIn.Raw = append(scanIn.Raw, ' ')
	manualIn.Raw = append(manualIn.Raw, ' ')
	if v, err := f.UploadSecurityScan(t.Context(), a, scanIn); err == nil || !reflect.DeepEqual(v, evidencedomain.SecurityScan{}) {
		t.Fatal("failed commit exposed scan", err)
	}
	if v, err := f.UploadManualSecurityDocument(t.Context(), a, manualIn); err == nil || v != (evidencedomain.ManualSecurityDocument{}) {
		t.Fatal("failed commit exposed manual document", err)
	}
	factory.fail = false
	failed, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, failed) {
		t.Fatal("failed document writes published repository effects", err)
	}
	if objects.stages != 4 {
		t.Fatal("failed writes did not reach real object staging")
	}
	for _, raw := range [][]byte{scanIn.Raw, manualIn.Raw} {
		digest := fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
		staging, final, err := app.CanonicalObjectPayloadKeys(a.TenantID, digest)
		if err != nil {
			t.Fatal(err)
		}
		object, err := objects.Get(t.Context(), staging)
		if err != nil || !reflect.DeepEqual(object.Bytes, raw) || object.Digest != digest {
			t.Fatal("failed transaction lost exact unreferenced staging bytes", err)
		}
		if _, err := objects.Get(t.Context(), final); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("failed document finalized object bytes", err)
		}
	}
}

type securityDocumentCorruptFixtureStore struct{ app.PayloadObjectStore }

func (s securityDocumentCorruptFixtureStore) StagePayload(ctx context.Context, p app.ObjectPayload, r io.Reader) (app.ObjectPayload, error) {
	v, err := s.PayloadObjectStore.StagePayload(ctx, p, r)
	if err != nil {
		return v, err
	}
	v.Size++
	return v, nil
}

func TestSecurityDocumentNativeFixtureRejectsUntrustedStagingAndKeepsExplicitResourcesOnRebind(t *testing.T) {
	ledger, base, objects := signatureRegressionLedger(t)
	owner := seedSignatureFixtureScope(t, ledger, "Owner")
	clock := &evidenceFlowFixtureClock{at: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	f := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, objects: objects, clock: clock}
	in := evidenceapp.UploadManualSecurityDocumentInput{ProductID: owner.product.ID, DocumentType: "threat_model", Title: "Review", Sensitivity: "confidential", MediaType: "application/json", Raw: []byte(`{"private_note":"review"}`)}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	f.objects = securityDocumentCorruptFixtureStore{objects}
	if v, err := f.UploadManualSecurityDocument(t.Context(), owner.actor, in); !errors.Is(err, app.ErrValidation) || v != (evidencedomain.ManualSecurityDocument{}) {
		t.Fatal("untrusted staging metadata accepted", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) || objects.stages != 1 {
		t.Fatal("bad staging metadata published repository effects or skipped object boundary", err)
	}
	f.objects = objects
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: base, Now: func() time.Time { panic("rebound security command used aggregate clock") }})
	s := &Server{securityDocumentCommands: f}
	s.bindIngestionFixturePorts(rebound)
	bound, ok := s.securityDocumentCommands.(ingestionFixtureCommands)
	if !ok || bound.objects != objects || bound.clock != clock || bound.ledger != rebound {
		t.Fatal("rebind discarded explicit security resources/configuration")
	}
	if v, err := bound.UploadManualSecurityDocument(t.Context(), owner.actor, in); err != nil || v.CreatedAt != clock.at || v.PayloadRef == "" {
		t.Fatal("rebound explicit staging/clock lost", err)
	}
	explicit := &securityDocumentHTTPFake{}
	s.securityDocumentCommands = explicit
	s.bindIngestionFixturePorts(ledger)
	s.bindSecurityDocumentFixtureResources(objects, clock)
	if s.securityDocumentCommands != explicit {
		t.Fatal("rebind replaced injected security command")
	}
}

func TestSecurityDocumentNativeFixtureRetainsExplicitMetadataOnlyStorageSemantics(t *testing.T) {
	ledger, base, objects := signatureRegressionLedger(t)
	owner := seedSignatureFixtureScope(t, ledger, "Owner")
	f := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	in := evidenceapp.UploadManualSecurityDocumentInput{ProductID: owner.product.ID, DocumentType: "threat_model", Title: "Review", Sensitivity: "internal", Raw: []byte("private-document")}
	v, err := f.UploadManualSecurityDocument(t.Context(), owner.actor, in)
	if err != nil || v.ID == "" || v.EvidenceID == "" || v.PayloadRef != "" || v.PayloadHash != fmt.Sprintf("sha256:%x", sha256.Sum256(in.Raw)) || objects.stages != 0 {
		t.Fatal("explicit absent storage recovered hidden object store or lost digest", err)
	}
	after, err := base.Snapshot()
	if err != nil || len(after.ManualSecurityDocuments) != len(before.ManualSecurityDocuments)+1 || len(after.Evidence) != len(before.Evidence)+1 || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+2 || len(after.ObjectPayloads) != len(before.ObjectPayloads) || len(after.OutboxJobs) != len(before.OutboxJobs) {
		t.Fatal("metadata-only record invented stored payload/finalization effects", err)
	}
}

func TestSecurityDocumentNativeFixtureHTTPFailureOmitsPrivateBodyAndRollsBackAllEffects(t *testing.T) {
	ledger, base, objects := signatureRegressionLedger(t)
	owner := seedSignatureFixtureScope(t, ledger, "Owner")
	s, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: &configuredAuthenticator{actor: owner.actor}})
	if err != nil {
		t.Fatal(err)
	}
	commands := &failingIngestionFixture{ingestionFixtureCommands: ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, objects: objects}}
	s.securityDocumentCommands = commands
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"product_id":%q,"document_type":"threat_model","title":"Review","sensitivity":"restricted","payload":{"note":"private-http-document"}}`, owner.product.ID)
	out := postRaw(t, s, "fixture", "/v1/security-documents", "failed-private-document", []byte(body), 500)
	if commands.changedID == "" || !commands.isolated || objects.stages != 1 || strings.Contains(out, "private-http-document") || strings.Contains(out, "private ingestion") || strings.Contains(out, commands.changedID) || strings.Contains(out, `"data"`) {
		t.Fatal("failed HTTP document exposed private/generated data or skipped actual write/stage")
	}
	after, err := base.Snapshot()
	if err != nil || len(after.Idempotency) != len(before.Idempotency)+1 {
		t.Fatal("failed HTTP document receipt missing", err)
	}
	for key, record := range after.Idempotency {
		if _, existed := before.Idempotency[key]; !existed && (record.State != app.IdempotencyFailed || record.Status != 0 || record.Response != nil) {
			t.Fatal("failed document cached partial/private success")
		}
	}
	after.Idempotency = before.Idempotency
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failed HTTP document committed evidence/document/payload/audit/job effects")
	}
}

func TestSecurityDocumentNativeFixtureRejectsForeignScopesRevokedGrantsAndMalformedInputsBeforeStaging(t *testing.T) {
	ledger, base, objects := signatureRegressionLedger(t)
	owner := seedSignatureFixtureScope(t, ledger, "Owner")
	ownerRelease, err := releaseSetup(ledger).CreateRelease(t.Context(), owner.actor, owner.product.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	foreign := seedSignatureFixtureScope(t, ledger, "Foreign")
	foreignRelease, err := releaseSetup(ledger).CreateRelease(t.Context(), foreign.actor, foreign.product.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	f := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: base})}, objects: objects}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	in := evidenceapp.UploadSecurityScanInput{ProductID: owner.product.ID, ReleaseID: ownerRelease.ID, ArtifactID: owner.artifact.ID, Category: "sast", Format: "generic", Scanner: "fixture", TargetRef: "api", Raw: []byte(`{"findings":[]}`)}
	for _, change := range []string{"product", "release", "artifact", "malformed", "array", "null", "unknown-field"} {
		bad := in
		want := app.ErrNotFound
		switch change {
		case "product":
			bad.ProductID = foreign.product.ID
		case "release":
			bad.ReleaseID = foreignRelease.ID
		case "artifact":
			bad.ArtifactID = foreign.artifact.ID
		case "malformed":
			bad.Raw = []byte("{")
			want = app.ErrValidation
		case "array":
			bad.Raw = []byte("[]")
			want = app.ErrValidation
		case "null":
			bad.Raw = []byte("null")
			want = app.ErrValidation
		case "unknown-field":
			bad.Raw = []byte(`{"findings":[{"severity":"high","private_marker":"do-not-echo"}]}`)
			want = app.ErrValidation
		}
		if _, err := f.UploadSecurityScan(t.Context(), owner.actor, bad); !errors.Is(err, want) {
			t.Fatal("foreign/malformed scan input accepted", change, err)
		}
	}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"security:write"}}
	if _, err := f.UploadSecurityScan(t.Context(), human, in); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("revoked security grant accepted", err)
	}
	manual := evidenceapp.UploadManualSecurityDocumentInput{ProductID: foreign.product.ID, DocumentType: "threat_model", Title: "Review", Sensitivity: "internal", Raw: []byte("review")}
	if _, err := f.UploadManualSecurityDocument(t.Context(), owner.actor, manual); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("foreign manual scope accepted", err)
	}
	bare := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture"})}, objects: objects}
	if _, err := bare.UploadSecurityScan(t.Context(), owner.actor, in); !errors.Is(err, app.ErrValidation) {
		t.Fatal("missing repository restored cached write", err)
	}
	var nilContext context.Context
	if _, err := f.UploadSecurityScan(nilContext, owner.actor, in); !errors.Is(err, app.ErrValidation) {
		t.Fatal("nil document context accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.UploadSecurityScan(ctx, owner.actor, in); !errors.Is(err, context.Canceled) {
		t.Fatal("document cancellation lost", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) || objects.stages != 0 {
		t.Fatal("denied/invalid documents staged or changed state", err)
	}
}
