package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type reportFixtureSigner struct {
	calls   int
	request app.SigningRequest
	mode    string
	onSign  func()
}

func (f *reportFixtureSigner) Sign(ctx context.Context, r app.SigningRequest) (app.SigningResult, error) {
	f.calls++
	f.request = r
	if f.onSign != nil {
		f.onSign()
	}
	if err := ctx.Err(); err != nil {
		return app.SigningResult{}, err
	}
	if f.mode == "unavailable" {
		return app.SigningResult{}, app.ErrRetryableSigning
	}
	v := app.SigningResult{Signature: "fixture-private-signature-value", KeyID: "receipt-key", Algorithm: "external-aws_kms", ProviderID: r.ProviderID, ProviderType: r.ProviderType, KeyRef: r.KeyRef, CanonicalPayloadHash: r.CanonicalPayloadHash, RequestID: r.RequestID, ProviderRequestID: "receipt-public-id", Checks: []domain.VerifyCheck{{Name: "fixture_provider_binding", Result: "passed", Detail: "Recorded fixture response"}}}
	if f.mode == "wrong-binding" {
		v.CanonicalPayloadHash = "sha256:" + strings.Repeat("f", 64)
	}
	if f.mode == "failed-check" {
		v.Checks[0].Result = "failed"
	}
	return v, nil
}
func reportSigningRegressionLedger(t *testing.T) (*app.Ledger, *app.MemoryUnitOfWorkFactory, *signatureFixtureStore, *reportFixtureSigner) {
	t.Helper()
	store, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	objects, signer, factory := &signatureFixtureStore{Store: store}, &reportFixtureSigner{}, app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory, ObjectStore: objects, Signer: signer, Now: func() time.Time { return time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC) }})
	return ledger, factory, objects, signer
}

type reportSigningFixtureScope struct {
	operationsFixtureScope
	provider domain.SigningProvider
}

func seedReportSigningFixtureScope(t *testing.T, ledger *app.Ledger, name string) reportSigningFixtureScope {
	t.Helper()
	f := reportSigningFixtureScope{operationsFixtureScope: seedOperationsFixtureScope(t, ledger, name)}
	var err error
	f.provider, err = ledger.CreateSigningProvider(t.Context(), f.actor, app.CreateSigningProviderInput{Name: name, Type: "aws_kms", KeyRef: "key-" + name, Encrypted: true})
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func reportSigningFixtureHuman(f reportSigningFixtureScope) domain.Actor {
	return domain.Actor{TenantID: f.actor.TenantID, UserID: "fixture-human", Scopes: []string{"report:read", "keys:admin"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: f.product.ID, Scopes: []string{"report:read"}}, {ResourceType: "tenant", ResourceID: f.actor.TenantID, Scopes: []string{"keys:admin"}}}}
}
func reportSigningFixtureRequests(f reportSigningFixtureScope) []struct{ name, path, body, auditType string } {
	return []struct{ name, path, body, auditType string }{
		{"pdf", "/v1/reports/pdf", fmt.Sprintf(`{"report_type":"release_readiness","product_id":%q,"release_id":%q,"title":" Readiness "}`, f.product.ID, f.release.ID), "pdf_report.created"},
		{"anomaly", "/v1/reports/anomaly", fmt.Sprintf(`{"subject_type":"release","subject_id":%q}`, f.release.ID), "anomaly_report.created"},
		{"signing", "/v1/signing-operations", fmt.Sprintf(`{"provider_id":%q,"subject_type":"release","subject_id":%q,"payload_hash":"sha256:%s"}`, f.provider.ID, f.release.ID, strings.Repeat("a", 64)), "signing_operation.created"},
	}
}

type failingReportSigningFixture struct {
	reportSigningFixtureCommands
	changedID string
	isolated  bool
}

func (f *failingReportSigningFixture) fail(ctx context.Context, id string, err error) error {
	if err != nil {
		return err
	}
	f.changedID, f.isolated = id, f.commandLedger(ctx) != f.ledger
	return errors.New("private report signing failure after write")
}
func (f *failingReportSigningFixture) CreatePDFReportPackage(ctx context.Context, a domain.Actor, in packageapp.CreatePDFReportInput) (packagedomain.PDFReportPackage, error) {
	v, err := f.reportSigningFixtureCommands.CreatePDFReportPackage(ctx, a, in)
	return v, f.fail(ctx, v.ID, err)
}
func (f *failingReportSigningFixture) GenerateAnomalyReport(ctx context.Context, a domain.Actor, in experimentalapp.AnomalyReportInput) (experimentaldomain.AnomalyReport, error) {
	v, err := f.reportSigningFixtureCommands.GenerateAnomalyReport(ctx, a, in)
	return v, f.fail(ctx, v.ID, err)
}
func (f *failingReportSigningFixture) CreateSigningOperation(ctx context.Context, a domain.Actor, in verificationapp.SigningOperationInput) (verificationdomain.SigningOperation, error) {
	v, err := f.reportSigningFixtureCommands.CreateSigningOperation(ctx, a, in)
	return v, f.fail(ctx, v.ID, err)
}

func TestReportSigningFixturesRollBackRecordPayloadJobSignatureAuditAndReplayAfterWrite(t *testing.T) {
	for index := 0; index < 3; index++ {
		ledger, factory, objects, signer := reportSigningRegressionLedger(t)
		owner := seedReportSigningFixtureScope(t, ledger, "Owner")
		request := reportSigningFixtureRequests(owner)[index]
		t.Run(request.name, func(t *testing.T) {
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			server.authn = &configuredAuthenticator{actor: reportSigningFixtureHuman(owner)}
			commands := &failingReportSigningFixture{reportSigningFixtureCommands: reportSigningFixtureCommands{catalogFixtureCommands{ledger: ledger}}}
			server.pdfReportCommands, server.anomalyReportCommands, server.signingOperationCommands = commands, commands, commands
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 500)
			if commands.changedID == "" || !commands.isolated || strings.Contains(out, commands.changedID) || strings.Contains(out, `"data"`) || strings.Contains(out, "private report") || strings.Contains(out, "fixture-private-signature") {
				t.Fatal("partial report/signing write bypassed isolation or leaked success")
			}
			after, err := factory.Snapshot()
			if err != nil || len(after.Idempotency) != len(before.Idempotency)+1 {
				t.Fatal("failed receipt missing", err)
			}
			for key, receipt := range after.Idempotency {
				if _, exists := before.Idempotency[key]; !exists && (receipt.State != app.IdempotencyFailed || receipt.Status != 0 || receipt.Response != nil) {
					t.Fatal("failed report/signing command cached partial success")
				}
			}
			after.Idempotency = before.Idempotency
			if !reflect.DeepEqual(before, after) {
				t.Fatal("failed command committed report, payload metadata, finalizer job, signature, audit or outbox effects")
			}
			wantStages, wantSigns := 0, 0
			if request.name == "pdf" {
				wantStages = 1
				in, err := decodePDFReportRequest([]byte(request.body))
				if err != nil {
					t.Fatal(err)
				}
				raw, err := packageapp.PDFReportPayload(in)
				if err != nil {
					t.Fatal(err)
				}
				digest := app.BytesPayloadSource(raw).Digest
				staging, final, err := app.CanonicalObjectPayloadKeys(owner.actor.TenantID, digest)
				if err != nil {
					t.Fatal(err)
				}
				staged, err := objects.Get(t.Context(), staging)
				if err != nil || !reflect.DeepEqual(staged.Bytes, raw) || staged.Digest != digest {
					t.Fatal("failed PDF did not exercise exact unreferenced physical staging", err)
				}
				if _, err := objects.Get(t.Context(), final); !errors.Is(err, app.ErrNotFound) {
					t.Fatal("failed PDF finalized its staged bytes", err)
				}
			}
			if request.name == "signing" {
				wantSigns = 1
			}
			if objects.stages != wantStages || signer.calls != wantSigns {
				t.Fatal("rollback test failed to exercise the real staging/signing boundary", objects.stages, signer.calls)
			}
		})
	}
}

func TestReportSigningFixturesPreserveCompleteDTOHashAuditAndReplayWithoutRepeatedIO(t *testing.T) {
	ledger, factory, objects, signer := reportSigningRegressionLedger(t)
	owner := seedReportSigningFixtureScope(t, ledger, "Owner")
	foreign := seedReportSigningFixtureScope(t, ledger, "Foreign")
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	human := reportSigningFixtureHuman(owner)
	auth := &configuredAuthenticator{actor: human}
	server.authn = auth
	for _, request := range reportSigningFixtureRequests(owner) {
		t.Run(request.name, func(t *testing.T) {
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			original := postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 201)
			id := dataField(t, original, "id")
			after, err := factory.Snapshot()
			if err != nil || len(after.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+1 || len(after.Idempotency) != len(before.Idempotency)+1 {
				t.Fatal("fresh report/signing command lacks one audit and receipt", err)
			}
			var value any
			var hash, signature string
			switch request.name {
			case "pdf":
				v := after.PDFReports[id]
				in, err := decodePDFReportRequest([]byte(request.body))
				if err != nil {
					t.Fatal(err)
				}
				raw, err := packageapp.PDFReportPayload(in)
				if err != nil || len(after.PDFReports) != len(before.PDFReports)+1 || v.Title != "Readiness" || v.ProductID != owner.product.ID || v.ReleaseID != owner.release.ID || v.PayloadHash != app.BytesPayloadSource(raw).Digest || v.PayloadSize != int64(len(raw)) || len(after.ObjectPayloads) != len(before.ObjectPayloads)+1 || len(after.OutboxJobs) != len(before.OutboxJobs)+1 {
					t.Fatal("PDF lost exact payload/hash, coordinates or atomic lifecycle/job", err)
				}
				staging, final, err := app.CanonicalObjectPayloadKeys(human.TenantID, v.PayloadHash)
				if err != nil || v.PayloadRef != "object://"+final {
					t.Fatal("PDF returned noncanonical final reference", err)
				}
				stored, err := objects.Get(t.Context(), staging)
				if err != nil || !reflect.DeepEqual(stored.Bytes, raw) {
					t.Fatal("PDF staged payload differs", err)
				}
				foundPayload, foundJob := false, false
				for _, payload := range after.ObjectPayloads {
					if payload.TenantID == human.TenantID && payload.Digest == v.PayloadHash {
						foundPayload = payload.Status == app.ObjectPayloadStaged && payload.StagingKey == staging && payload.FinalKey == final && payload.Size == v.PayloadSize && payload.MediaType == "application/pdf" && payload.FinalizedAt == nil
					}
				}
				for key, job := range after.OutboxJobs {
					if _, existed := before.OutboxJobs[key]; !existed {
						foundJob = job.Kind == "finalize_payload" && job.TenantID == human.TenantID && job.SubjectType == "object_payload" && job.SubjectID == v.PayloadHash && job.Payload["payload_digest"] == v.PayloadHash
					}
				}
				if !foundPayload || !foundJob {
					t.Fatal("PDF did not atomically bind exact staging metadata and finalizer job")
				}
				value, hash = v, v.PayloadHash
			case "anomaly":
				v := after.AnomalyReports[id]
				if len(after.AnomalyReports) != len(before.AnomalyReports)+1 || v.Result != "attention_required" || len(v.Signals) != 2 || len(v.Assumptions) == 0 || len(v.Limitations) == 0 || v.SubjectID != owner.release.ID {
					t.Fatal("anomaly test lacks meaningful detached release signals")
				}
				value = v
			case "signing":
				v := after.SigningOperations[id]
				if len(after.SigningOperations) != len(before.SigningOperations)+1 || len(after.Signatures) != len(before.Signatures)+1 || v.Result != "passed" || v.ProviderID != owner.provider.ID || v.SubjectID != owner.release.ID || v.CanonicalPayloadHash == "" || v.RequestID == "" || v.ProviderRequestID != "receipt-public-id" || v.SignatureRef == "" || len(v.Checks) < 5 || after.Signatures[v.SignatureRef].Value != "fixture-private-signature-value" || signer.calls != 1 {
					t.Fatal("signing receipt lost exact bindings, checks or persisted signature")
				}
				r := signer.request
				wantHash, err := verificationapp.CanonicalProviderSigningRequestHash(verificationapp.ProviderSigningRequest{Profile: r.Profile, TenantID: r.TenantID, ProviderID: r.ProviderID, ProviderType: r.ProviderType, ExpectedProviderType: r.ExpectedProviderType, KeyRef: r.KeyRef, SubjectType: r.SubjectType, SubjectID: r.SubjectID, PayloadHash: r.PayloadHash, CanonicalPayloadHash: r.CanonicalPayloadHash, RequestID: r.RequestID, Nonce: r.Nonce})
				if err != nil || wantHash != v.CanonicalPayloadHash || r.TenantID != human.TenantID || r.ProviderID != owner.provider.ID || r.KeyRef != owner.provider.KeyRef || r.SubjectID != owner.release.ID || r.RequestID != v.RequestID || r.PayloadHash != v.PayloadHash {
					t.Fatal("signer received unbound or noncanonical request", err)
				}
				value, hash, signature = v, v.PayloadHash, v.SignatureRef
			}
			want, err := json.Marshal(map[string]any{"data": value, "meta": map[string]string{"api_version": "v1"}})
			if err != nil {
				t.Fatal(err)
			}
			assertTrustHTTPReplay(t, string(want), original)
			if strings.Contains(original, "fixture-private-signature-value") {
				t.Fatal("public receipt exposed raw provider signature")
			}
			audit := after.AuditEntries[human.TenantID][len(after.AuditEntries[human.TenantID])-1]
			if audit.TenantID != human.TenantID || audit.ActorType != "human_user" || audit.ActorID != human.UserID || audit.SubjectID != id || audit.EntryType != request.auditType || audit.PayloadHash != hash || audit.SignatureRef != signature {
				t.Fatal("report/signing audit lost human caller or payload/signature binding")
			}
			stages, signs := objects.stages, signer.calls
			signer.mode = "unavailable"
			expectedReplay := original
			if request.name == "pdf" {
				// Fresh creation returns a reference; the existing privacy-safe
				// receipt deliberately omits it while retaining every other field.
				var envelope struct {
					Data map[string]any `json:"data"`
					Meta map[string]any `json:"meta"`
				}
				if err := json.Unmarshal([]byte(original), &envelope); err != nil {
					t.Fatal(err)
				}
				delete(envelope.Data, "payload_ref")
				encoded, err := json.Marshal(envelope)
				if err != nil {
					t.Fatal(err)
				}
				expectedReplay = string(encoded)
				for _, receipt := range after.Idempotency {
					raw, err := json.Marshal(receipt.Response)
					if err != nil || strings.Contains(string(raw), `"payload_ref"`) {
						t.Fatal("stored replay retained private object reference", err)
					}
				}
			}
			assertTrustHTTPReplay(t, expectedReplay, postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 201))
			for _, grants := range [][]domain.ResourceGrant{nil, {{ResourceType: "product", ResourceID: foreign.product.ID, Scopes: []string{"*"}}}} {
				auth.actor.ResourceGrants = grants
				postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 403)
			}
			auth.actor = human
			postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body+" "), 409)
			auth.err = app.ErrUnauthorized
			postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 401)
			auth.err = nil
			signer.mode = ""
			latest, err := factory.Snapshot()
			if err != nil || !reflect.DeepEqual(after, latest) || stages != objects.stages || signs != signer.calls {
				t.Fatal("saved/rejected report replay changed state, staged bytes or signed again", err)
			}
		})
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	stages, signs := objects.stages, signer.calls
	for index, request := range reportSigningFixtureRequests(owner) {
		var replacements [][2]string
		switch index {
		case 0:
			replacements = [][2]string{{owner.product.ID, foreign.product.ID}, {owner.release.ID, foreign.release.ID}}
		case 1:
			replacements = [][2]string{{owner.release.ID, foreign.release.ID}}
		case 2:
			replacements = [][2]string{{owner.provider.ID, foreign.provider.ID}, {owner.release.ID, foreign.release.ID}}
		}
		for _, pair := range replacements {
			postRaw(t, server, "fixture-auth", request.path, "foreign", []byte(strings.Replace(request.body, pair[0], pair[1], 1)), 404)
		}
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) || stages != objects.stages || signs != signer.calls {
		t.Fatal("foreign preflight reserved records, staged bytes or contacted signer", err)
	}
}

func TestReportSigningFixtureGuardsArePureAndHonorCancellation(t *testing.T) {
	ledger, factory, objects, signer := reportSigningRegressionLedger(t)
	owner := seedReportSigningFixtureScope(t, ledger, "Owner")
	human := reportSigningFixtureHuman(owner)
	commands := reportSigningFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	pdf := packageapp.CreatePDFReportInput{ReportType: "release_readiness", ReleaseID: owner.release.ID, Title: "Readiness"}
	anomaly := experimentalapp.AnomalyReportInput{SubjectType: "release", SubjectID: owner.release.ID}
	signing := verificationapp.SigningOperationInput{ProviderID: owner.provider.ID, SubjectType: "release", SubjectID: owner.release.ID, PayloadHash: "sha256:" + strings.Repeat("a", 64)}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, guard := range []func(context.Context) error{
		func(ctx context.Context) error { return commands.AuthorizeCreatePDFReportPackage(ctx, human, pdf) },
		func(ctx context.Context) error { return commands.AuthorizeGenerateAnomalyReport(ctx, human, anomaly) },
		func(ctx context.Context) error { return commands.AuthorizeCreateSigningOperation(ctx, human, signing) },
	} {
		if err := guard(t.Context()); err != nil {
			t.Fatal("owned preflight failed", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := guard(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("preflight ignored cancellation", err)
		}
	}
	if objects.stages != 0 || signer.calls != 0 {
		t.Fatal("pure preflight staged bytes or invoked signer")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	signer.onSign = cancel
	if v, err := commands.CreateSigningOperation(ctx, human, signing); !errors.Is(err, context.Canceled) || v.ID != "" || signer.calls != 1 {
		t.Fatal("canceled signer produced a receipt", err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("preflight or canceled signing persisted receipt/signature/audit/replay effects", err)
	}
}

func TestBindLedgerPreservesExplicitReportSigningPorts(t *testing.T) {
	first, _ := integrationRegressionLedger()
	second, _ := integrationRegressionLedger()
	pdf, anomaly, signing := &pdfHTTPFake{}, &anomalyHTTPFake{}, &signingOperationHTTPCommands{}
	executor := &decisionHTTPExecutorFake{}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), first, ServerOptions{PDFReportCommands: pdf, AnomalyReportCommands: anomaly, SigningOperationCommands: signing, DurableCommandExecutor: executor})
	if err != nil {
		t.Fatal(err)
	}
	s.bindLegacyLedgerFixture(second)
	if s.pdfReportCommands != pdf || s.anomalyReportCommands != anomaly || s.signingOperationCommands != signing || s.durableCommandExecutor != executor {
		t.Fatal("fixture rebinding overwrote explicitly configured report/signing ports")
	}
}

func TestReportSigningFixtureMappersPreserveCompleteDTOsWithoutNestedAliasing(t *testing.T) {
	ledger, _, _, _ := reportSigningRegressionLedger(t)
	owner := seedReportSigningFixtureScope(t, ledger, "Owner")
	pdf, err := ledger.CreatePDFReportPackage(t.Context(), owner.actor, app.CreatePDFReportPackageInput{ReportType: "release_readiness", ProductID: owner.product.ID, ReleaseID: owner.release.ID, Title: "Readiness"})
	if err != nil || len(pdf.Limitations) == 0 {
		t.Fatal(err)
	}
	anomaly, err := ledger.GenerateAnomalyReport(t.Context(), owner.actor, app.AnomalyReportInput{SubjectType: "release", SubjectID: owner.release.ID})
	if err != nil || len(anomaly.Signals) == 0 || len(anomaly.Assumptions) == 0 || len(anomaly.Limitations) == 0 {
		t.Fatal(err)
	}
	signing, err := ledger.CreateSigningOperation(t.Context(), owner.actor, app.CreateSigningOperationInput{ProviderID: owner.provider.ID, SubjectType: "release", SubjectID: owner.release.ID, PayloadHash: "sha256:" + strings.Repeat("a", 64)})
	if err != nil || len(signing.Checks) == 0 {
		t.Fatal(err)
	}
	pdfModel, anomalyModel, signingModel := pdfFixtureModel(pdf), anomalyFixtureModel(anomaly), signingOperationFixtureModel(signing)
	for _, pair := range []struct {
		value  any
		encode func() ([]byte, error)
	}{
		{pdf, func() ([]byte, error) { return packageapp.EncodePDFReport(pdfModel) }},
		{anomaly, func() ([]byte, error) { return experimentalapp.EncodeAnomalyReport(anomalyModel) }},
		{signing, func() ([]byte, error) { return verificationapp.EncodeSigningOperation(signingModel) }},
	} {
		want, err := json.Marshal(pair.value)
		if err != nil {
			t.Fatal(err)
		}
		got, err := pair.encode()
		if err != nil {
			t.Fatal(err)
		}
		assertTrustHTTPReplay(t, string(want), string(got))
	}
	pdfBefore, anomalyBefore, signingBefore := pdfFixtureModel(pdf), anomalyFixtureModel(anomaly), signingOperationFixtureModel(signing)
	pdfModel.Limitations[0] = "modified"
	anomalyModel.Signals[0].Detail, anomalyModel.Assumptions[0], anomalyModel.Limitations[0] = "modified", "modified", "modified"
	signingModel.Checks[0].Detail = "modified"
	if !reflect.DeepEqual(pdfBefore, pdfFixtureModel(pdf)) || !reflect.DeepEqual(anomalyBefore, anomalyFixtureModel(anomaly)) || !reflect.DeepEqual(signingBefore, signingOperationFixtureModel(signing)) {
		t.Fatal("focused report/signing mapper aliases mutable legacy data")
	}
}

func TestSigningOperationFixtureProviderFailuresNeverCommitSuccess(t *testing.T) {
	for _, mode := range []string{"unavailable", "wrong-binding", "failed-check"} {
		t.Run(mode, func(t *testing.T) {
			ledger, factory, _, signer := reportSigningRegressionLedger(t)
			owner := seedReportSigningFixtureScope(t, ledger, "Owner")
			signer.mode = mode
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			server.authn = &configuredAuthenticator{actor: reportSigningFixtureHuman(owner)}
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			request := reportSigningFixtureRequests(owner)[2]
			want := 422
			if mode == "unavailable" {
				want = 503
			}
			out := postRaw(t, server, "fixture-auth", request.path, mode, []byte(request.body), want)
			if signer.calls != 1 || strings.Contains(out, `"data"`) || strings.Contains(out, "fixture-private-signature-value") || strings.Contains(out, `"signature_ref"`) {
				t.Fatal("failed or unbound provider result exposed signature authority")
			}
			after, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if mode == "unavailable" {
				// Retryable failures release the reservation, not a poisoned
				// completed or failed receipt requiring a new caller key.
				if !reflect.DeepEqual(before, after) {
					t.Fatal("retryable signing failure persisted effects or poisoned replay")
				}
			} else {
				if len(after.Idempotency) != len(before.Idempotency)+1 {
					t.Fatal("failed signing receipt missing")
				}
				for key, receipt := range after.Idempotency {
					if _, exists := before.Idempotency[key]; !exists && (receipt.State != app.IdempotencyFailed || receipt.Status != 0 || receipt.Response != nil) {
						t.Fatal("failed signing cached partial success")
					}
				}
				after.Idempotency = before.Idempotency
				if !reflect.DeepEqual(before, after) {
					t.Fatal("failed signing committed receipt, signature, audit or job effects")
				}
			}
		})
	}
}
