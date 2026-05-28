package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

type recordingOutbox struct {
	jobs []OutboxJob
}

func (r *recordingOutbox) Enqueue(_ context.Context, job OutboxJob) error {
	r.jobs = append(r.jobs, job)
	return nil
}

func TestTenantScopedEvidenceAndAPIKeyAuth(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	_, _, secretA, err := ledger.BootstrapTenant(ctx, "Tenant A", "admin-a", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap tenant A: %v", err)
	}
	_, _, secretB, err := ledger.BootstrapTenant(ctx, "Tenant B", "admin-b", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap tenant B: %v", err)
	}
	actorA, err := ledger.Authenticate(ctx, secretA)
	if err != nil {
		t.Fatalf("authenticate A: %v", err)
	}
	actorB, err := ledger.Authenticate(ctx, secretB)
	if err != nil {
		t.Fatalf("authenticate B: %v", err)
	}
	product, err := ledger.CreateProduct(ctx, actorA, "Payments API", "payments-api")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actorA, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	item, err := ledger.CreateEvidence(ctx, actorA, CreateEvidenceInput{
		ProductID:   product.ID,
		ReleaseID:   release.ID,
		Type:        "build",
		Title:       "Build evidence",
		PayloadHash: sampleDigest("build"),
	})
	if err != nil {
		t.Fatalf("create evidence: %v", err)
	}
	if _, err := ledger.GetEvidence(ctx, actorB, item.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant read err = %v, want not found", err)
	}
	keys, err := ledger.ListAPIKeys(ctx, actorA)
	if err != nil {
		t.Fatalf("list keys: %v", err)
	}
	for _, key := range keys {
		if key.Hash != "" {
			t.Fatal("API key hash leaked in list response")
		}
	}
	if strings.Contains(secretA, keys[0].Prefix) && keys[0].Prefix == secretA {
		t.Fatal("full API key secret leaked as prefix")
	}
}

func TestScopedAPIKeyCannotWriteEvidence(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	_, _, adminSecret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	admin, err := ledger.Authenticate(ctx, adminSecret)
	if err != nil {
		t.Fatalf("auth admin: %v", err)
	}
	_, readerSecret, err := ledger.CreateAPIKey(ctx, admin, "reader", []string{ScopeEvidenceRead}, nil)
	if err != nil {
		t.Fatalf("create reader: %v", err)
	}
	reader, err := ledger.Authenticate(ctx, readerSecret)
	if err != nil {
		t.Fatalf("auth reader: %v", err)
	}
	_, err = ledger.CreateEvidence(ctx, reader, CreateEvidenceInput{Type: "build", Title: "Build", PayloadHash: sampleDigest("x")})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("reader create evidence err = %v, want forbidden", err)
	}
}

func TestUploadSBOMEnqueuesParserVersion(t *testing.T) {
	outbox := &recordingOutbox{}
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, Outbox: outbox})
	ctx := context.Background()
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	product, err := ledger.CreateProduct(ctx, actor, "Payments API", "payments-parser-version")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	artifact, err := ledger.RegisterArtifact(ctx, actor, "api.tar.gz", "application/gzip", sampleDigest("api"), 42)
	if err != nil {
		t.Fatalf("artifact: %v", err)
	}
	if _, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"api"}]}`)); err != nil {
		t.Fatalf("upload sbom: %v", err)
	}
	if len(outbox.jobs) != 1 {
		t.Fatalf("outbox jobs = %d, want 1", len(outbox.jobs))
	}
	job := outbox.jobs[0]
	if job.Kind != "parse_sbom" || job.Payload["parser_version"] != ParserVersionCycloneDXJSON {
		t.Fatalf("outbox job = %#v", job)
	}
}

func TestUploadSBOMCanDeferParserSideEffectsToWorker(t *testing.T) {
	outbox := &recordingOutbox{}
	store := NewMemoryStore()
	objects := newTestObjectStore()
	ledger := NewLedger(Config{
		APIKeyPepper:                 "test-pepper",
		Now:                          fixedNow,
		Store:                        store,
		ObjectStore:                  objects,
		Outbox:                       outbox,
		WorkerOwnedParserSideEffects: true,
	})
	ctx := context.Background()
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	product, err := ledger.CreateProduct(ctx, actor, "Payments API", "payments-worker-parser")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	artifact, err := ledger.RegisterArtifact(ctx, actor, "api.tar.gz", "application/gzip", sampleDigest("api"), 42)
	if err != nil {
		t.Fatalf("artifact: %v", err)
	}

	sbom, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"api","purl":"pkg:oci/api"}]}`))
	if err != nil {
		t.Fatalf("upload sbom: %v", err)
	}
	if sbom.SpecVersion != "1.6" || sbom.ComponentCount != 1 || len(sbom.Components) != 1 {
		t.Fatalf("upload response should keep parsed fields: %#v", sbom)
	}

	state, ok, err := store.LoadState(ctx)
	if err != nil || !ok {
		t.Fatalf("load state ok=%v err=%v", ok, err)
	}
	persisted := state.SBOMs[sbom.ID]
	if persisted.SpecVersion != "" || persisted.ComponentCount != 0 || len(persisted.Components) != 0 {
		t.Fatalf("persisted sbom should wait for worker parser side effects: %#v", persisted)
	}
	if len(outbox.jobs) != 1 {
		t.Fatalf("outbox jobs = %d, want 1", len(outbox.jobs))
	}
	job := outbox.jobs[0]
	if job.Kind != "parse_sbom" || job.Payload["payload_ref"] == "" || job.Payload["payload_hash"] == "" {
		t.Fatalf("outbox job missing replay metadata: %#v", job)
	}
	payloadRef, ok := job.Payload["payload_ref"].(string)
	payloadKey := strings.TrimPrefix(payloadRef, "object://")
	if !ok || !strings.HasPrefix(payloadKey, "tenants/"+actor.TenantID+"/") {
		t.Fatalf("payload ref %q is not tenant-prefixed", job.Payload["payload_ref"])
	}
	if _, err := objects.Get(ctx, payloadKey); err != nil {
		t.Fatalf("stored payload missing: %v", err)
	}
}

func TestIdempotencyReplayAndConflict(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	calls := 0
	status, response, err := ledger.WithIdempotency(ctx, actor, "POST", "/v1/products", "idem-1", []byte(`{"name":"A"}`), func() (int, any, error) {
		calls++
		return 201, map[string]string{"id": "prod_1"}, nil
	})
	if err != nil || status != 201 || response == nil {
		t.Fatalf("first idempotent call status=%d response=%v err=%v", status, response, err)
	}
	status, response, err = ledger.WithIdempotency(ctx, actor, "POST", "/v1/products", "idem-1", []byte(`{"name":"A"}`), func() (int, any, error) {
		calls++
		return 201, map[string]string{"id": "prod_2"}, nil
	})
	if err != nil || status != 201 || response == nil {
		t.Fatalf("replay status=%d response=%v err=%v", status, response, err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
	_, _, err = ledger.WithIdempotency(ctx, actor, "POST", "/v1/products", "idem-1", []byte(`{"name":"B"}`), func() (int, any, error) {
		return 201, nil, nil
	})
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflict err = %v, want idempotency conflict", err)
	}
}

func TestIdempotencyIsScopedByHumanSessionActor(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	admin, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("auth admin: %v", err)
	}
	org, err := ledger.CreateOrganization(ctx, admin, CreateOrganizationInput{Name: "Org", Slug: "org"})
	if err != nil {
		t.Fatalf("org: %v", err)
	}
	provider, err := ledger.CreateSSOProvider(ctx, admin, CreateSSOProviderInput{Name: "OIDC", Type: "oidc", Issuer: "https://idp.example.test", ClientID: "client"})
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	userA, err := ledger.CreateUser(ctx, admin, CreateUserInput{OrganizationID: org.ID, Email: "a@example.test", DisplayName: "A"})
	if err != nil {
		t.Fatalf("user a: %v", err)
	}
	userB, err := ledger.CreateUser(ctx, admin, CreateUserInput{OrganizationID: org.ID, Email: "b@example.test", DisplayName: "B"})
	if err != nil {
		t.Fatalf("user b: %v", err)
	}
	for _, user := range []domain.HumanUser{userA, userB} {
		if _, err := ledger.CreateRoleBinding(ctx, admin, CreateRoleBindingInput{SubjectType: "user", SubjectID: user.ID, Role: "security_engineer"}); err != nil {
			t.Fatalf("role binding: %v", err)
		}
	}
	_, secretA, err := ledger.CreateSSOSession(ctx, admin, CreateSSOSessionInput{UserID: userA.ID, ProviderID: provider.ID, ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("session a: %v", err)
	}
	_, secretB, err := ledger.CreateSSOSession(ctx, admin, CreateSSOSessionInput{UserID: userB.ID, ProviderID: provider.ID, ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("session b: %v", err)
	}
	actorA, err := ledger.Authenticate(ctx, secretA)
	if err != nil {
		t.Fatalf("auth a: %v", err)
	}
	actorB, err := ledger.Authenticate(ctx, secretB)
	if err != nil {
		t.Fatalf("auth b: %v", err)
	}
	if _, _, err := ledger.WithIdempotency(ctx, actorA, "POST", "/v1/products", "shared", []byte(`{"name":"A"}`), func() (int, any, error) {
		return 201, map[string]any{"actor": "a"}, nil
	}); err != nil {
		t.Fatalf("idempotency a: %v", err)
	}
	for key := range ledger.idempotency {
		if strings.ContainsRune(key, '\x00') {
			t.Fatalf("idempotency key contains postgres-unsafe NUL: %q", key)
		}
		if parsed, ok := ParseIdempotencyRecordKey(key); !ok || parsed.ActorID == "" {
			t.Fatalf("idempotency key did not parse: %q parsed=%#v ok=%v", key, parsed, ok)
		}
	}
	status, response, err := ledger.WithIdempotency(ctx, actorB, "POST", "/v1/products", "shared", []byte(`{"name":"B"}`), func() (int, any, error) {
		return 201, map[string]any{"actor": "b"}, nil
	})
	if err != nil {
		t.Fatalf("idempotency b should not conflict with actor a: %v", err)
	}
	got, _ := response.(map[string]any)
	if status != 201 || got["actor"] != "b" {
		t.Fatalf("unexpected actor b response status=%d response=%#v", status, response)
	}
}

func TestEvidenceCanonicalHashAndAuditChainVerification(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	item, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{Type: "build", Title: "Build", PayloadHash: sampleDigest("build")})
	if err != nil {
		t.Fatalf("create evidence: %v", err)
	}
	vr, err := ledger.VerifySubject(ctx, actor, "evidence_item", item.ID)
	if err != nil {
		t.Fatalf("verify evidence: %v", err)
	}
	if vr.Result != "passed" {
		t.Fatalf("evidence verify result = %s", vr.Result)
	}
	vr, err = ledger.VerifySubject(ctx, actor, "audit_chain", "")
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if vr.Result != "passed" {
		t.Fatalf("chain verify result = %s", vr.Result)
	}
}

func TestReleaseBundleSignatureVerification(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	product, err := ledger.CreateProduct(ctx, actor, "Payments API", "payments")
	if err != nil {
		t.Fatalf("product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ReleaseID: release.ID, Type: "build", Title: "Build", PayloadHash: sampleDigest("build")}); err != nil {
		t.Fatalf("evidence: %v", err)
	}
	bundle, err := ledger.CreateReleaseBundle(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	vr, err := ledger.VerifySubject(ctx, actor, "release_bundle", bundle.ID)
	if err != nil {
		t.Fatalf("verify bundle: %v", err)
	}
	if vr.Result != "passed" {
		t.Fatalf("bundle verify result = %s", vr.Result)
	}
}

func TestMemoryStorePersistsLedgerState(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	ledger, err := NewLedgerWithError(Config{APIKeyPepper: "test-pepper", Now: fixedNow, Store: store})
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	product, err := ledger.CreateProduct(ctx, actor, "Payments API", "payments")
	if err != nil {
		t.Fatalf("product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	bundle, err := ledger.CreateReleaseBundle(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}

	restarted, err := NewLedgerWithError(Config{APIKeyPepper: "test-pepper", Now: fixedNow, Store: store})
	if err != nil {
		t.Fatalf("restart ledger: %v", err)
	}
	restartedActor, err := restarted.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("auth after restart: %v", err)
	}
	if _, err := restarted.GetRelease(ctx, restartedActor, release.ID); err != nil {
		t.Fatalf("release after restart: %v", err)
	}
	vr, err := restarted.VerifySubject(ctx, restartedActor, "release_bundle", bundle.ID)
	if err != nil {
		t.Fatalf("verify bundle after restart: %v", err)
	}
	if vr.Result != "passed" {
		t.Fatalf("verify result = %s", vr.Result)
	}
}

func TestReleaseReadinessRequiresHandledCriticalFinding(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	scan, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{
		"scanner":"grype",
		"target_ref":"pkg:oci/payments-api",
		"release_id":"`+release.ID+`",
		"findings":[{"vulnerability":"CVE-2026-0001","component":"pkg:apk/openssl@3.1.0","severity":"critical","state":"open"}]
	}`))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if _, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"openssl","version":"3.1.0","purl":"pkg:apk/openssl@3.1.0"}]}`)); err != nil {
		t.Fatalf("sbom: %v", err)
	}
	if _, err := ledger.CreateReleaseBundle(ctx, actor, release.ID); err != nil {
		t.Fatalf("bundle: %v", err)
	}
	addBuildProvenance(t, ledger, actor, release, artifact)
	report, err := ledger.ReleaseReadinessReport(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("readiness: %v", err)
	}
	if report.Result != "failed" || len(report.BlockingFindings) != 1 {
		t.Fatalf("expected blocking critical finding, got %#v", report)
	}
	if _, err := ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{Status: decisionStatusNotAffected, Justification: "vulnerable code is not present"}); err != nil {
		t.Fatalf("decision: %v", err)
	}
	report, err = ledger.ReleaseReadinessReport(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("readiness after decision: %v", err)
	}
	if report.Result != "passed" || len(report.BlockingFindings) != 0 {
		t.Fatalf("expected readiness pass after decision, got %#v", report)
	}
}

func TestOpenVEXIngestionCreatesDecisionAndRejectsMalformedInput(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	if _, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{
		"scanner":"grype",
		"target_ref":"pkg:oci/payments-api",
		"release_id":"`+release.ID+`",
		"findings":[{"vulnerability":"CVE-2026-0002","component":"pkg:apk/openssl@3.1.0","severity":"critical","state":"open"}]
	}`)); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if _, err := ledger.UploadVEX(ctx, actor, release.ID, artifact.ID, []byte(`{
		"@context":"https://openvex.dev/ns/v0.2.0",
		"@id":"https://example.test/vex/1",
		"author":"security@example.test",
		"timestamp":"2026-05-27T12:00:00Z",
		"version":1,
		"statements":[{
			"vulnerability":{"name":"CVE-2026-0002"},
			"products":[{"@id":"pkg:apk/openssl@3.1.0"}],
			"status":"fixed",
			"justification":"fixed in release candidate",
			"impact_statement":"patched before release",
			"action_statement":"ship fixed artifact"
		}]
	}`)); err != nil {
		t.Fatalf("vex: %v", err)
	}
	report, err := ledger.ReleaseReadinessReport(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("readiness: %v", err)
	}
	if len(report.BlockingFindings) != 0 {
		t.Fatalf("VEX decision did not handle finding: %#v", report.BlockingFindings)
	}
	if _, err := ledger.UploadVEX(ctx, actor, release.ID, artifact.ID, []byte(`{"author":"a","timestamp":"2026-05-27T12:00:00Z","statements":[],"extra":true}`)); !errors.Is(err, ErrValidation) {
		t.Fatalf("malformed VEX err = %v, want validation", err)
	}
}

func TestExceptionApprovalControlsReadinessAndTenantScope(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actorA, releaseA, artifactA := setupReleaseRiskFixture(t, ledger)
	_, _, secretB, err := ledger.BootstrapTenant(ctx, "Tenant B", "admin-b", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap B: %v", err)
	}
	actorB, err := ledger.Authenticate(ctx, secretB)
	if err != nil {
		t.Fatalf("auth B: %v", err)
	}
	scan, err := ledger.UploadVulnerabilityScan(ctx, actorA, []byte(`{
		"scanner":"grype",
		"target_ref":"pkg:oci/payments-api",
		"release_id":"`+releaseA.ID+`",
		"findings":[{"vulnerability":"CVE-2026-0003","component":"pkg:apk/openssl@3.1.0","severity":"critical","state":"open"}]
	}`))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if _, err := ledger.UploadSBOM(ctx, actorA, releaseA.ID, artifactA.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"openssl","purl":"pkg:apk/openssl@3.1.0"}]}`)); err != nil {
		t.Fatalf("sbom: %v", err)
	}
	if _, err := ledger.CreateReleaseBundle(ctx, actorA, releaseA.ID); err != nil {
		t.Fatalf("bundle: %v", err)
	}
	addBuildProvenance(t, ledger, actorA, releaseA, artifactA)
	exception, err := ledger.CreateException(ctx, actorA, CreateExceptionInput{ReleaseID: releaseA.ID, FindingID: scan.Findings[0].ID, Reason: "accepted for limited release", Owner: "security", ExpiresAt: fixedNow().Add(24 * time.Hour)})
	if err != nil {
		t.Fatalf("exception: %v", err)
	}
	report, err := ledger.ReleaseReadinessReport(ctx, actorA, releaseA.ID)
	if err != nil {
		t.Fatalf("readiness: %v", err)
	}
	if report.Result != "failed" {
		t.Fatalf("unapproved exception should not pass readiness: %#v", report)
	}
	if _, err := ledger.ApproveException(ctx, actorB, exception.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant approve err=%v, want not found", err)
	}
	if _, err := ledger.ApproveException(ctx, actorA, exception.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	report, err = ledger.ReleaseReadinessReport(ctx, actorA, releaseA.ID)
	if err != nil {
		t.Fatalf("readiness approved: %v", err)
	}
	if report.Result != "passed" || len(report.AcceptedExceptions) != 1 {
		t.Fatalf("approved exception should pass readiness: %#v", report)
	}
}

func TestCollectorBuildAttestationReadinessFlow(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	project, err := ledger.CreateProject(ctx, actor, release.ProductID, "api")
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	if _, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"api","purl":"pkg:oci/payments-api"}]}`)); err != nil {
		t.Fatalf("sbom: %v", err)
	}
	if _, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{"scanner":"grype","target_ref":"pkg:oci/payments-api","release_id":"`+release.ID+`","findings":[]}`)); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if _, err := ledger.CreateReleaseBundle(ctx, actor, release.ID); err != nil {
		t.Fatalf("bundle: %v", err)
	}
	report, err := ledger.ReleaseReadinessReport(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("readiness before build: %v", err)
	}
	if report.Result != "failed" || !hasMissing(report.Gaps, "passed_build") || !hasMissing(report.Gaps, "build_attestation") {
		t.Fatalf("expected build gaps before upload, got %#v", report)
	}

	collector, collectorKey, secret, err := ledger.CreateCollector(ctx, actor, CreateCollectorInput{Name: "gha", Type: "github_actions", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("collector: %v", err)
	}
	if secret == "" || collector.APIKeyID != collectorKey.ID || collectorKey.Hash != "" {
		t.Fatalf("collector API key leaked or not bound: collector=%#v key=%#v secret=%q", collector, collectorKey, secret)
	}
	collectorActor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("auth collector: %v", err)
	}
	if collectorActor.CollectorID != collector.ID {
		t.Fatalf("collector actor id=%q want %q", collectorActor.CollectorID, collector.ID)
	}
	build, err := ledger.CreateBuildRun(ctx, collectorActor, CreateBuildRunInput{
		ProjectID:   project.ID,
		ReleaseID:   release.ID,
		Provider:    "github_actions",
		CommitSHA:   "0123456789abcdef0123456789abcdef01234567",
		Repository:  "aatuh/evydence",
		WorkflowRef: "aatuh/evydence/.github/workflows/release.yml@refs/heads/main",
		RunID:       "123456789",
		RunAttempt:  1,
		Status:      "passed",
		StartedAt:   fixedNow(),
		Outputs:     []domain.BuildOutput{{ArtifactID: artifact.ID, Digest: artifact.Digest}},
		OIDCSubject: "repo:aatuh/evydence:ref:refs/heads/main",
		GitHubActor: "aatu",
		Ref:         "refs/heads/main",
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if build.CollectorID != collector.ID {
		t.Fatalf("build collector_id=%q want %q", build.CollectorID, collector.ID)
	}
	if _, err := ledger.GetBuildRun(ctx, collectorActor, build.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("write-only collector read err=%v, want forbidden", err)
	}
	report, err = ledger.ReleaseReadinessReport(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("readiness after build: %v", err)
	}
	if report.Result != "failed" || !hasMissing(report.Gaps, "build_attestation") {
		t.Fatalf("expected attestation gap after build, got %#v", report)
	}

	attestation, err := ledger.UploadBuildAttestation(ctx, collectorActor, build.ID, dsseForDigest(t, artifact.Digest))
	if err != nil {
		t.Fatalf("attestation: %v", err)
	}
	if attestation.PayloadHash == "" || attestation.SignatureCount != 1 || attestation.PredicateType == "" {
		t.Fatalf("attestation metadata incomplete: %#v", attestation)
	}
	report, err = ledger.ReleaseReadinessReport(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("readiness after attestation: %v", err)
	}
	if report.Result != "passed" {
		t.Fatalf("expected passed readiness, got %#v", report)
	}
}

func TestBuildValidationTenantIsolationAndMalformedAttestation(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actorA, releaseA, artifactA := setupReleaseRiskFixture(t, ledger)
	projectA, err := ledger.CreateProject(ctx, actorA, releaseA.ProductID, "api")
	if err != nil {
		t.Fatalf("project A: %v", err)
	}
	actorB, _, _ := setupReleaseRiskFixture(t, ledger)
	if _, err := ledger.CreateBuildRun(ctx, actorA, CreateBuildRunInput{
		ProjectID:   projectA.ID,
		ReleaseID:   releaseA.ID,
		Provider:    "github_actions",
		CommitSHA:   "bad",
		Repository:  "aatuh/evydence",
		WorkflowRef: "wf",
		RunID:       "1",
		RunAttempt:  1,
		Status:      "passed",
		StartedAt:   fixedNow(),
		Outputs:     []domain.BuildOutput{{ArtifactID: artifactA.ID, Digest: artifactA.Digest}},
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("malformed commit err=%v, want validation", err)
	}
	build, err := ledger.CreateBuildRun(ctx, actorA, CreateBuildRunInput{
		ProjectID:   projectA.ID,
		ReleaseID:   releaseA.ID,
		Provider:    "github_actions",
		CommitSHA:   "0123456789abcdef0123456789abcdef01234567",
		Repository:  "aatuh/evydence",
		WorkflowRef: "wf",
		RunID:       "1",
		RunAttempt:  1,
		Status:      "passed",
		StartedAt:   fixedNow(),
		Outputs:     []domain.BuildOutput{{ArtifactID: artifactA.ID, Digest: artifactA.Digest}},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := ledger.GetBuildRun(ctx, actorB, build.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant build read err=%v, want not found", err)
	}
	if _, err := ledger.UploadBuildAttestation(ctx, actorA, build.ID, []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"@@@","signatures":[{"sig":"abc"}]}`)); !errors.Is(err, ErrValidation) {
		t.Fatalf("bad base64 err=%v, want validation", err)
	}
	if _, err := ledger.UploadBuildAttestation(ctx, actorA, build.ID, dsseForDigest(t, sampleDigest("x"))); !errors.Is(err, ErrValidation) {
		t.Fatalf("unmatched subject err=%v, want validation", err)
	}
}

func TestParsersRejectMalformedInputs(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if _, err := ledger.UploadSBOM(ctx, actor, "", "", []byte(`{"bomFormat":"SPDX"}`)); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid sbom err = %v, want validation", err)
	}
	if _, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{"scanner":"","target_ref":"x"}`)); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid scan err = %v, want validation", err)
	}
	if _, err := ledger.UploadOpenAPIContract(ctx, actor, "", "", "bad", []byte(`{"openapi":"3.1.0"}`)); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid openapi err = %v, want validation", err)
	}
}

func hasMissing(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func addBuildProvenance(t *testing.T, ledger *Ledger, actor domain.Actor, release domain.Release, artifact domain.Artifact) {
	t.Helper()
	ctx := context.Background()
	project, err := ledger.CreateProject(ctx, actor, release.ProductID, "provenance")
	if err != nil {
		t.Fatalf("provenance project: %v", err)
	}
	build, err := ledger.CreateBuildRun(ctx, actor, CreateBuildRunInput{
		ProjectID:   project.ID,
		ReleaseID:   release.ID,
		Provider:    "github_actions",
		CommitSHA:   "0123456789abcdef0123456789abcdef01234567",
		Repository:  "aatuh/evydence",
		WorkflowRef: "aatuh/evydence/.github/workflows/release.yml@refs/heads/main",
		RunID:       "123",
		RunAttempt:  1,
		Status:      "passed",
		StartedAt:   fixedNow(),
		Outputs:     []domain.BuildOutput{{ArtifactID: artifact.ID, Digest: artifact.Digest}},
	})
	if err != nil {
		t.Fatalf("provenance build: %v", err)
	}
	if _, err := ledger.UploadBuildAttestation(ctx, actor, build.ID, dsseForDigest(t, artifact.Digest)); err != nil {
		t.Fatalf("provenance attestation: %v", err)
	}
}

func dsseForDigest(t *testing.T, digest string) []byte {
	t.Helper()
	statement := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": []map[string]any{{
			"name":   "payments-api.tar.gz",
			"digest": map[string]string{"sha256": strings.TrimPrefix(digest, "sha256:")},
		}},
		"predicate": map[string]any{
			"builder":   map[string]string{"id": "https://github.com/actions/runner"},
			"buildType": "https://github.com/actions/workflow",
			"materials": []map[string]any{{
				"uri":    "git+https://github.com/aatuh/evydence",
				"digest": map[string]string{"sha1": "0123456789abcdef0123456789abcdef01234567"},
			}},
		},
	}
	statementBody, err := json.Marshal(statement)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	envelope := map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(statementBody),
		"signatures":  []map[string]string{{"keyid": "test", "sig": "c2ln"}},
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return body
}

func setupReleaseRiskFixture(t *testing.T, ledger *Ledger) (domain.Actor, domain.Release, domain.Artifact) {
	t.Helper()
	ctx := context.Background()
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	product, err := ledger.CreateProduct(ctx, actor, "Payments API", "payments")
	if err != nil {
		t.Fatalf("product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	artifact, err := ledger.RegisterArtifact(ctx, actor, "payments-api.tar.gz", "application/gzip", sampleDigest("artifact"), 123)
	if err != nil {
		t.Fatalf("artifact: %v", err)
	}
	return actor, release, artifact
}

func fixedNow() time.Time {
	return time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
}

func sampleDigest(seed string) string {
	switch seed {
	case "build":
		return "sha256:44575cf5b2853284ce5d55751bc9e87d165bd64d5ef12c55fa291e9d40afae86"
	case "x":
		return "sha256:2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
	default:
		return "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
	}
}
