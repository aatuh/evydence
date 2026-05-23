package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

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
