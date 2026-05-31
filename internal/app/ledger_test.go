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

func TestReleaseSecuritySummaryIsTenantScopedAndRedacted(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	if _, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"openssl","purl":"pkg:apk/openssl@3.1.0"}]}`)); err != nil {
		t.Fatalf("sbom: %v", err)
	}
	scan, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{
		"scanner":"grype",
		"target_ref":"pkg:oci/payments-api",
		"release_id":"`+release.ID+`",
		"findings":[{"vulnerability":"CVE-2026-0099","component":"pkg:apk/openssl@3.1.0","severity":"critical","state":"open"}]
	}`))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	addBuildProvenance(t, ledger, actor, release, artifact)
	if _, err := ledger.CreateReleaseBundle(ctx, actor, release.ID); err != nil {
		t.Fatalf("bundle: %v", err)
	}

	summary, err := ledger.ReleaseSecuritySummary(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if summary.SchemaVersion != domain.ReleaseSecuritySummaryVersion || summary.SBOMStatus != "present" || summary.VulnerabilityScanStatus != "present" {
		t.Fatalf("summary basics missing: %#v", summary)
	}
	if summary.OpenFindingsBySeverity["critical"] != 1 || len(summary.MissingRequiredDecisions) != 1 || summary.ReadinessStatus != "failed" {
		t.Fatalf("summary should show unhandled critical finding: %#v", summary)
	}
	body, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("marshal summary: %v", err)
	}
	for _, forbidden := range []string{"payload_ref", "payload_hash", "internal_notes", "secret", "token"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("summary leaked %q: %s", forbidden, body)
		}
	}

	if _, err := ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{Status: decisionStatusNotAffected, Justification: "vulnerable code is not present"}); err != nil {
		t.Fatalf("decision: %v", err)
	}
	summary, err = ledger.ReleaseSecuritySummary(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("summary after decision: %v", err)
	}
	if len(summary.MissingRequiredDecisions) != 0 || summary.DecisionsByStatus[decisionStatusNotAffected] != 1 || summary.ReadinessStatus != "passed" {
		t.Fatalf("summary should reflect accepted decision: %#v", summary)
	}

	_, readerSecret, err := ledger.CreateAPIKey(ctx, actor, "release-reader", []string{ScopeReleaseRead}, nil)
	if err != nil {
		t.Fatalf("reader key: %v", err)
	}
	reader, err := ledger.Authenticate(ctx, readerSecret)
	if err != nil {
		t.Fatalf("reader auth: %v", err)
	}
	if _, err := ledger.ReleaseSecuritySummary(ctx, reader, release.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("wrong-scope summary err = %v, want forbidden", err)
	}

	_, _, otherSecret, err := ledger.BootstrapTenant(ctx, "Other Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("other bootstrap: %v", err)
	}
	other, err := ledger.Authenticate(ctx, otherSecret)
	if err != nil {
		t.Fatalf("other auth: %v", err)
	}
	if _, err := ledger.ReleaseSecuritySummary(ctx, other, release.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant summary err = %v, want not found", err)
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

func TestUploadVulnerabilityScanCanDeferParserSideEffectsToWorker(t *testing.T) {
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
	product, err := ledger.CreateProduct(ctx, actor, "Payments API", "payments-worker-scan")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}

	scan, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{"scanner":"grype","target_ref":"pkg:oci/api","release_id":"`+release.ID+`","findings":[{"vulnerability":"CVE-2026-0001","component":"api","severity":"critical","state":"open"}]}`))
	if err != nil {
		t.Fatalf("upload scan: %v", err)
	}
	if scan.Scanner != "grype" || scan.Summary["critical"] != 1 || len(scan.Findings) != 1 || !strings.HasPrefix(scan.Findings[0].ID, scan.ID+":finding:") {
		t.Fatalf("upload response should keep parsed scan fields with stable finding ids: %#v", scan)
	}

	state, ok, err := store.LoadState(ctx)
	if err != nil || !ok {
		t.Fatalf("load state ok=%v err=%v", ok, err)
	}
	persisted := state.Scans[scan.ID]
	if persisted.Scanner != "" || persisted.TargetRef != "" || persisted.Summary != nil || len(persisted.Findings) != 0 {
		t.Fatalf("persisted scan should wait for worker parser side effects: %#v", persisted)
	}
	if len(outbox.jobs) != 1 {
		t.Fatalf("outbox jobs = %d, want 1", len(outbox.jobs))
	}
	job := outbox.jobs[0]
	if job.Kind != "parse_vulnerability_scan" || job.Payload["payload_ref"] == "" || job.Payload["payload_hash"] == "" || job.Payload["parser_version"] != ParserVersionGenericVulnerabilityJSON {
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

func TestUploadOpenAPIContractCanDeferParserSideEffectsToWorker(t *testing.T) {
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
	product, err := ledger.CreateProduct(ctx, actor, "Payments API", "payments-worker-openapi")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}

	contract, err := ledger.UploadOpenAPIContract(ctx, actor, product.ID, release.ID, "v1", []byte(`{"openapi":"3.1.0","info":{"title":"API","version":"1"},"paths":{"/v1/a":{"get":{"responses":{"200":{"description":"ok"}}}}}}`))
	if err != nil {
		t.Fatalf("upload contract: %v", err)
	}
	if contract.PathCount != 1 || len(contract.Operations) != 1 {
		t.Fatalf("upload response should keep parsed contract fields: %#v", contract)
	}

	state, ok, err := store.LoadState(ctx)
	if err != nil || !ok {
		t.Fatalf("load state ok=%v err=%v", ok, err)
	}
	persisted := state.Contracts[contract.ID]
	if persisted.PathCount != 0 || len(persisted.Operations) != 0 || persisted.Hash == "" {
		t.Fatalf("persisted contract should wait for worker parser side effects but keep hash: %#v", persisted)
	}
	if len(outbox.jobs) != 1 {
		t.Fatalf("outbox jobs = %d, want 1", len(outbox.jobs))
	}
	job := outbox.jobs[0]
	if job.Kind != "parse_openapi_contract" || job.Payload["payload_ref"] == "" || job.Payload["payload_hash"] == "" || job.Payload["parser_version"] != ParserVersionOpenAPIJSON {
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

func TestUploadBuildAttestationCanDeferParserSideEffectsToWorker(t *testing.T) {
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
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	project, err := ledger.CreateProject(ctx, actor, release.ProductID, "api")
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	_, _, secret, err := ledger.CreateCollector(ctx, actor, CreateCollectorInput{Name: "gha", Type: "github_actions", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("collector: %v", err)
	}
	collectorActor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("auth collector: %v", err)
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
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	attestation, err := ledger.UploadBuildAttestation(ctx, collectorActor, build.ID, dsseForDigest(t, artifact.Digest))
	if err != nil {
		t.Fatalf("attestation: %v", err)
	}
	if attestation.PredicateType == "" || len(attestation.SubjectDigests) != 1 || attestation.SignatureCount != 1 || attestation.VerificationStatus != "structurally_valid" {
		t.Fatalf("upload response should keep parsed attestation fields: %#v", attestation)
	}

	state, ok, err := store.LoadState(ctx)
	if err != nil || !ok {
		t.Fatalf("load state ok=%v err=%v", ok, err)
	}
	persisted := state.BuildAttestations[attestation.ID]
	if persisted.TenantID != actor.TenantID || persisted.PayloadHash == "" || persisted.PayloadSize == 0 || persisted.VerificationStatus != "accepted" {
		t.Fatalf("persisted attestation should keep accepted metadata: %#v", persisted)
	}
	if persisted.PredicateType != "" || len(persisted.SubjectDigests) != 0 || persisted.SignatureCount != 0 {
		t.Fatalf("persisted attestation should wait for worker parser side effects: %#v", persisted)
	}
	if len(outbox.jobs) != 1 {
		t.Fatalf("outbox jobs = %d, want 1", len(outbox.jobs))
	}
	job := outbox.jobs[0]
	if job.Kind != "verify_attestation" || job.Payload["payload_ref"] == "" || job.Payload["payload_hash"] == "" || job.Payload["parser_version"] != ParserVersionDSSEInTotoJSON {
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
	if report.PolicySet == "" || report.Summary.Headline == "" || len(report.Sections) < 5 || !hasMissing(report.MissingEvidence, "vulnerability_decision") || !hasMissing(report.FailedPolicies, "critical_exploitable_blocks_release") || len(report.KnownLimitations) == 0 || len(report.NonClaims) == 0 {
		t.Fatalf("readiness v2 fields missing: %#v", report)
	}
	criticalCheck := policyCheckByName(t, report.Checks, "critical_exploitable_blocks_release")
	if criticalCheck.Remediation == "" {
		t.Fatalf("critical check missing remediation: %#v", criticalCheck)
	}
	criticalQuestion := readinessQuestionByID(t, report, "critical_findings_triaged")
	if criticalQuestion.Status != "missing_evidence" || !hasMissing(criticalQuestion.MissingEvidence, "vulnerability_decision") {
		t.Fatalf("critical readiness question = %#v", criticalQuestion)
	}
	packageQuestion := readinessQuestionByID(t, report, "customer_package_safe_to_share")
	if packageQuestion.Status != "limited" {
		t.Fatalf("customer package question = %#v", packageQuestion)
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
	decisionQuestion := readinessQuestionByID(t, report, "vex_decisions_for_blockers")
	if decisionQuestion.Status != "passed" || !hasMissing(decisionQuestion.Evidence, "vulnerability_decision") {
		t.Fatalf("decision readiness question = %#v", decisionQuestion)
	}
	highScan, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{
		"scanner":"grype",
		"target_ref":"pkg:oci/payments-api",
		"release_id":"`+release.ID+`",
		"findings":[{"vulnerability":"CVE-2026-0002","component":"pkg:apk/curl@8.0.0","severity":"high","state":"open"}]
	}`))
	if err != nil {
		t.Fatalf("high scan: %v", err)
	}
	report, err = ledger.ReleaseReadinessReport(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("readiness after high finding: %v", err)
	}
	highCheck := policyCheckByName(t, report.Checks, "high_findings_require_triage")
	if report.Result != "failed" || highCheck.Result != "failed" || highCheck.Remediation == "" {
		t.Fatalf("expected high finding triage failure, report=%#v check=%#v", report, highCheck)
	}
	if _, err := ledger.CreateVulnerabilityDecision(ctx, actor, highScan.Findings[0].ID, CreateVulnerabilityDecisionInput{Status: decisionStatusFixed, Justification: "fixed in release"}); err != nil {
		t.Fatalf("high decision: %v", err)
	}
	report, err = ledger.ReleaseReadinessReport(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("readiness after high decision: %v", err)
	}
	if report.Result != "passed" {
		t.Fatalf("expected readiness pass after high decision, got %#v", report)
	}
	profile, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{Name: "unsafe package profile", AllowedTypes: []string{"vulnerability_decision"}})
	if err != nil {
		t.Fatalf("redaction profile: %v", err)
	}
	if _, err := ledger.CreateCustomerSecurityPackage(ctx, actor, CreateCustomerPackageInput{ProductID: release.ProductID, ReleaseID: release.ID, RedactionProfileID: profile.ID, Title: "Unsafe package", ExpiresAt: fixedNow().Add(time.Hour)}); err != nil {
		t.Fatalf("customer package: %v", err)
	}
	report, err = ledger.ReleaseReadinessReport(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("readiness after unsafe package: %v", err)
	}
	packageCheck := policyCheckByName(t, report.Checks, "package_redaction_profile_valid")
	if report.Result != "failed" || packageCheck.Result != "failed" || packageCheck.Remediation == "" {
		t.Fatalf("expected package redaction failure, report=%#v check=%#v", report, packageCheck)
	}
}

func TestCustomerVisibleDecisionRequiresImpactAndRedactsInternalNotes(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	scan, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{
		"scanner":"grype",
		"target_ref":"pkg:oci/payments-api",
		"release_id":"`+release.ID+`",
		"findings":[{"vulnerability":"CVE-2026-0100","component":"pkg:apk/openssl@3.1.0","severity":"critical","state":"open"}]
	}`))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if _, err := ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{
		Status:          decisionStatusNotAffected,
		Justification:   "runtime code path is not present",
		CustomerVisible: true,
		InternalNotes:   "private triage note",
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("customer-visible decision without impact err=%v, want validation", err)
	}
	decision, err := ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{
		Status:          decisionStatusNotAffected,
		Justification:   "runtime code path is not present",
		ImpactStatement: "This release is not affected because the vulnerable runtime code is not included.",
		ActionStatement: "No customer action is required for this finding.",
		CustomerVisible: true,
		InternalNotes:   "private triage note",
	})
	if err != nil {
		t.Fatalf("decision: %v", err)
	}
	if !decision.CustomerVisible || decision.InternalNotes != "private triage note" {
		t.Fatalf("decision customer visibility/internal notes not preserved: %#v", decision)
	}
	profile, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{Name: "customer decisions", AllowedTypes: []string{"vulnerability_decision"}})
	if err != nil {
		t.Fatalf("redaction profile: %v", err)
	}
	pkg, err := ledger.CreateCustomerSecurityPackage(ctx, actor, CreateCustomerPackageInput{
		ProductID:          release.ProductID,
		ReleaseID:          release.ID,
		RedactionProfileID: profile.ID,
		Title:              "Customer decision package",
		ExpiresAt:          fixedNow().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("customer package: %v", err)
	}
	body, err := json.Marshal(pkg.Manifest)
	if err != nil {
		t.Fatalf("marshal package manifest: %v", err)
	}
	if !strings.Contains(string(body), decision.ImpactStatement) {
		t.Fatalf("package manifest missing customer-safe impact statement: %s", body)
	}
	if strings.Contains(string(body), "private triage note") {
		t.Fatalf("package manifest leaked internal notes: %s", body)
	}
}

func TestVulnerabilityDecisionSummaryReportRedactsInternalAndOnlyIncludesActiveVisible(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	supporting, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{
		ProductID: release.ProductID, ReleaseID: release.ID, Type: "security_review", Title: "Runtime review", PayloadHash: sampleDigest("summary-support"),
	})
	if err != nil {
		t.Fatalf("supporting evidence: %v", err)
	}
	scan, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{
		"scanner":"grype",
		"target_ref":"pkg:oci/payments-api",
		"release_id":"`+release.ID+`",
		"findings":[
			{"vulnerability":"CVE-2026-0104","component":"pkg:apk/openssl@3.1.0","severity":"critical","state":"open"},
			{"vulnerability":"CVE-2026-0105","component":"pkg:apk/zlib@1.2.13","severity":"critical","state":"open"}
		]
	}`))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	first, err := ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{
		Status:          decisionStatusUnderInvestigation,
		Justification:   "review started",
		ImpactStatement: "Initial customer impact statement.",
		CustomerVisible: true,
		InternalNotes:   "old private note",
	})
	if err != nil {
		t.Fatalf("first decision: %v", err)
	}
	second, err := ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{
		Status:          decisionStatusNotAffected,
		Justification:   "runtime path not present",
		ImpactStatement: "This release is not affected because the vulnerable runtime path is not included.",
		ActionStatement: "No customer action is required for this finding.",
		CustomerVisible: true,
		InternalNotes:   "replacement private note",
		EvidenceIDs:     []string{supporting.ID},
	})
	if err != nil {
		t.Fatalf("second decision: %v", err)
	}
	if _, err := ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[1].ID, CreateVulnerabilityDecisionInput{
		Status:        decisionStatusFixed,
		Justification: "fixed but not customer-visible yet",
		InternalNotes: "hidden private note",
	}); err != nil {
		t.Fatalf("hidden decision: %v", err)
	}
	report, err := ledger.VulnerabilityDecisionSummaryReport(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if report.ProductID != release.ProductID || report.ReleaseID != release.ID || len(report.Decisions) != 1 {
		t.Fatalf("summary scope/decision count mismatch: %#v", report)
	}
	got := report.Decisions[0]
	if got.ID != second.ID || got.ImpactStatement != second.ImpactStatement || len(got.EvidenceIDs) != 1 || got.EvidenceIDs[0] != supporting.ID {
		t.Fatalf("summary decision=%#v, want active customer-visible decision", got)
	}
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal summary: %v", err)
	}
	text := string(body)
	if strings.Contains(text, first.ImpactStatement) || strings.Contains(text, "private note") || strings.Contains(text, "hidden private note") {
		t.Fatalf("summary leaked superseded or internal decision data: %s", body)
	}
	if !strings.Contains(text, "not certification") || !strings.Contains(text, second.ImpactStatement) {
		t.Fatalf("summary missing limitations or active impact statement: %s", body)
	}
}

func TestVulnerabilityDecisionLifecycleSupersedesAndPackagesOnlyActive(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	scan, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{
		"scanner":"grype",
		"target_ref":"pkg:oci/payments-api",
		"release_id":"`+release.ID+`",
		"findings":[{"vulnerability":"CVE-2026-0101","component":"pkg:apk/openssl@3.1.0","severity":"critical","state":"open"}]
	}`))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if _, err := ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{
		Status:        "not_a_status",
		Justification: "bad status",
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid lifecycle status err=%v, want validation", err)
	}
	first, err := ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{
		Status:          decisionStatusUnderInvestigation,
		Justification:   "triage started",
		ImpactStatement: "The finding is under investigation.",
		CustomerVisible: true,
		InternalNotes:   "initial private note",
	})
	if err != nil {
		t.Fatalf("first decision: %v", err)
	}
	second, err := ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{
		Status:          decisionStatusFixed,
		Justification:   "patched in release artifact",
		ImpactStatement: "This issue is fixed in the release artifact.",
		ActionStatement: "Upgrade to this release.",
		CustomerVisible: true,
		InternalNotes:   "replacement private note",
	})
	if err != nil {
		t.Fatalf("second decision: %v", err)
	}
	if second.Supersedes != first.ID {
		t.Fatalf("second supersedes=%q, want %q", second.Supersedes, first.ID)
	}
	if got := ledger.decisions[first.ID].SupersededBy; got != second.ID {
		t.Fatalf("first superseded_by=%q, want %q", got, second.ID)
	}
	created, superseded := 0, 0
	for _, entry := range ledger.chain[actor.TenantID] {
		switch {
		case entry.EntryType == "vulnerability_decision.created" && entry.SubjectID == scan.Findings[0].ID:
			created++
		case entry.EntryType == "vulnerability_decision.superseded" && entry.SubjectID == first.ID:
			superseded++
		}
	}
	if created != 2 || superseded != 1 {
		t.Fatalf("decision lifecycle audit counts created=%d superseded=%d", created, superseded)
	}
	profile, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{Name: "active decisions", AllowedTypes: []string{"vulnerability_decision"}})
	if err != nil {
		t.Fatalf("redaction profile: %v", err)
	}
	pkg, err := ledger.CreateCustomerSecurityPackage(ctx, actor, CreateCustomerPackageInput{
		ProductID:          release.ProductID,
		ReleaseID:          release.ID,
		RedactionProfileID: profile.ID,
		Title:              "Active decision package",
		ExpiresAt:          fixedNow().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("customer package: %v", err)
	}
	body, err := json.Marshal(pkg.Manifest)
	if err != nil {
		t.Fatalf("marshal package manifest: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, second.ImpactStatement) {
		t.Fatalf("package manifest missing active impact statement: %s", body)
	}
	if strings.Contains(text, first.ImpactStatement) || strings.Contains(text, "private note") {
		t.Fatalf("package manifest included superseded decision or internal notes: %s", body)
	}
}

func TestListVulnerabilityDecisionsFiltersHistoryAndTenantScope(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	scan, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{
		"scanner":"grype",
		"target_ref":"pkg:oci/payments-api",
		"release_id":"`+release.ID+`",
		"findings":[{"vulnerability":"CVE-2026-0103","component":"pkg:apk/openssl@3.1.0","severity":"critical","state":"open"}]
	}`))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	first, err := ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{
		Status:          decisionStatusUnderInvestigation,
		Justification:   "review started",
		ImpactStatement: "The finding is under investigation.",
		CustomerVisible: true,
	})
	if err != nil {
		t.Fatalf("first decision: %v", err)
	}
	second, err := ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{
		Status:          decisionStatusFixed,
		Justification:   "fixed in release artifact",
		ImpactStatement: "The finding is fixed in this release artifact.",
		CustomerVisible: true,
	})
	if err != nil {
		t.Fatalf("second decision: %v", err)
	}
	history, err := ledger.ListVulnerabilityDecisions(ctx, actor, ListVulnerabilityDecisionsInput{
		ProductID:     release.ProductID,
		ReleaseID:     release.ID,
		Vulnerability: "CVE-2026-0103",
		Component:     "pkg:apk/openssl@3.1.0",
	})
	if err != nil {
		t.Fatalf("list history: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("history length=%d want 2 history=%#v", len(history), history)
	}
	active := true
	activeOnly, err := ledger.ListVulnerabilityDecisions(ctx, actor, ListVulnerabilityDecisionsInput{ReleaseID: release.ID, Active: &active})
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	if len(activeOnly) != 1 || activeOnly[0].ID != second.ID || activeOnly[0].Supersedes != first.ID {
		t.Fatalf("active decisions=%#v, want second decision superseding first", activeOnly)
	}
	active = false
	superseded, err := ledger.ListVulnerabilityDecisions(ctx, actor, ListVulnerabilityDecisionsInput{ReleaseID: release.ID, Status: decisionStatusUnderInvestigation, Active: &active})
	if err != nil {
		t.Fatalf("list superseded: %v", err)
	}
	if len(superseded) != 1 || superseded[0].ID != first.ID || superseded[0].SupersededBy != second.ID {
		t.Fatalf("superseded decisions=%#v, want first decision superseded by second", superseded)
	}
	if _, err := ledger.ListVulnerabilityDecisions(ctx, actor, ListVulnerabilityDecisionsInput{Status: "not_a_status"}); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid status err=%v, want validation", err)
	}
	_, _, secretB, err := ledger.BootstrapTenant(ctx, "Tenant B", "admin-b", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap tenant B: %v", err)
	}
	actorB, err := ledger.Authenticate(ctx, secretB)
	if err != nil {
		t.Fatalf("authenticate tenant B: %v", err)
	}
	foreignHistory, err := ledger.ListVulnerabilityDecisions(ctx, actorB, ListVulnerabilityDecisionsInput{})
	if err != nil {
		t.Fatalf("foreign list: %v", err)
	}
	if len(foreignHistory) != 0 {
		t.Fatalf("foreign tenant saw decisions: %#v", foreignHistory)
	}
}

func TestVulnerabilityDecisionEvidenceLinksAreTenantAndReleaseScoped(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	supporting, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{
		ProductID: release.ProductID, ReleaseID: release.ID, Type: "security_review", Title: "Runtime review", PayloadHash: sampleDigest("supporting-review"),
	})
	if err != nil {
		t.Fatalf("supporting evidence: %v", err)
	}
	otherRelease, err := ledger.CreateRelease(ctx, actor, release.ProductID, "2.0.0")
	if err != nil {
		t.Fatalf("other release: %v", err)
	}
	wrongReleaseEvidence, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{
		ProductID: release.ProductID, ReleaseID: otherRelease.ID, Type: "security_review", Title: "Wrong release review", PayloadHash: sampleDigest("wrong-release-review"),
	})
	if err != nil {
		t.Fatalf("wrong release evidence: %v", err)
	}
	_, _, secretB, err := ledger.BootstrapTenant(ctx, "Tenant B", "admin-b", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap tenant B: %v", err)
	}
	actorB, err := ledger.Authenticate(ctx, secretB)
	if err != nil {
		t.Fatalf("authenticate tenant B: %v", err)
	}
	foreignEvidence, err := ledger.CreateEvidence(ctx, actorB, CreateEvidenceInput{Type: "security_review", Title: "Foreign review", PayloadHash: sampleDigest("foreign-review")})
	if err != nil {
		t.Fatalf("foreign evidence: %v", err)
	}
	scan, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{
		"scanner":"grype",
		"target_ref":"pkg:oci/payments-api",
		"release_id":"`+release.ID+`",
		"findings":[{"vulnerability":"CVE-2026-0102","component":"pkg:apk/openssl@3.1.0","severity":"critical","state":"open"}]
	}`))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if _, err := ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{
		Status:          decisionStatusNotAffected,
		Justification:   "reviewed runtime path",
		ImpactStatement: "The vulnerable runtime path is not included.",
		CustomerVisible: true,
		EvidenceIDs:     []string{wrongReleaseEvidence.ID},
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong-release evidence link err=%v, want not found", err)
	}
	if _, err := ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{
		Status:          decisionStatusNotAffected,
		Justification:   "reviewed runtime path",
		ImpactStatement: "The vulnerable runtime path is not included.",
		CustomerVisible: true,
		EvidenceIDs:     []string{foreignEvidence.ID},
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign evidence link err=%v, want not found", err)
	}
	decision, err := ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{
		Status:          decisionStatusNotAffected,
		Justification:   "reviewed runtime path",
		ImpactStatement: "The vulnerable runtime path is not included.",
		CustomerVisible: true,
		EvidenceIDs:     []string{supporting.ID, supporting.ID},
	})
	if err != nil {
		t.Fatalf("decision: %v", err)
	}
	if len(decision.EvidenceIDs) != 1 || decision.EvidenceIDs[0] != supporting.ID {
		t.Fatalf("decision evidence links = %#v, want %s", decision.EvidenceIDs, supporting.ID)
	}
	profile, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{Name: "decision links", AllowedTypes: []string{"vulnerability_decision"}})
	if err != nil {
		t.Fatalf("redaction profile: %v", err)
	}
	pkg, err := ledger.CreateCustomerSecurityPackage(ctx, actor, CreateCustomerPackageInput{
		ProductID:          release.ProductID,
		ReleaseID:          release.ID,
		RedactionProfileID: profile.ID,
		Title:              "Decision links package",
		ExpiresAt:          fixedNow().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("customer package: %v", err)
	}
	body, err := json.Marshal(pkg.Manifest)
	if err != nil {
		t.Fatalf("marshal package manifest: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, supporting.ID) {
		t.Fatalf("customer package missing linked evidence id: %s", body)
	}
	if strings.Contains(text, wrongReleaseEvidence.ID) || strings.Contains(text, foreignEvidence.ID) {
		t.Fatalf("customer package leaked unlinked/foreign evidence ids: %s", body)
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
	vex, err := ledger.UploadVEX(ctx, actor, release.ID, artifact.ID, []byte(`{
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
	}`))
	if err != nil {
		t.Fatalf("vex: %v", err)
	}
	importReport, err := ledger.GetVEXImportReport(ctx, actor, vex.ID)
	if err != nil {
		t.Fatalf("import report: %v", err)
	}
	if importReport.Status != "parsed" || importReport.StatementCount != 1 || importReport.DecisionsCreated != 1 || importReport.DecisionsSuperseded != 0 || len(importReport.MappingFailures) != 0 {
		t.Fatalf("unexpected import report: %#v", importReport)
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

func TestOpenVEXImportReportTracksSupersessionAndMappingFailures(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	scan, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{
		"scanner":"grype",
		"target_ref":"pkg:oci/payments-api",
		"release_id":"`+release.ID+`",
		"findings":[{"vulnerability":"CVE-2026-0003","component":"pkg:apk/openssl@3.1.0","severity":"critical","state":"open"}]
	}`))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if _, err := ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{
		Status:          decisionStatusUnderInvestigation,
		Justification:   "manual triage started",
		ImpactStatement: "The finding is under investigation.",
		CustomerVisible: true,
	}); err != nil {
		t.Fatalf("manual decision: %v", err)
	}
	vex, err := ledger.UploadVEX(ctx, actor, release.ID, artifact.ID, []byte(`{
		"@context":"https://openvex.dev/ns/v0.2.0",
		"@id":"https://example.test/vex/2",
		"author":"security@example.test",
		"timestamp":"2026-05-27T12:00:00Z",
		"version":1,
		"statements":[{
			"vulnerability":{"name":"CVE-2026-0003"},
			"products":[{"@id":"pkg:apk/openssl@3.1.0"}],
			"status":"fixed",
			"justification":"fixed in release candidate",
			"impact_statement":"patched before release"
		},{
			"vulnerability":{"name":"CVE-2026-9999"},
			"products":[{"@id":"pkg:apk/missing@1.0.0"}],
			"status":"not_affected",
			"justification":"component not present",
			"impact_statement":"not present in this release"
		}]
	}`))
	if err != nil {
		t.Fatalf("vex: %v", err)
	}
	report, err := ledger.GetVEXImportReport(ctx, actor, vex.ID)
	if err != nil {
		t.Fatalf("import report: %v", err)
	}
	if report.StatementCount != 2 || report.DecisionsCreated != 1 || report.DecisionsSuperseded != 1 {
		t.Fatalf("report counts = %#v", report)
	}
	if len(report.MappingFailures) != 1 || report.MappingFailures[0].StatementIndex != 2 || report.MappingFailures[0].Code != "finding_not_found" {
		t.Fatalf("mapping failures = %#v", report.MappingFailures)
	}
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if strings.Contains(string(body), "payload") || strings.Contains(string(body), "manual triage") {
		t.Fatalf("import report leaked raw payload or internal triage details: %s", body)
	}
}

func TestUploadVEXCanDeferDocumentParserSideEffectsToWorker(t *testing.T) {
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
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	scan, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{
		"scanner":"grype",
		"target_ref":"pkg:oci/payments-api",
		"release_id":"`+release.ID+`",
		"findings":[{"vulnerability":"CVE-2026-0002","component":"pkg:apk/openssl@3.1.0","severity":"critical","state":"open"}]
	}`))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	ledger.mu.Lock()
	ledger.scans[scan.ID] = scan
	ledger.mu.Unlock()
	outbox.jobs = nil

	vex, err := ledger.UploadVEX(ctx, actor, release.ID, artifact.ID, []byte(`{
		"@context":"https://openvex.dev/ns/v0.2.0",
		"@id":"https://example.test/vex/worker",
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
	}`))
	if err != nil {
		t.Fatalf("vex: %v", err)
	}
	if vex.Author != "security@example.test" || vex.StatementCount != 1 || vex.StatusSummary["fixed"] != 1 {
		t.Fatalf("upload response should keep parsed VEX fields: %#v", vex)
	}

	state, ok, err := store.LoadState(ctx)
	if err != nil || !ok {
		t.Fatalf("load state ok=%v err=%v", ok, err)
	}
	persisted := state.VEXDocuments[vex.ID]
	if persisted.Author != "" || persisted.StatementCount != 0 || persisted.StatusSummary != nil {
		t.Fatalf("persisted vex document should wait for worker parser side effects: %#v", persisted)
	}
	importReport, err := ledger.GetVEXImportReport(ctx, actor, vex.ID)
	if err != nil {
		t.Fatalf("import report: %v", err)
	}
	if importReport.Status != "accepted" || importReport.StatementCount != 1 || importReport.DecisionsCreated != 0 || len(importReport.Warnings) == 0 {
		t.Fatalf("worker-owned import report = %#v", importReport)
	}
	decisionFound := false
	for _, decision := range state.Decisions {
		if decision.FindingID == scan.Findings[0].ID && decision.VEXDocumentID == vex.ID && decision.Status == decisionStatusFixed {
			decisionFound = true
		}
	}
	if decisionFound {
		t.Fatal("worker-owned parser mode should leave OpenVEX-derived vulnerability decisions to the worker")
	}
	if len(outbox.jobs) != 1 {
		t.Fatalf("outbox jobs = %d, want 1", len(outbox.jobs))
	}
	job := outbox.jobs[0]
	if job.Kind != "parse_vex" || job.Payload["payload_ref"] == "" || job.Payload["payload_hash"] == "" || job.Payload["parser_version"] != ParserVersionOpenVEXJSON || job.Payload["worker_create_decisions"] != true || job.Payload["import_report_id"] == "" {
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

func policyCheckByName(t *testing.T, checks []domain.PolicyCheck, name string) domain.PolicyCheck {
	t.Helper()
	for _, check := range checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("policy check %s not found in %#v", name, checks)
	return domain.PolicyCheck{}
}

func readinessQuestionByID(t *testing.T, report domain.ReleaseReadinessReport, id string) domain.ReadinessQuestion {
	t.Helper()
	for _, section := range report.Sections {
		for _, question := range section.Questions {
			if question.ID == id {
				return question
			}
		}
	}
	t.Fatalf("readiness question %s not found in %#v", id, report.Sections)
	return domain.ReadinessQuestion{}
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
