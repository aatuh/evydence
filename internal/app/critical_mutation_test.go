package app

import (
	"context"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

type focusedStoreSpy struct {
	saveCalls     int
	criticalCalls int
	releaseCalls  int
	mutations     []CriticalMutation
	releases      []ReleaseLedgerMutation
}

func (s *focusedStoreSpy) LoadState(context.Context) (PersistedState, bool, error) {
	return PersistedState{}, false, nil
}

func (s *focusedStoreSpy) SaveState(context.Context, PersistedState) error {
	s.saveCalls++
	return nil
}

func (s *focusedStoreSpy) ApplyCriticalMutation(_ context.Context, mutation CriticalMutation) error {
	s.criticalCalls++
	s.mutations = append(s.mutations, mutation)
	return nil
}

func (s *focusedStoreSpy) ApplyReleaseLedgerMutation(_ context.Context, mutation ReleaseLedgerMutation) error {
	s.releaseCalls++
	s.releases = append(s.releases, mutation)
	return nil
}

func (s *focusedStoreSpy) reset() {
	s.saveCalls = 0
	s.criticalCalls = 0
	s.releaseCalls = 0
	s.mutations = nil
	s.releases = nil
}

func TestCriticalMutationStoreAvoidsAggregateSaveForMigratedFlows(t *testing.T) {
	ctx := context.Background()
	store := &focusedStoreSpy{}
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, Store: store})

	_, key, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if store.saveCalls != 0 || store.criticalCalls != 1 {
		t.Fatalf("bootstrap save=%d critical=%d", store.saveCalls, store.criticalCalls)
	}
	first := store.mutations[0]
	if len(first.APIKeys) != 1 || first.APIKeys[0].Hash != "" || first.APIKeyHashes[key.ID] == "" {
		t.Fatalf("api key mutation leaked or missed hash: %#v hashes=%#v", first.APIKeys, first.APIKeyHashes)
	}

	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if store.saveCalls != 0 || store.criticalCalls != 2 {
		t.Fatalf("authenticate save=%d critical=%d", store.saveCalls, store.criticalCalls)
	}

	store.reset()
	if _, _, err := ledger.CreateAPIKey(ctx, actor, "reader", []string{ScopeProductRead}, nil); err != nil {
		t.Fatalf("create api key: %v", err)
	}
	if store.saveCalls != 0 || store.criticalCalls != 1 {
		t.Fatalf("create api key save=%d critical=%d", store.saveCalls, store.criticalCalls)
	}

	store.reset()
	status, response, err := ledger.WithIdempotency(ctx, actor, "POST", "/v1/products", "idem-key", []byte(`{"name":"x"}`), func() (int, any, error) {
		return 201, map[string]any{"ok": true}, nil
	})
	if err != nil || status != 201 || response == nil {
		t.Fatalf("idempotency status=%d response=%#v err=%v", status, response, err)
	}
	if store.saveCalls != 0 || store.criticalCalls != 1 || len(store.mutations[0].Idempotency) != 1 {
		t.Fatalf("idempotency save=%d critical=%d mutation=%#v", store.saveCalls, store.criticalCalls, store.mutations)
	}
}

func TestCriticalMutationStoreCoversBundleVerificationAndDecision(t *testing.T) {
	ctx := context.Background()
	store := &focusedStoreSpy{}
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, Store: store})
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	_ = artifact

	store.reset()
	bundle, err := ledger.CreateReleaseBundle(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if store.saveCalls != 0 || store.criticalCalls != 1 {
		t.Fatalf("bundle save=%d critical=%d", store.saveCalls, store.criticalCalls)
	}
	bundleMutation := store.mutations[0]
	if len(bundleMutation.ReleaseBundles) == 0 || len(bundleMutation.Signatures) == 0 || len(bundleMutation.AuditChainEntries) == 0 || len(bundleMutation.OutboxJobs) != 1 {
		t.Fatalf("bundle mutation incomplete: %#v", bundleMutation)
	}

	store.reset()
	if _, err := ledger.VerifySubject(ctx, actor, "release_bundle", bundle.ID); err != nil {
		t.Fatalf("verify bundle: %v", err)
	}
	if store.saveCalls != 0 || store.criticalCalls != 1 || len(store.mutations[0].VerificationResults) == 0 || len(store.mutations[0].OutboxJobs) != 1 {
		t.Fatalf("verify mutation incomplete save=%d critical=%d mutation=%#v", store.saveCalls, store.criticalCalls, store.mutations)
	}

	scan := domain.VulnerabilityScan{ID: "scan_test", TenantID: actor.TenantID, ReleaseID: release.ID, Findings: []domain.VulnerabilityFinding{{ID: "finding_test", Vulnerability: "CVE-0000-0001", Severity: "critical", Component: "lib"}}}
	ledger.scans[scan.ID] = scan
	store.reset()
	if _, err := ledger.CreateVulnerabilityDecision(ctx, actor, "finding_test", CreateVulnerabilityDecisionInput{Status: decisionStatusNotAffected, Justification: "component is not present"}); err != nil {
		t.Fatalf("decision: %v", err)
	}
	if store.saveCalls != 0 || store.criticalCalls != 1 || len(store.mutations[0].VulnerabilityDecisions) == 0 {
		t.Fatalf("decision mutation incomplete save=%d critical=%d mutation=%#v", store.saveCalls, store.criticalCalls, store.mutations)
	}
}

func TestCriticalMutationStoreCoversSSOAndPortalSecrets(t *testing.T) {
	ctx := context.Background()
	store := &focusedStoreSpy{}
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, Store: store})
	actor := domain.Actor{TenantID: "ten_test", KeyID: "key_test", Scopes: []string{"*"}}
	ledger.tenants[actor.TenantID] = domain.Tenant{ID: actor.TenantID, Name: "Tenant", CreatedAt: fixedNow()}
	ledger.users["user_test"] = domain.HumanUser{
		ID: "user_test", TenantID: actor.TenantID, OrganizationID: "org_test",
		Email: "user@example.test", Status: "active", SchemaVersion: domain.HumanUserSchemaVersion,
		CreatedAt: fixedNow(),
	}
	ledger.ssoProviders["sso_test"] = domain.SSOProvider{
		ID: "sso_test", TenantID: actor.TenantID, Name: "OIDC", Type: "oidc",
		Issuer: "https://idp.example.test", ClientID: "client", Status: "active",
		SchemaVersion: domain.SSOProviderSchemaVersion, CreatedAt: fixedNow(),
	}
	ledger.customerPackages["pkg_test"] = domain.CustomerSecurityPackage{
		ID: "pkg_test", TenantID: actor.TenantID, Title: "Customer package",
		ManifestHash: "sha256:test", SchemaVersion: domain.CustomerPackageSchemaVersion,
		CreatedAt: fixedNow(),
	}

	store.reset()
	session, secret, err := ledger.CreateSSOSession(ctx, actor, CreateSSOSessionInput{
		UserID: "user_test", ProviderID: "sso_test", ExpiresAt: fixedNow().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create sso session: %v", err)
	}
	if secret == "" || session.Hash != "" {
		t.Fatalf("sso session leaked hash or missed secret: session=%#v secret=%q", session, secret)
	}
	if store.saveCalls != 0 || store.criticalCalls != 1 || len(store.mutations[0].SSOSessions) == 0 || store.mutations[0].SSOSessionHashes[session.ID] == "" {
		t.Fatalf("sso mutation incomplete save=%d critical=%d mutation=%#v", store.saveCalls, store.criticalCalls, store.mutations)
	}
	if store.mutations[0].SSOSessions[0].Hash != "" {
		t.Fatalf("sso mutation exposed hash on resource: %#v", store.mutations[0].SSOSessions[0])
	}

	store.reset()
	access, portalSecret, err := ledger.CreateCustomerPortalAccess(ctx, actor, CreateCustomerPortalAccessInput{
		PackageID: "pkg_test", CustomerName: "Customer", ExpiresAt: fixedNow().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create portal access: %v", err)
	}
	if portalSecret == "" || access.Hash != "" {
		t.Fatalf("portal access leaked hash or missed secret: access=%#v secret=%q", access, portalSecret)
	}
	if store.saveCalls != 0 || store.criticalCalls != 1 || len(store.mutations[0].CustomerPortalAccess) == 0 || store.mutations[0].CustomerPortalHashes[access.ID] == "" {
		t.Fatalf("portal mutation incomplete save=%d critical=%d mutation=%#v", store.saveCalls, store.criticalCalls, store.mutations)
	}
	if store.mutations[0].CustomerPortalAccess[0].Hash != "" {
		t.Fatalf("portal mutation exposed hash on resource: %#v", store.mutations[0].CustomerPortalAccess[0])
	}
}

func TestReleaseLedgerMutationStoreAvoidsAggregateSaveForCoreFlows(t *testing.T) {
	ctx := context.Background()
	store := &focusedStoreSpy{}
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, Store: store})
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	store.reset()
	product, err := ledger.CreateProduct(ctx, actor, "Payments API", "payments-core")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	if store.saveCalls != 0 || store.releaseCalls != 1 || len(store.releases[0].Products) == 0 || len(store.releases[0].AuditChainEntries) == 0 {
		t.Fatalf("product mutation save=%d release=%d mutation=%#v", store.saveCalls, store.releaseCalls, store.releases)
	}

	store.reset()
	project, err := ledger.CreateProject(ctx, actor, product.ID, "API")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	if _, err := ledger.FreezeRelease(ctx, actor, release.ID); err != nil {
		t.Fatalf("freeze release: %v", err)
	}
	if _, err := ledger.ApproveRelease(ctx, actor, release.ID); err != nil {
		t.Fatalf("approve release: %v", err)
	}
	if store.saveCalls != 0 || store.releaseCalls != 4 {
		t.Fatalf("project/release save=%d release=%d mutations=%#v", store.saveCalls, store.releaseCalls, store.releases)
	}
	lastReleaseMutation := store.releases[len(store.releases)-1]
	if len(lastReleaseMutation.Releases) == 0 || len(lastReleaseMutation.AuditChainEntries) == 0 {
		t.Fatalf("release mutation incomplete: %#v", lastReleaseMutation)
	}

	store.reset()
	artifact, err := ledger.RegisterArtifact(ctx, actor, "api.tar.gz", "application/gzip", sampleDigest("artifact"), 42)
	if err != nil {
		t.Fatalf("register artifact: %v", err)
	}
	item, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{
		ProductID:   product.ID,
		ProjectID:   project.ID,
		ReleaseID:   release.ID,
		Type:        "build",
		Title:       "Build evidence",
		PayloadHash: sampleDigest("build"),
		SubjectRefs: []domain.SubjectRef{{Type: "artifact", ID: artifact.ID}},
	})
	if err != nil {
		t.Fatalf("create evidence: %v", err)
	}
	if _, err := ledger.RecordEvidenceLifecycleEvent(ctx, actor, item.ID, RecordEvidenceLifecycleInput{Action: lifecycleAmendment, Reason: "corrected metadata"}); err != nil {
		t.Fatalf("record lifecycle: %v", err)
	}
	if store.saveCalls != 0 || store.releaseCalls != 3 {
		t.Fatalf("artifact/evidence save=%d release=%d mutations=%#v", store.saveCalls, store.releaseCalls, store.releases)
	}
	last := store.releases[len(store.releases)-1]
	if len(last.Evidence) == 0 || len(last.EvidenceLifecycle) == 0 || len(last.AuditChainEntries) == 0 {
		t.Fatalf("evidence lifecycle mutation incomplete: %#v", last)
	}
}

func TestReleaseLedgerMutationStoreCoversParserMetadataAndOutbox(t *testing.T) {
	ctx := context.Background()
	store := &focusedStoreSpy{}
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, Store: store, WorkerOwnedParserSideEffects: true})
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)

	store.reset()
	if _, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"lib","version":"1.0.0"}]}`)); err != nil {
		t.Fatalf("upload sbom: %v", err)
	}
	if store.saveCalls != 0 || store.releaseCalls == 0 || !releaseMutationsContainSBOMAndOutbox(store.releases, "parse_sbom") {
		t.Fatalf("sbom release mutations save=%d release=%d mutations=%#v", store.saveCalls, store.releaseCalls, store.releases)
	}

	store.reset()
	if _, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{"scanner":"generic","target_ref":"api","release_id":"`+release.ID+`","findings":[{"vulnerability":"CVE-0000-0001","component":"lib","severity":"critical"}]}`)); err != nil {
		t.Fatalf("upload scan: %v", err)
	}
	if store.saveCalls != 0 || store.releaseCalls == 0 || !releaseMutationsContainScanAndOutbox(store.releases, "parse_vulnerability_scan") {
		t.Fatalf("scan release mutations save=%d release=%d mutations=%#v", store.saveCalls, store.releaseCalls, store.releases)
	}

	store.reset()
	rawOpenAPI := []byte(`{"openapi":"3.1.0","info":{"title":"API","version":"1.0.0"},"paths":{"/health":{"get":{"responses":{"200":{"description":"ok"}}}}}}`)
	if _, err := ledger.UploadOpenAPIContract(ctx, actor, release.ProductID, release.ID, "1.0.0", rawOpenAPI); err != nil {
		t.Fatalf("upload openapi: %v", err)
	}
	if store.saveCalls != 0 || store.releaseCalls == 0 || !releaseMutationsContainContractAndOutbox(store.releases, "parse_openapi_contract") {
		t.Fatalf("openapi release mutations save=%d release=%d mutations=%#v", store.saveCalls, store.releaseCalls, store.releases)
	}

	store.reset()
	rawVEX := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex","author":"security","timestamp":"2026-01-01T00:00:00Z","statements":[{"vulnerability":{"name":"CVE-0000-0001"},"products":[{"@id":"lib"}],"status":"not_affected","justification":"component_not_present","impact_statement":"not shipped"}]}`)
	if _, err := ledger.UploadVEX(ctx, actor, release.ID, artifact.ID, rawVEX); err != nil {
		t.Fatalf("upload vex: %v", err)
	}
	if store.saveCalls != 0 || store.releaseCalls == 0 || !releaseMutationsContainVEXAndOutbox(store.releases, "parse_vex") {
		t.Fatalf("vex release mutations save=%d release=%d mutations=%#v", store.saveCalls, store.releaseCalls, store.releases)
	}
}

func TestCriticalMutationFallsBackToAggregateSave(t *testing.T) {
	ctx := context.Background()
	store := &focusedFallbackStore{}
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, Store: store})
	if _, _, _, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"}); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if store.saveCalls != 1 {
		t.Fatalf("fallback save calls = %d", store.saveCalls)
	}
}

func TestReleaseLedgerMutationFallsBackToAggregateSave(t *testing.T) {
	ctx := context.Background()
	store := &focusedFallbackStore{}
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, Store: store})
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	store.saveCalls = 0
	if _, err := ledger.CreateProduct(ctx, actor, "Payments API", "payments-fallback"); err != nil {
		t.Fatalf("create product: %v", err)
	}
	if store.saveCalls != 1 {
		t.Fatalf("release fallback save calls = %d", store.saveCalls)
	}
}

func releaseMutationsContainSBOMAndOutbox(mutations []ReleaseLedgerMutation, kind string) bool {
	for _, mutation := range mutations {
		if len(mutation.SBOMs) > 0 && releaseMutationHasOutbox(mutation, kind) {
			return true
		}
	}
	return false
}

func releaseMutationsContainScanAndOutbox(mutations []ReleaseLedgerMutation, kind string) bool {
	for _, mutation := range mutations {
		if len(mutation.Scans) > 0 && releaseMutationHasOutbox(mutation, kind) {
			return true
		}
	}
	return false
}

func releaseMutationsContainContractAndOutbox(mutations []ReleaseLedgerMutation, kind string) bool {
	for _, mutation := range mutations {
		if len(mutation.Contracts) > 0 && releaseMutationHasOutbox(mutation, kind) {
			return true
		}
	}
	return false
}

func releaseMutationsContainVEXAndOutbox(mutations []ReleaseLedgerMutation, kind string) bool {
	for _, mutation := range mutations {
		if len(mutation.VEXDocuments) > 0 && releaseMutationHasOutbox(mutation, kind) {
			return true
		}
	}
	return false
}

func releaseMutationHasOutbox(mutation ReleaseLedgerMutation, kind string) bool {
	for _, job := range mutation.OutboxJobs {
		if job.Kind == kind {
			return true
		}
	}
	return false
}

type focusedFallbackStore struct {
	saveCalls int
}

func (s *focusedFallbackStore) LoadState(context.Context) (PersistedState, bool, error) {
	return PersistedState{}, false, nil
}

func (s *focusedFallbackStore) SaveState(context.Context, PersistedState) error {
	s.saveCalls++
	return nil
}

type fullRelationalStoreSpy struct {
	saveCalls       int
	relationalCalls int
	criticalCalls   int
	releaseCalls    int
	states          []PersistedState
}

func (s *fullRelationalStoreSpy) LoadState(context.Context) (PersistedState, bool, error) {
	return PersistedState{}, false, nil
}

func (s *fullRelationalStoreSpy) SaveState(context.Context, PersistedState) error {
	s.saveCalls++
	return nil
}

func (s *fullRelationalStoreSpy) SaveRelationalState(_ context.Context, state PersistedState) error {
	s.relationalCalls++
	s.states = append(s.states, state)
	return nil
}

func (s *fullRelationalStoreSpy) ApplyCriticalMutation(context.Context, CriticalMutation) error {
	s.criticalCalls++
	return nil
}

func (s *fullRelationalStoreSpy) ApplyReleaseLedgerMutation(context.Context, ReleaseLedgerMutation) error {
	s.releaseCalls++
	return nil
}

func (s *fullRelationalStoreSpy) reset() {
	s.saveCalls = 0
	s.relationalCalls = 0
	s.criticalCalls = 0
	s.releaseCalls = 0
	s.states = nil
}

func TestRelationalStateStoreAvoidsAggregateSaveForRemainingFamilies(t *testing.T) {
	ctx := context.Background()
	store := &fullRelationalStoreSpy{}
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, Store: store})
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	store.reset()
	framework, err := ledger.CreateControlFramework(ctx, actor, CreateControlFrameworkInput{Name: "CRA Readiness", Slug: "cra-readiness", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("create control framework: %v", err)
	}
	if store.saveCalls != 0 || store.relationalCalls != 1 || store.criticalCalls != 0 || store.releaseCalls != 0 {
		t.Fatalf("framework persistence save=%d relational=%d critical=%d release=%d", store.saveCalls, store.relationalCalls, store.criticalCalls, store.releaseCalls)
	}
	if got := store.states[0].ControlFrameworks[framework.ID]; got.ID != framework.ID || got.TenantID != actor.TenantID {
		t.Fatalf("relational state missed framework: %#v", got)
	}

	product, err := ledger.CreateProduct(ctx, actor, "Payments", "payments-relational-state")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	store.reset()
	incident, err := ledger.CreateIncident(ctx, actor, CreateIncidentInput{ProductID: product.ID, ReleaseID: release.ID, Title: "Incident", Severity: "high"})
	if err != nil {
		t.Fatalf("create incident: %v", err)
	}
	if store.saveCalls != 0 || store.relationalCalls != 1 {
		t.Fatalf("incident persistence save=%d relational=%d", store.saveCalls, store.relationalCalls)
	}
	if got := store.states[0].Incidents[incident.ID]; got.ID != incident.ID || got.TenantID != actor.TenantID {
		t.Fatalf("relational state missed incident: %#v", got)
	}
}
