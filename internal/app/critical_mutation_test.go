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
	mutations     []CriticalMutation
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

func (s *focusedStoreSpy) reset() {
	s.saveCalls = 0
	s.criticalCalls = 0
	s.mutations = nil
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
