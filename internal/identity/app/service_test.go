package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var errIdentityCommit = errors.New("commit failed")

func TestPrepareAndCommitTenantBootstrapOwnsOnlyIdentityState(t *testing.T) {
	fixture := newIdentityServiceFixture(t)

	prepared, err := fixture.service.PrepareTenantBootstrap(context.Background(), BootstrapTenantInput{
		TenantName: " Design Partner ", APIKeyName: " local admin ",
	})
	if err != nil {
		t.Fatalf("PrepareTenantBootstrap: %v", err)
	}
	if len(fixture.transactions.state.tenants) != 0 || len(fixture.transactions.state.apiKeys) != 0 || len(fixture.transactions.state.audit) != 0 {
		t.Fatalf("preparation published state=%#v", fixture.transactions.state)
	}
	err = fixture.transactions.Execute(context.Background(), func(ctx context.Context, tx Transaction) error {
		return fixture.service.CommitTenantBootstrap(ctx, tx, prepared)
	})
	if err != nil {
		t.Fatalf("CommitTenantBootstrap: %v", err)
	}
	tenant, key, secret := prepared.PublicResult()
	if tenant.ID != "ten_1" || tenant.Name != "Design Partner" || key.ID != "key_1" || key.Name != "local admin" {
		t.Fatalf("tenant=%#v key=%#v", tenant, key)
	}
	if secret != "evy_secret" || key.Hash != "" || len(key.Scopes) != 1 || key.Scopes[0] != "*" {
		t.Fatalf("public key=%#v secret=%q", key, secret)
	}
	storedTenant, tenantCommitted := fixture.transactions.state.tenants[tenant.ID]
	storedKey, keyCommitted := fixture.transactions.state.apiKeys[key.ID]
	if !tenantCommitted || !keyCommitted || storedTenant.Name != tenant.Name || storedKey.Hash != "stored-hash" {
		t.Fatalf("committed tenant=%#v key=%#v state=%#v", storedTenant, storedKey, fixture.transactions.state)
	}
	if fixture.transactions.commits != 1 {
		t.Fatalf("commits=%d", fixture.transactions.commits)
	}
	if len(fixture.transactions.state.audit) != 1 {
		t.Fatalf("audit=%#v", fixture.transactions.state.audit)
	}
	audit := fixture.transactions.state.audit[0]
	if audit.EntryType != "tenant.created" || audit.SubjectType != "tenant" || audit.SubjectID != tenant.ID || audit.ActorType != "system" || audit.ActorID != "bootstrap" {
		t.Fatalf("audit=%#v", audit)
	}
}

func TestCommitTenantBootstrapFailureRollsBackIdentity(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	prepared, err := fixture.service.PrepareTenantBootstrap(context.Background(), BootstrapTenantInput{
		TenantName: "Tenant", APIKeyName: "admin", Scopes: []string{"*"},
	})
	if err != nil {
		t.Fatalf("PrepareTenantBootstrap: %v", err)
	}
	fixture.transactions.err = errIdentityCommit
	err = fixture.transactions.Execute(context.Background(), func(ctx context.Context, tx Transaction) error {
		return fixture.service.CommitTenantBootstrap(ctx, tx, prepared)
	})
	if !errors.Is(err, errIdentityCommit) {
		t.Fatalf("commit error=%v", err)
	}
	if len(fixture.transactions.state.tenants) != 0 || len(fixture.transactions.state.apiKeys) != 0 || len(fixture.transactions.state.audit) != 0 {
		t.Fatalf("failed bootstrap published state=%#v", fixture.transactions.state)
	}
	if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 {
		t.Fatalf("commits=%d rollbacks=%d", fixture.transactions.commits, fixture.transactions.rollbacks)
	}
}

func TestCreateAPIKeyCommitsSecretHashAndAuditBeforeReturningSecret(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	key, secret, err := fixture.service.CreateAPIKey(context.Background(), fixture.actor, CreateAPIKeyInput{Name: " automation ", Scopes: []string{"evidence:read"}})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if secret != "evy_secret" || key.Hash != "" || key.Name != "automation" || key.ID != "key_1" {
		t.Fatalf("key=%#v secret=%q", key, secret)
	}
	stored := fixture.transactions.state.apiKeys[key.ID]
	if stored.Hash != "stored-hash" || len(fixture.transactions.state.audit) != 1 || fixture.transactions.commits != 1 {
		t.Fatalf("stored=%#v state=%#v", stored, fixture.transactions.state)
	}
	if fixture.grants.calls != 1 || fixture.authorizer.calls != 1 {
		t.Fatalf("grant calls=%d authorization calls=%d", fixture.grants.calls, fixture.authorizer.calls)
	}
	if request := fixture.authorizer.requests[0]; request.Scope != ScopeAdmin || !request.ScopeOnly || !request.TenantWide {
		t.Fatalf("authorization request = %#v", request)
	}
}

func TestCreateAPIKeyAttributesHumanSessionAuditToUser(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	fixture.actor.KeyID = ""
	fixture.actor.UserID = "usr_1"
	fixture.actor.SessionID = "sess_1"

	if _, _, err := fixture.service.CreateAPIKey(context.Background(), fixture.actor, CreateAPIKeyInput{Name: "automation", Scopes: []string{"evidence:read"}}); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if len(fixture.transactions.state.audit) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(fixture.transactions.state.audit))
	}
	event := fixture.transactions.state.audit[0]
	if event.ActorType != "human_user" || event.ActorID != "usr_1" {
		t.Fatalf("audit actor = %s/%s, want human_user/usr_1", event.ActorType, event.ActorID)
	}
}

func TestCreateAPIKeyDoesNotReturnSecretWhenTransactionFails(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	fixture.transactions.err = errIdentityCommit
	key, secret, err := fixture.service.CreateAPIKey(context.Background(), fixture.actor, CreateAPIKeyInput{Name: "automation", Scopes: []string{"evidence:read"}})
	if !errors.Is(err, errIdentityCommit) || key.ID != "" || secret != "" {
		t.Fatalf("key=%#v secret=%q err=%v", key, secret, err)
	}
}

func TestCreateAPIKeyPreservesNormalizedScopeCompatibility(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	key, _, err := fixture.service.CreateAPIKey(context.Background(), fixture.actor, CreateAPIKeyInput{Name: "automation", Scopes: []string{" evidence:read ", " "}})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	stored := fixture.transactions.state.apiKeys[key.ID]
	if len(stored.Scopes) != 2 || stored.Scopes[0] != "" || stored.Scopes[1] != "evidence:read" {
		t.Fatalf("stored scopes = %#v", stored.Scopes)
	}
}

func TestAuthenticateAPIKeyUpdatesActivityInOneTransaction(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	fixture.reader.apiKeys = []identitydomain.APIKey{{ID: "key_auth", TenantID: "ten_1", Name: "collector", Prefix: "evy_secret", Hash: "stored-hash", Scopes: []string{"evidence:write"}, CreatedAt: fixture.now}}
	fixture.reader.collector = CollectorBinding{ID: "col_1", TenantID: "ten_1", APIKeyID: "key_auth"}
	fixture.transactions.state.apiKeys["key_auth"] = fixture.reader.apiKeys[0]

	actor, err := fixture.service.Authenticate(context.Background(), "Bearer evy_secret")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if actor.KeyID != "key_auth" || actor.CollectorID != "col_1" || actor.TenantID != "ten_1" {
		t.Fatalf("actor = %#v", actor)
	}
	if fixture.transactions.state.apiKeys["key_auth"].LastUsedAt == nil || len(fixture.transactions.state.collectorActivity) != 1 {
		t.Fatalf("state = %#v", fixture.transactions.state)
	}
}

func TestAuthenticateDoesNotRegressNewerAPIKeyActivity(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	newer := fixture.now.Add(time.Minute)
	key := identitydomain.APIKey{
		ID: "key_auth", TenantID: "ten_1", Name: "automation", Prefix: "evy_secret", Hash: "stored-hash",
		Scopes: []string{"evidence:read"}, LastUsedAt: &newer, CreatedAt: fixture.now,
	}
	fixture.reader.apiKeys = []identitydomain.APIKey{key}
	fixture.transactions.state.apiKeys[key.ID] = key

	if _, err := fixture.service.Authenticate(context.Background(), "evy_secret"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got := fixture.transactions.state.apiKeys[key.ID].LastUsedAt; got == nil || !got.Equal(newer) {
		t.Fatalf("last used=%v, want monotonic %s", got, newer)
	}
}

func TestAuthenticateMapsActivityFailureToUnauthorized(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	fixture.reader.apiKeys = []identitydomain.APIKey{{ID: "key_auth", TenantID: "ten_1", Prefix: "evy_secret", Hash: "stored-hash", Scopes: []string{"evidence:read"}, CreatedAt: fixture.now}}
	fixture.transactions.state.apiKeys["key_auth"] = fixture.reader.apiKeys[0]
	fixture.transactions.err = errors.New("database detail")
	if _, err := fixture.service.Authenticate(context.Background(), "evy_secret"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Authenticate error = %v", err)
	}
}

func TestAuthenticateRejectsRevokedExpiredAndCrossTenantSessions(t *testing.T) {
	tests := []struct {
		name     string
		session  identitydomain.SSOSession
		identity SessionIdentity
	}{
		{
			name: "revoked",
			session: func() identitydomain.SSOSession {
				revokedAt := time.Date(2026, 8, 22, 11, 0, 0, 0, time.UTC)
				return identitydomain.SSOSession{ID: "sess_1", TenantID: "ten_1", UserID: "usr_1", Prefix: "evy_secret", Hash: "stored-hash", ExpiresAt: time.Date(2026, 8, 22, 13, 0, 0, 0, time.UTC), RevokedAt: &revokedAt}
			}(),
			identity: activeSessionIdentity("ten_1"),
		},
		{
			name:     "expired",
			session:  identitydomain.SSOSession{ID: "sess_1", TenantID: "ten_1", UserID: "usr_1", Prefix: "evy_secret", Hash: "stored-hash", ExpiresAt: time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)},
			identity: activeSessionIdentity("ten_1"),
		},
		{
			name:     "cross tenant user",
			session:  identitydomain.SSOSession{ID: "sess_1", TenantID: "ten_1", UserID: "usr_1", Prefix: "evy_secret", Hash: "stored-hash", ExpiresAt: time.Date(2026, 8, 22, 13, 0, 0, 0, time.UTC)},
			identity: activeSessionIdentity("ten_2"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newIdentityServiceFixture(t)
			fixture.reader.sessions = []identitydomain.SSOSession{test.session}
			fixture.reader.sessionIdentity = test.identity
			if _, err := fixture.service.Authenticate(context.Background(), "evy_secret"); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("Authenticate error = %v, want unauthorized", err)
			}
			if fixture.transactions.commits != 0 {
				t.Fatalf("committed transactions = %d", fixture.transactions.commits)
			}
		})
	}
}

func TestAuthenticateRejectsSessionWithoutAuthorizationGrants(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	fixture.reader.sessions = []identitydomain.SSOSession{{ID: "sess_1", TenantID: "ten_1", UserID: "usr_1", Prefix: "evy_secret", Hash: "stored-hash", ExpiresAt: fixture.now.Add(time.Hour)}}
	fixture.reader.sessionIdentity = SessionIdentity{User: identitydomain.HumanUser{ID: "usr_1", TenantID: "ten_1", Status: "active"}}
	if _, err := fixture.service.Authenticate(context.Background(), "evy_secret"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("Authenticate error = %v, want forbidden", err)
	}
}

func TestAuthenticatePropagatesCancellationFromSessionIdentityLookup(t *testing.T) {
	fixture := newIdentityServiceFixture(t)
	fixture.reader.sessions = []identitydomain.SSOSession{{
		ID: "sess_1", TenantID: "ten_1", UserID: "usr_1", Prefix: "evy_secret", Hash: "stored-hash", ExpiresAt: fixture.now.Add(time.Hour),
	}}
	ctx, cancel := context.WithCancel(context.Background())
	fixture.reader.sessionIdentityHook = cancel
	fixture.reader.sessionIdentityErr = context.Canceled

	if _, err := fixture.service.Authenticate(ctx, "evy_secret"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Authenticate error = %v, want cancellation", err)
	}
}

func activeSessionIdentity(tenantID string) SessionIdentity {
	return SessionIdentity{
		User:   identitydomain.HumanUser{ID: "usr_1", TenantID: tenantID, Status: "active"},
		Grants: []identitydomain.ResourceGrant{{Role: "reader", Scopes: []string{"evidence:read"}}},
	}
}

type identityServiceFixture struct {
	service            *Service
	actor              identitydomain.Actor
	now                time.Time
	reader             *fakeIdentityReader
	authorizer         *fakeIdentityAuthorizer
	grants             *fakeGrantPolicy
	sessionCredentials *fakeSessionCredentials
	targets            *fakeGrantTargetResolver
	sessionGrants      *fakeSessionGrantPolicy
	trust              *fakeTrustMaterial
	hasher             *fakeCanonicalHasher
	discovery          *fakeOIDCDiscovery
	verifier           *fakeCredentialVerifier
	verificationPolicy fakeProviderVerificationPolicy
	transactions       *fakeIdentityTransactions
}

func newIdentityServiceFixture(t *testing.T) *identityServiceFixture {
	t.Helper()
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	reader := &fakeIdentityReader{}
	authorizer := &fakeIdentityAuthorizer{}
	grants := &fakeGrantPolicy{}
	sessionCredentials := &fakeSessionCredentials{}
	targets := &fakeGrantTargetResolver{}
	sessionGrants := &fakeSessionGrantPolicy{}
	trust := &fakeTrustMaterial{}
	hasher := &fakeCanonicalHasher{hash: "sha256:trust"}
	discovery := &fakeOIDCDiscovery{}
	verifier := &fakeCredentialVerifier{}
	verificationPolicy := fakeProviderVerificationPolicy{}
	transactions := &fakeIdentityTransactions{state: newFakeIdentityState()}
	service, err := NewService(Config{
		Reader: reader, Transactions: transactions, Authorizer: authorizer, GrantPolicy: grants,
		Credentials: fakeCredentials{}, SessionCredentials: sessionCredentials, GrantTargets: targets,
		SessionGrants: sessionGrants, TrustMaterial: trust, CanonicalHasher: hasher,
		OIDCDiscovery: discovery, CredentialVerifier: verifier, VerificationPolicy: verificationPolicy,
		Clock: application.ClockFunc(func() time.Time { return now }),
		IDs:   application.IDGeneratorFunc(func(prefix string) string { return prefix + "_1" }),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return &identityServiceFixture{
		service: service, actor: identitydomain.Actor{TenantID: "ten_1", KeyID: "admin_1", Scopes: []string{"*"}},
		now: now, reader: reader, authorizer: authorizer, grants: grants, sessionCredentials: sessionCredentials, targets: targets,
		sessionGrants: sessionGrants, trust: trust, hasher: hasher, discovery: discovery,
		verifier: verifier, verificationPolicy: verificationPolicy, transactions: transactions,
	}
}

type fakeIdentityAuthorizer struct {
	calls    int
	err      error
	requests []application.AuthorizationRequest
}

func (f *fakeIdentityAuthorizer) Authorize(_ context.Context, _ identitydomain.Actor, request application.AuthorizationRequest) error {
	f.calls++
	f.requests = append(f.requests, request)
	return f.err
}

type fakeGrantPolicy struct {
	calls int
	err   error
}

func (f *fakeGrantPolicy) AuthorizeScopes(identitydomain.Actor, []string) error {
	f.calls++
	return f.err
}

type fakeCredentials struct{}

func (fakeCredentials) Generate() (Credential, error) {
	return Credential{Secret: "evy_secret", Prefix: "evy_secret", Hash: "stored-hash"}, nil
}
func (fakeCredentials) Prefix(secret string) string         { return secret }
func (fakeCredentials) Hash(string) string                  { return "stored-hash" }
func (fakeCredentials) Equal(stored, candidate string) bool { return stored == candidate }

type fakeSessionCredentials struct {
	err error
}

func (f *fakeSessionCredentials) GenerateSession() (Credential, error) {
	if f.err != nil {
		return Credential{}, f.err
	}
	return Credential{Secret: "evysso_secret", Prefix: "evysso_secret", Hash: "session-hash"}, nil
}

type fakeGrantTargetResolver struct {
	subjectCalls  int
	resourceCalls int
	subjectErr    error
	resourceErr   error
}

func (f *fakeGrantTargetResolver) ValidateSubject(context.Context, string, string, string) error {
	f.subjectCalls++
	return f.subjectErr
}

func (f *fakeGrantTargetResolver) ValidateResource(context.Context, string, string, string) error {
	f.resourceCalls++
	return f.resourceErr
}

type fakeSessionGrantPolicy struct {
	grants []identitydomain.ResourceGrant
}

func (f *fakeSessionGrantPolicy) GrantsForProviderGroups(identitydomain.SSOProvider, []string) []identitydomain.ResourceGrant {
	return cloneGrants(f.grants)
}

type fakeTrustMaterial struct {
	jwks         map[string]any
	certificates []string
	err          error
}

func (f *fakeTrustMaterial) NormalizeJWKS(input map[string]any) (map[string]any, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.jwks != nil {
		return cloneAnyMap(f.jwks), nil
	}
	return cloneAnyMap(input), nil
}

func (f *fakeTrustMaterial) NormalizeSAMLSigningCertificates(input []string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.certificates != nil {
		return append([]string(nil), f.certificates...), nil
	}
	return append([]string(nil), input...), nil
}

type fakeCanonicalHasher struct {
	calls int
	hash  string
	err   error
}

func (f *fakeCanonicalHasher) Hash(any) (string, error) {
	f.calls++
	return f.hash, f.err
}

type fakeOIDCDiscovery struct {
	result OIDCDiscoveryResult
	err    error
}

func (f *fakeOIDCDiscovery) FetchOIDCTrustMaterial(context.Context, OIDCDiscoveryRequest) (OIDCDiscoveryResult, error) {
	return f.result, f.err
}

type fakeCredentialVerifier struct {
	result CredentialVerificationResult
	err    error
}

func (f *fakeCredentialVerifier) Verify(context.Context, CredentialVerificationRequest) (CredentialVerificationResult, error) {
	return f.result, f.err
}

type fakeProviderVerificationPolicy struct{}

func (fakeProviderVerificationPolicy) Assess(record identitydomain.ProviderVerification, _ identitydomain.SSOProvider, _ bool) identitydomain.ProviderVerification {
	record = cloneProviderVerification(record)
	record.Result = "passed"
	for _, check := range record.Checks {
		if check.Result == "failed" || check.Result == "error" {
			record.Result = "failed"
			break
		}
	}
	return record
}

func (fakeProviderVerificationPolicy) ReturnsFailure(result string) bool {
	return result == "failed" || result == "error"
}

type fakeIdentityReader struct {
	apiKeys             []identitydomain.APIKey
	sessions            []identitydomain.SSOSession
	collector           CollectorBinding
	sessionIdentity     SessionIdentity
	sessionIdentityErr  error
	sessionIdentityHook func()
	organizations       []identitydomain.Organization
	users               []identitydomain.HumanUser
	roleBindings        []identitydomain.RoleBinding
	providers           []identitydomain.SSOProvider
	links               []identitydomain.UserIdentityLink
	userGrants          []identitydomain.ResourceGrant
	calls               int
}

func (f *fakeIdentityReader) HasTenants(context.Context) (bool, error) { return true, nil }
func (f *fakeIdentityReader) ListAPIKeys(context.Context, string) ([]identitydomain.APIKey, error) {
	return append([]identitydomain.APIKey(nil), f.apiKeys...), nil
}
func (f *fakeIdentityReader) APIKeysByPrefix(context.Context, string) ([]identitydomain.APIKey, error) {
	return append([]identitydomain.APIKey(nil), f.apiKeys...), nil
}
func (f *fakeIdentityReader) SessionsByPrefix(context.Context, string) ([]identitydomain.SSOSession, error) {
	return append([]identitydomain.SSOSession(nil), f.sessions...), nil
}
func (f *fakeIdentityReader) CollectorByAPIKey(context.Context, string, string) (CollectorBinding, bool, error) {
	if f.collector.ID == "" {
		return CollectorBinding{}, false, nil
	}
	return f.collector, true, nil
}
func (f *fakeIdentityReader) SessionIdentity(context.Context, identitydomain.SSOSession) (SessionIdentity, error) {
	if f.sessionIdentityHook != nil {
		f.sessionIdentityHook()
	}
	if f.sessionIdentityErr != nil {
		return SessionIdentity{}, f.sessionIdentityErr
	}
	if f.sessionIdentity.User.ID == "" {
		return SessionIdentity{}, ErrNotFound
	}
	return f.sessionIdentity, nil
}

func (f *fakeIdentityReader) OrganizationBySlug(_ context.Context, _ string, slug string) (identitydomain.Organization, bool, error) {
	f.calls++
	for _, organization := range f.organizations {
		if organization.Slug == slug {
			return organization, true, nil
		}
	}
	return identitydomain.Organization{}, false, nil
}

func (f *fakeIdentityReader) Organization(_ context.Context, _ string, id string) (identitydomain.Organization, error) {
	f.calls++
	for _, organization := range f.organizations {
		if organization.ID == id {
			return organization, nil
		}
	}
	return identitydomain.Organization{}, ErrNotFound
}

func (f *fakeIdentityReader) UserByEmail(_ context.Context, _ string, email string) (identitydomain.HumanUser, bool, error) {
	f.calls++
	for _, user := range f.users {
		if user.Email == email {
			return user, true, nil
		}
	}
	return identitydomain.HumanUser{}, false, nil
}

func (f *fakeIdentityReader) User(_ context.Context, _ string, id string) (identitydomain.HumanUser, error) {
	f.calls++
	for _, user := range f.users {
		if user.ID == id {
			return user, nil
		}
	}
	return identitydomain.HumanUser{}, ErrNotFound
}

func (f *fakeIdentityReader) ListRoleBindings(context.Context, string) ([]identitydomain.RoleBinding, error) {
	f.calls++
	return append([]identitydomain.RoleBinding(nil), f.roleBindings...), nil
}

func (f *fakeIdentityReader) SSOProvider(_ context.Context, _ string, id string) (identitydomain.SSOProvider, error) {
	f.calls++
	for _, provider := range f.providers {
		if provider.ID == id {
			return cloneSSOProvider(provider), nil
		}
	}
	return identitydomain.SSOProvider{}, ErrNotFound
}

func (f *fakeIdentityReader) SSOProviderByID(_ context.Context, id string) (identitydomain.SSOProvider, error) {
	f.calls++
	for _, provider := range f.providers {
		if provider.ID == id {
			return cloneSSOProvider(provider), nil
		}
	}
	return identitydomain.SSOProvider{}, ErrNotFound
}

func (f *fakeIdentityReader) IdentityLink(_ context.Context, _ string, providerID, subject string) (identitydomain.UserIdentityLink, bool, error) {
	f.calls++
	for _, link := range f.links {
		if link.ProviderID == providerID && link.Subject == subject {
			return link, true, nil
		}
	}
	return identitydomain.UserIdentityLink{}, false, nil
}

func (f *fakeIdentityReader) SSOSession(_ context.Context, _ string, id string) (identitydomain.SSOSession, error) {
	f.calls++
	for _, session := range f.sessions {
		if session.ID == id {
			return cloneSSOSession(session), nil
		}
	}
	return identitydomain.SSOSession{}, ErrNotFound
}

func (f *fakeIdentityReader) UserGrants(context.Context, string, string) ([]identitydomain.ResourceGrant, error) {
	f.calls++
	return cloneGrants(f.userGrants), nil
}

type fakeIdentityState struct {
	tenants           map[string]identitydomain.Tenant
	apiKeys           map[string]identitydomain.APIKey
	collectorActivity []CollectorActivity
	organizations     map[string]identitydomain.Organization
	users             map[string]identitydomain.HumanUser
	roleBindings      map[string]identitydomain.RoleBinding
	providers         map[string]identitydomain.SSOProvider
	links             map[string]identitydomain.UserIdentityLink
	verifications     map[string]identitydomain.ProviderVerification
	sessions          map[string]identitydomain.SSOSession
	audit             []application.AuditEvent
}

func newFakeIdentityState() fakeIdentityState {
	return fakeIdentityState{
		tenants: map[string]identitydomain.Tenant{}, apiKeys: map[string]identitydomain.APIKey{}, organizations: map[string]identitydomain.Organization{},
		users: map[string]identitydomain.HumanUser{}, roleBindings: map[string]identitydomain.RoleBinding{},
		providers: map[string]identitydomain.SSOProvider{}, links: map[string]identitydomain.UserIdentityLink{},
		verifications: map[string]identitydomain.ProviderVerification{}, sessions: map[string]identitydomain.SSOSession{},
	}
}

func (s fakeIdentityState) clone() fakeIdentityState {
	result := newFakeIdentityState()
	result.collectorActivity = append([]CollectorActivity(nil), s.collectorActivity...)
	result.audit = append([]application.AuditEvent(nil), s.audit...)
	for key, value := range s.tenants {
		result.tenants[key] = value
	}
	for key, value := range s.apiKeys {
		result.apiKeys[key] = cloneAPIKey(value)
	}
	for key, value := range s.organizations {
		result.organizations[key] = value
	}
	for key, value := range s.users {
		result.users[key] = cloneHumanUser(value)
	}
	for key, value := range s.roleBindings {
		result.roleBindings[key] = value
	}
	for key, value := range s.providers {
		result.providers[key] = cloneSSOProvider(value)
	}
	for key, value := range s.links {
		result.links[key] = value
	}
	for key, value := range s.verifications {
		result.verifications[key] = cloneProviderVerification(value)
	}
	for key, value := range s.sessions {
		result.sessions[key] = cloneSSOSession(value)
	}
	return result
}

type fakeIdentityTransactions struct {
	state               fakeIdentityState
	err                 error
	auditErr            error
	validateExchange    func(SSOExchangeSnapshot) error
	exchangeValidations int
	commits             int
	rollbacks           int
}

func (f *fakeIdentityTransactions) Execute(ctx context.Context, command TransactionCommand) error {
	pending := f.state.clone()
	tx := &fakeIdentityTransaction{state: &pending, auditErr: f.auditErr, transactions: f}
	if err := command(ctx, tx); err != nil {
		f.rollbacks++
		return err
	}
	if f.err != nil {
		f.rollbacks++
		return f.err
	}
	f.state = pending
	f.commits++
	return nil
}

type fakeIdentityTransaction struct {
	state        *fakeIdentityState
	auditErr     error
	transactions *fakeIdentityTransactions
}

func (f *fakeIdentityTransaction) Identity() Repository {
	return fakeIdentityRepository{state: f.state, transactions: f.transactions}
}
func (f *fakeIdentityTransaction) Audit() application.AuditAppender {
	return fakeIdentityAudit{state: f.state, err: f.auditErr}
}

type fakeIdentityRepository struct {
	state        *fakeIdentityState
	transactions *fakeIdentityTransactions
}

func (f fakeIdentityRepository) InsertTenant(_ context.Context, value identitydomain.Tenant) error {
	f.state.tenants[value.ID] = value
	return nil
}

func (f fakeIdentityRepository) InsertAPIKey(_ context.Context, value identitydomain.APIKey) error {
	f.state.apiKeys[value.ID] = value
	return nil
}
func (f fakeIdentityRepository) UpdateAPIKeyActivity(_ context.Context, value identitydomain.APIKey, collector CollectorActivity) error {
	f.state.apiKeys[value.ID] = value
	if collector.ID != "" {
		f.state.collectorActivity = append(f.state.collectorActivity, collector)
	}
	return nil
}
func (f fakeIdentityRepository) ValidateActiveSession(context.Context, identitydomain.SSOSession, time.Time) error {
	return nil
}

func (f fakeIdentityRepository) InsertOrganization(_ context.Context, value identitydomain.Organization) error {
	f.state.organizations[value.ID] = value
	return nil
}

func (f fakeIdentityRepository) InsertHumanUser(_ context.Context, value identitydomain.HumanUser) error {
	f.state.users[value.ID] = cloneHumanUser(value)
	return nil
}

func (f fakeIdentityRepository) DeactivateHumanUser(_ context.Context, value identitydomain.HumanUser) error {
	f.state.users[value.ID] = cloneHumanUser(value)
	return nil
}

func (f fakeIdentityRepository) InsertRoleBinding(_ context.Context, value identitydomain.RoleBinding) error {
	f.state.roleBindings[value.ID] = value
	return nil
}

func (f fakeIdentityRepository) InsertSSOProvider(_ context.Context, value identitydomain.SSOProvider) error {
	f.state.providers[value.ID] = cloneSSOProvider(value)
	return nil
}

func (f fakeIdentityRepository) CompareAndSwapSSOProviderTrustMaterial(_ context.Context, expected, value identitydomain.SSOProvider) error {
	stored, ok := f.state.providers[expected.ID]
	if !ok || !sameSSOProviderTrustState(stored, expected) {
		return ErrConflict
	}
	f.state.providers[value.ID] = cloneSSOProvider(value)
	return nil
}

func sameSSOProviderTrustState(left, right identitydomain.SSOProvider) bool {
	return left.ID == right.ID &&
		left.TenantID == right.TenantID &&
		left.Type == right.Type &&
		left.Issuer == right.Issuer &&
		left.ClientID == right.ClientID &&
		left.Status == right.Status &&
		reflect.DeepEqual(left.JWKS, right.JWKS) &&
		reflect.DeepEqual(left.SAMLSigningCertificates, right.SAMLSigningCertificates) &&
		equalOptionalTime(left.TrustMaterialUpdatedAt, right.TrustMaterialUpdatedAt)
}

func equalOptionalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func (f fakeIdentityRepository) InsertUserIdentityLink(_ context.Context, value identitydomain.UserIdentityLink) error {
	f.state.links[value.ID] = value
	return nil
}

func (f fakeIdentityRepository) ValidateSSOExchangeState(_ context.Context, snapshot SSOExchangeSnapshot) error {
	f.transactions.exchangeValidations++
	if f.transactions.validateExchange != nil {
		return f.transactions.validateExchange(cloneSSOExchangeSnapshot(snapshot))
	}
	return nil
}

func (f fakeIdentityRepository) InsertProviderVerification(_ context.Context, value identitydomain.ProviderVerification) error {
	f.state.verifications[value.ID] = cloneProviderVerification(value)
	return nil
}

func (f fakeIdentityRepository) InsertSSOSession(_ context.Context, value identitydomain.SSOSession) error {
	f.state.sessions[value.ID] = cloneSSOSession(value)
	return nil
}

func (f fakeIdentityRepository) RevokeSSOSession(_ context.Context, value identitydomain.SSOSession) error {
	f.state.sessions[value.ID] = cloneSSOSession(value)
	return nil
}

type fakeIdentityAudit struct {
	state *fakeIdentityState
	err   error
}

func (f fakeIdentityAudit) AppendAudit(_ context.Context, value application.AuditEvent) (application.AuditReceipt, error) {
	if f.err != nil {
		return application.AuditReceipt{}, f.err
	}
	f.state.audit = append(f.state.audit, value)
	return application.AuditReceipt{ID: value.ID}, nil
}
