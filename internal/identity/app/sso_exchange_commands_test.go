package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var errExchangeUnit = errors.New("private exchange failure")

func TestSSOExchangeCommandsRequireOIDCAuthenticationRequestBeforeVerification(t *testing.T) {
	s, f, _, _ := exchangeCommandsForTest(t)
	input := ExchangeSSOCredentialInput{ProviderID: "provider", Subject: "subject", IDToken: "raw-id-token"}
	_, session, secret, err := s.ExchangeSSOCredential(t.Context(), input)
	if !errors.Is(err, ErrUnauthorized) || secret != "" || session.ID != "" || f.verificationsCalled != 0 || len(f.sessions)+len(f.verifications)+len(f.audits) != 0 {
		t.Fatal("unbound OIDC proof reached verification, issuance or durable effects", err)
	}
}

func TestSSOExchangeCommandsRejectOIDCNonceMismatchAndCommittedReplay(t *testing.T) {
	for _, profile := range []string{"nonce mismatch", "replay"} {
		t.Run(profile, func(t *testing.T) {
			s, f, in, _ := exchangeCommandsForTest(t)
			if profile == "nonce mismatch" {
				f.result.Nonce = "wrong-nonce"
			} else {
				if _, _, _, err := s.ExchangeSSOCredential(t.Context(), in); err != nil {
					t.Fatal(err)
				}
			}
			beforeSessions, beforeVerifications := len(f.sessions), len(f.verifications)
			_, session, secret, err := s.ExchangeSSOCredential(t.Context(), in)
			if !errors.Is(err, ErrUnauthorized) || session.ID != "" || secret != "" || len(f.sessions) != beforeSessions || len(f.verifications) != beforeVerifications {
				t.Fatal("unbound or replayed OIDC proof issued a session", err)
			}
		})
	}
}

func TestSSOExchangeCommandsRollbackProofConsumptionOnCommitFailure(t *testing.T) {
	s, f, in, _ := exchangeCommandsForTest(t)
	f.phase = "commit"
	if _, session, secret, err := s.ExchangeSSOCredential(t.Context(), in); err == nil || session.ID != "" || secret != "" || f.request.ConsumedAt != nil {
		t.Fatal("failed commit consumed proof or returned material")
	}
	f.phase = ""
	if _, session, secret, err := s.ExchangeSSOCredential(t.Context(), in); err != nil || session.ID == "" || secret == "" || f.request.ConsumedAt == nil {
		t.Fatal("rolled-back proof was not safely retryable", err)
	}
}

func TestSSOExchangeCommandsConsumeVerifiedProofEvenWhenIdentityIsDenied(t *testing.T) {
	s, f, in, _ := exchangeCommandsForTest(t)
	f.user.Status = "deactivated"
	if _, session, secret, err := s.ExchangeSSOCredential(t.Context(), in); !errors.Is(err, ErrVerificationFailed) || session.ID != "" || secret != "" || f.request.ConsumedAt == nil {
		t.Fatal("valid proof denial retained replayable authentication state", err)
	}
}

func exchangeTestString(v any) string { return fmt.Sprintf("%#v", v) }

// This fake implements only the exchange ports, not Reader or Service.
type exchangeCommandFixture struct {
	provider                                              identitydomain.SSOProvider
	link                                                  identitydomain.UserIdentityLink
	user                                                  identitydomain.HumanUser
	grants                                                []identitydomain.ResourceGrant
	result                                                CredentialVerificationResult
	credential                                            Credential
	verifications                                         []identitydomain.ProviderVerification
	sessions                                              []identitydomain.SSOSession
	audits                                                []application.AuditEvent
	snapshot                                              SSOExchangeSnapshot
	phase                                                 string
	reads, verificationsCalled, generations, transactions int
	cancel                                                context.CancelFunc
	commitHook                                            func()
	auditHook                                             func(application.AuditEvent)
	request                                               identitydomain.OIDCAuthenticationRequest
	samlBinding                                           identitydomain.SAMLProviderBinding
	samlRequest                                           identitydomain.SAMLAuthenticationRequest
	samlUses                                              map[string]bool
	verifiedRequest                                       CredentialVerificationRequest
	inTransaction                                         bool
}

func (f *exchangeCommandFixture) SSOProviderByID(_ context.Context, id string) (identitydomain.SSOProvider, error) {
	f.reads++
	if f.phase == "provider read" {
		return identitydomain.SSOProvider{}, errExchangeUnit
	}
	if id != f.provider.ID {
		return identitydomain.SSOProvider{}, ErrNotFound
	}
	if f.phase == "mismatched provider" {
		p := cloneSSOProvider(f.provider)
		p.ID = "foreign"
		return p, nil
	}
	return cloneSSOProvider(f.provider), nil
}
func (f *exchangeCommandFixture) IdentityLink(_ context.Context, tenant, provider, subject string) (identitydomain.UserIdentityLink, bool, error) {
	f.reads++
	if tenant != f.provider.TenantID || provider != f.provider.ID || subject != "subject" {
		return identitydomain.UserIdentityLink{}, false, errExchangeUnit
	}
	if f.phase == "link read" {
		return identitydomain.UserIdentityLink{}, false, errExchangeUnit
	}
	if f.link.ID == "" {
		return identitydomain.UserIdentityLink{}, false, nil
	}
	return f.link, true, nil
}
func (f *exchangeCommandFixture) User(_ context.Context, tenant, id string) (identitydomain.HumanUser, error) {
	f.reads++
	if tenant != f.provider.TenantID || id != f.link.UserID {
		return identitydomain.HumanUser{}, errExchangeUnit
	}
	if f.phase == "user read" {
		return identitydomain.HumanUser{}, errExchangeUnit
	}
	if f.user.ID == "" {
		return identitydomain.HumanUser{}, ErrNotFound
	}
	return cloneHumanUser(f.user), nil
}
func (f *exchangeCommandFixture) UserGrants(_ context.Context, tenant, id string) ([]identitydomain.ResourceGrant, error) {
	f.reads++
	if tenant != f.provider.TenantID || id != f.user.ID {
		return nil, errExchangeUnit
	}
	if f.phase == "grant read" {
		return nil, errExchangeUnit
	}
	return cloneGrants(f.grants), nil
}
func (f *exchangeCommandFixture) Verify(_ context.Context, r CredentialVerificationRequest) (CredentialVerificationResult, error) {
	f.verificationsCalled++
	f.verifiedRequest = r
	if r.Provider.ID != f.provider.ID || r.Subject != "subject" || r.Now.IsZero() || f.inTransaction {
		return CredentialVerificationResult{}, errExchangeUnit
	}
	// A verifier cannot mutate the provider snapshot used at commit.
	r.Provider.RoleMapping["security"] = "tenant_admin"
	if f.phase == "cancel verifier" {
		f.cancel()
	}
	if f.phase == "verifier" {
		return f.result, errors.New("raw-id-token private provider response")
	}
	return f.result, nil
}
func (f *exchangeCommandFixture) GenerateSession() (Credential, error) {
	f.generations++
	if f.phase == "credential" {
		return Credential{}, errExchangeUnit
	}
	return f.credential, nil
}
func (f *exchangeCommandFixture) ExecuteSSOExchange(ctx context.Context, fn func(context.Context, SSOExchangeTransaction) error) error {
	f.transactions++
	f.inTransaction = true
	defer func() { f.inTransaction = false }()
	if f.phase == "nil transaction" {
		return fn(ctx, nil)
	}
	pending := &exchangeCommandFixture{phase: f.phase, cancel: f.cancel, request: f.request}
	pending.auditHook = f.auditHook
	pending.samlBinding = cloneSAMLProviderBinding(f.samlBinding)
	pending.samlRequest = f.samlRequest
	pending.samlUses = make(map[string]bool, len(f.samlUses))
	for hash, used := range f.samlUses {
		pending.samlUses[hash] = used
	}
	if f.phase == "nil transaction context" {
		//nolint:contextcheck // Deliberately exercise a broken transaction adapter.
		return fn(nil, pending)
	}
	if err := fn(ctx, pending); err != nil {
		return err
	}
	f.snapshot = pending.snapshot
	if f.phase == "commit" {
		return errExchangeUnit
	}
	f.verifications = append(f.verifications, pending.verifications...)
	f.sessions = append(f.sessions, pending.sessions...)
	f.audits = append(f.audits, pending.audits...)
	f.request = pending.request
	f.samlRequest, f.samlUses = pending.samlRequest, pending.samlUses
	if f.commitHook != nil {
		f.commitHook()
	}
	return nil
}
func (f *exchangeCommandFixture) ReadOIDCAuthenticationRequest(_ context.Context, tenant, provider, id string) (identitydomain.OIDCAuthenticationRequest, error) {
	f.reads++
	if f.request.ID != id || f.request.TenantID != tenant || f.request.ProviderID != provider {
		return identitydomain.OIDCAuthenticationRequest{}, ErrNotFound
	}
	return f.request, nil
}
func (f *exchangeCommandFixture) ConsumeOIDCAuthenticationRequest(_ context.Context, v identitydomain.OIDCAuthenticationRequest, c application.Clock) (time.Time, error) {
	if !f.request.PendingAt(c.Now()) || f.request.ID != v.ID {
		return time.Time{}, ErrUnauthorized
	}
	at := c.Now().UTC()
	f.request.ConsumedAt = &at
	return at, nil
}
func (f *exchangeCommandFixture) ValidateSSOExchangeState(_ context.Context, v SSOExchangeSnapshot) error {
	f.snapshot = cloneSSOExchangeSnapshot(v)
	if f.phase == "stale" {
		return ErrConflict
	}
	return nil
}
func (f *exchangeCommandFixture) InsertProviderVerification(_ context.Context, v identitydomain.ProviderVerification) error {
	if f.phase == "verification write" {
		return errExchangeUnit
	}
	f.verifications = append(f.verifications, cloneProviderVerification(v))
	return nil
}
func (f *exchangeCommandFixture) InsertSSOSession(_ context.Context, v identitydomain.SSOSession) error {
	if f.phase == "session write" {
		return errExchangeUnit
	}
	f.sessions = append(f.sessions, cloneSSOSession(v))
	return nil
}
func (f *exchangeCommandFixture) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if f.phase == "verification audit" && v.EntryType == "provider_identity.verified" || f.phase == "session audit" && v.EntryType == "sso_session.created" {
		return application.AuditReceipt{}, errExchangeUnit
	}
	f.audits = append(f.audits, v)
	if f.auditHook != nil {
		f.auditHook(v)
	}
	if f.cancel != nil {
		f.cancel()
	}
	return application.AuditReceipt{ID: v.ID}, nil
}
func exchangeCommandsForTest(t *testing.T) (*SSOExchangeCommands, *exchangeCommandFixture, ExchangeSSOCredentialInput, time.Time) {
	t.Helper()
	f := &exchangeCommandFixture{
		provider: identitydomain.SSOProvider{ID: "provider", TenantID: "tenant", Type: "oidc", Status: "active", GroupsClaim: "groups", RoleMapping: map[string]string{"security": "security_engineer"}},
		link:     identitydomain.UserIdentityLink{ID: "link", TenantID: "tenant", ProviderID: "provider", UserID: "user", Subject: "subject", Verified: true},
		user:     identitydomain.HumanUser{ID: "user", TenantID: "tenant", Status: "active"},
		grants:   []identitydomain.ResourceGrant{{Role: "release_manager", Scopes: []string{"release:read"}}},
		result:   CredentialVerificationResult{Checks: []identitydomain.VerificationCheck{{Name: "signature", Result: "passed"}}, Groups: []string{"security", "raw-id-token"}},
	}
	credentials, err := NewHMACAuthenticationCredentials("fixture-pepper")
	if err != nil {
		t.Fatal(err)
	}
	secret := "evysso_" + strings.Repeat("A", 43)
	f.credential = Credential{Secret: secret, Prefix: credentials.Prefix(secret), Hash: credentials.Hash(secret)}
	now := time.Date(2026, 9, 1, 1, 2, 3, 0, time.FixedZone("fixture", 3600))
	state, err := credentials.GenerateLoginState()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := credentials.GenerateLoginNonce()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := OIDCProviderTrustFingerprint(f.provider)
	if err != nil {
		t.Fatal(err)
	}
	f.request = identitydomain.OIDCAuthenticationRequest{ID: "request", TenantID: "tenant", ProviderID: "provider", Delivery: "api", TrustFingerprint: fingerprint, StateHash: state.Hash, NonceHash: nonce.Hash, CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(5 * time.Minute), SchemaVersion: identitydomain.OIDCAuthenticationRequestSchemaVersion}
	f.result.Nonce = nonce.Secret
	f.result.IssuedAt = now.UTC()
	f.result.ExpiresAt = now.UTC().Add(time.Hour)
	s, err := NewSSOExchangeCommands(SSOExchangeCommandConfig{Reader: f, Transactions: f, Credentials: f, Verifier: f, VerificationPolicy: fakeProviderVerificationPolicy{}, SessionGrants: exchangeGroupPolicy{}, Clock: application.ClockFunc(func() time.Time { return now }), IDs: application.IDGeneratorFunc(func(p string) string { return p + "_exchange" }), AuthenticationRequests: f, ProofCredentials: credentials})
	if err != nil {
		t.Fatal(err)
	}
	return s, f, ExchangeSSOCredentialInput{ProviderID: " provider ", Subject: " subject ", IDToken: " raw-id-token ", AuthenticationRequestID: f.request.ID, StateSecret: state.Secret}, now.UTC()
}

type exchangeGroupPolicy struct{}

func (exchangeGroupPolicy) GrantsForProviderGroups(p identitydomain.SSOProvider, groups []string) []identitydomain.ResourceGrant {
	return ProviderGroupGrants(p, groups)
}

func TestSSOExchangeCommandsCommitVerificationSessionAndAuditsWithoutAggregate(t *testing.T) {
	s, f, in, now := exchangeCommandsForTest(t)
	v, session, secret, err := s.ExchangeSSOCredential(t.Context(), in)
	if err != nil || v.Result != "passed" || session.TenantID != "tenant" || session.UserID != "user" || session.ProviderID != "provider" || session.Hash != "" || secret != f.credential.Secret || session.ExpiresAt != now.Add(8*time.Hour) || session.CreatedAt != now || session.SchemaVersion != identitydomain.SSOSessionSchemaVersion {
		t.Fatal("exchange result changed", err)
	}
	if f.reads != 5 || f.verificationsCalled != 1 || f.generations != 1 || f.transactions != 1 || len(f.verifications) != 1 || len(f.sessions) != 1 || len(f.audits) != 3 || f.sessions[0].Hash != f.credential.Hash {
		t.Fatal("exchange was not atomic and focused")
	}
	if !reflect.DeepEqual(session.Groups, []string{"security"}) || !f.snapshot.UserLoaded || !f.snapshot.UserFound || !f.snapshot.UserGrantsLoaded || f.snapshot.Provider.RoleMapping["security"] != "security_engineer" {
		t.Fatal("snapshot or group isolation lost")
	}
	if f.audits[0].EntryType != "provider_identity.verified" || f.audits[1].EntryType != "sso_session.created" || f.audits[1].ActorType != "sso_provider" || f.audits[1].ActorID != "provider" || f.audits[1].SubjectID != "user" || f.audits[0].TenantID != "tenant" {
		t.Fatal("exchange audit attribution changed")
	}
	if f.audits[2].EntryType != "oidc_authentication_request.consumed" || f.audits[2].SubjectID != f.request.ID || f.request.ConsumedAt == nil {
		t.Fatal("consumption and its audit were not committed with issuance")
	}
	for _, record := range []any{f.verifications, f.sessions, f.audits, v, session} {
		// Marshaling is unnecessary: all secret-bearing outputs are explicit.
		if strings.Contains(exchangeTestString(record), "raw-id-token") || strings.Contains(exchangeTestString(record), f.credential.Secret) {
			t.Fatal("credential reached persisted/public metadata")
		}
	}
}

func TestSSOExchangeCommandsFailuresReturnNoSessionOrSecretAndRollback(t *testing.T) {
	for _, phase := range []string{"provider read", "link read", "user read", "grant read", "credential", "stale", "nil transaction", "nil transaction context", "verification write", "verification audit", "session write", "session audit", "commit", "cancel"} {
		t.Run(phase, func(t *testing.T) {
			s, f, in, _ := exchangeCommandsForTest(t)
			f.phase = phase
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if phase == "cancel" {
				f.cancel = cancel
			}
			v, session, secret, err := s.ExchangeSSOCredential(ctx, in)
			if err == nil || v.ID != "" || session.ID != "" || secret != "" || len(f.verifications)+len(f.sessions)+len(f.audits) != 0 {
				t.Fatal("failed exchange leaked results or committed partial state", err)
			}
			if phase == "stale" && !errors.Is(err, ErrConflict) || phase == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("wrong failure class", err)
			}
		})
	}
}

func TestSSOExchangeCommandsConservativeFailuresPersistOnlyVerification(t *testing.T) {
	for _, phase := range []string{"bad credential", "verifier", "missing link", "unverified link", "foreign link", "wrong provider link", "wrong subject link", "missing user", "inactive user", "foreign user", "wrong user", "no grants"} {
		t.Run(phase, func(t *testing.T) {
			s, f, in, _ := exchangeCommandsForTest(t)
			want := ErrVerificationFailed
			switch phase {
			case "bad credential":
				f.result.Checks[0].Result = "failed"
			case "verifier":
				f.phase = phase
			case "missing link":
				f.link = identitydomain.UserIdentityLink{}
			case "unverified link":
				f.link.Verified = false
			case "foreign link":
				f.link.TenantID = "foreign"
			case "wrong provider link":
				f.link.ProviderID = "foreign"
			case "wrong subject link":
				f.link.Subject = "foreign"
			case "missing user":
				f.user = identitydomain.HumanUser{}
			case "inactive user":
				f.user.Status = "inactive"
			case "foreign user":
				f.user.TenantID = "foreign"
			case "wrong user":
				f.user.ID = "foreign"
			case "no grants":
				f.grants = nil
				f.result.Groups = nil
				want = ErrForbidden
			}
			v, session, secret, err := s.ExchangeSSOCredential(t.Context(), in)
			wantAudits := 2
			if phase == "bad credential" || phase == "verifier" {
				wantAudits = 1
			}
			if !errors.Is(err, want) || v.Result != "failed" || session.ID != "" || secret != "" || f.generations != 0 || len(f.sessions) != 0 || len(f.verifications) != 1 || len(f.audits) != wantAudits || f.audits[0].EntryType != "provider_identity.verified" {
				t.Fatal("conservative failure contract changed", err)
			}
			if (f.request.ConsumedAt != nil) != (wantAudits == 2) || (wantAudits == 2 && f.audits[1].EntryType != "oidc_authentication_request.consumed") {
				t.Fatal("proof consumption did not match verified denial")
			}
			if strings.Contains(exchangeTestString(v), "raw-id-token") || strings.Contains(exchangeTestString(v), "private provider response") {
				t.Fatal("verifier details leaked")
			}
		})
	}
}

func TestSSOExchangeCommandsValidateCredentialShapeAndExpiryBeforeReads(t *testing.T) {
	for _, name := range []string{"provider", "subject", "credential", "both", "secret subject", "expired", "too long"} {
		t.Run(name, func(t *testing.T) {
			s, f, in, now := exchangeCommandsForTest(t)
			switch name {
			case "provider":
				in.ProviderID = " "
			case "subject":
				in.Subject = " "
			case "credential":
				in.IDToken = " "
			case "both":
				in.SAMLAssertion = "assertion"
			case "secret subject":
				in.Subject = "subject-raw-id-token"
			case "expired":
				in.ExpiresAt = now
			case "too long":
				in.ExpiresAt = now.Add(12*time.Hour + time.Nanosecond)
			}
			v, session, secret, err := s.ExchangeSSOCredential(t.Context(), in)
			if !errors.Is(err, ErrValidation) || v.ID != "" || session.ID != "" || secret != "" || f.reads+f.verificationsCalled+f.generations+f.transactions != 0 {
				t.Fatal("invalid exchange reached trust or storage", err)
			}
		})
	}
	for _, duration := range []time.Duration{time.Hour, 12 * time.Hour} {
		s, f, in, now := exchangeCommandsForTest(t)
		in.ExpiresAt = now.Add(duration)
		_, session, _, err := s.ExchangeSSOCredential(t.Context(), in)
		if err != nil || session.ExpiresAt != in.ExpiresAt || f.transactions != 1 {
			t.Fatal("valid lifetime rejected", err)
		}
	}
}

func TestSSOExchangeCommandsRejectInactiveProviderAndWrongCredentialType(t *testing.T) {
	for _, name := range []string{"inactive", "wrong id", "mismatched provider", "no tenant", "oidc assertion", "saml token"} {
		t.Run(name, func(t *testing.T) {
			s, f, in, _ := exchangeCommandsForTest(t)
			want := ErrNotFound
			switch name {
			case "inactive":
				f.provider.Status = "inactive"
			case "wrong id":
				in.ProviderID = "foreign"
			case "mismatched provider":
				f.phase = name
			case "no tenant":
				f.provider.TenantID = ""
			case "oidc assertion":
				in.IDToken = ""
				in.SAMLAssertion = "assertion"
				want = ErrValidation
			case "saml token":
				f.provider.Type = "saml"
				want = ErrValidation
			}
			v, session, secret, err := s.ExchangeSSOCredential(t.Context(), in)
			if !errors.Is(err, want) || v.ID != "" || session.ID != "" || secret != "" || f.verificationsCalled+f.generations+f.transactions != 0 {
				t.Fatal("invalid provider reached verifier or writes", err)
			}
		})
	}
}

func TestSSOExchangeCommandsRejectIncompleteComposition(t *testing.T) {
	s, _, _, _ := exchangeCommandsForTest(t)
	for _, omit := range []func(*SSOExchangeCommandConfig){
		func(c *SSOExchangeCommandConfig) { c.Reader = nil },
		func(c *SSOExchangeCommandConfig) { c.Transactions = nil },
		func(c *SSOExchangeCommandConfig) { c.Credentials = nil },
		func(c *SSOExchangeCommandConfig) { c.Verifier = nil },
		func(c *SSOExchangeCommandConfig) { c.VerificationPolicy = nil },
		func(c *SSOExchangeCommandConfig) { c.SessionGrants = nil },
		func(c *SSOExchangeCommandConfig) { c.Clock = nil },
		func(c *SSOExchangeCommandConfig) { c.IDs = nil },
		func(c *SSOExchangeCommandConfig) { c.AuthenticationRequests = nil },
		func(c *SSOExchangeCommandConfig) { c.ProofCredentials = nil },
	} {
		c := s.config
		omit(&c)
		if command, err := NewSSOExchangeCommands(c); !errors.Is(err, ErrValidation) || command != nil {
			t.Fatal("incomplete exchange composition accepted", err)
		}
	}
}

func TestSSOExchangeCommandsRejectNilAndCancelledCallsWithoutEffects(t *testing.T) {
	s, f, in, _ := exchangeCommandsForTest(t)
	var absent *SSOExchangeCommands
	if v, session, secret, err := absent.ExchangeSSOCredential(t.Context(), in); !errors.Is(err, ErrValidation) || v.ID != "" || session.ID != "" || secret != "" {
		t.Fatal("nil command call accepted", err)
	}
	//nolint:staticcheck // The command contract explicitly rejects a nil context.
	if _, _, _, err := s.ExchangeSSOCredential(nil, in); !errors.Is(err, ErrValidation) {
		t.Fatal("nil context accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, session, secret, err := s.ExchangeSSOCredential(ctx, in); !errors.Is(err, context.Canceled) || v.ID != "" || session.ID != "" || secret != "" || f.reads+f.transactions+f.generations != 0 {
		t.Fatal("cancelled exchange reached trust/storage", err)
	}
}

func TestSSOExchangeCommandsDoNotReturnFailedReceiptUntilCommit(t *testing.T) {
	for _, phase := range []string{"stale", "verification write", "verification audit", "commit", "cancel"} {
		t.Run(phase, func(t *testing.T) {
			s, f, in, _ := exchangeCommandsForTest(t)
			f.phase = phase
			f.result.Checks[0].Result = "failed"
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if phase == "cancel" {
				f.cancel = cancel
			}
			v, session, secret, err := s.ExchangeSSOCredential(ctx, in)
			if err == nil || v.ID != "" || session.ID != "" || secret != "" || f.generations != 0 || len(f.verifications)+len(f.sessions)+len(f.audits) != 0 {
				t.Fatal("denied exchange returned or retained an uncommitted receipt", err)
			}
		})
	}
}

func TestSSOExchangeCommandsAcceptSAMLAndProviderGroupOnlyGrants(t *testing.T) {
	for _, name := range []string{"saml", "groups only", "unknown groups"} {
		t.Run(name, func(t *testing.T) {
			s, f, in, _ := exchangeCommandsForTest(t)
			var want error
			switch name {
			case "saml":
				s, f, in, _ = boundSAMLExchangeCommandsForTest(t)
			case "groups only":
				f.grants = nil
			case "unknown groups":
				f.grants = nil
				f.result.Groups = []string{"unknown"}
				want = ErrForbidden
			}
			v, session, secret, err := s.ExchangeSSOCredential(t.Context(), in)
			if !errors.Is(err, want) {
				t.Fatal("provider/grant contract changed", err)
			}
			if want == nil && (v.Result != "passed" || session.ID == "" || secret != f.credential.Secret || len(f.sessions) != 1) {
				t.Fatal("valid provider exchange did not issue a session")
			}
			if want != nil && (v.Result != "failed" || session.ID != "" || secret != "" || len(f.sessions) != 0) {
				t.Fatal("unknown group conferred a grant")
			}
		})
	}
}

func TestSSOExchangeCommandsCancelDuringVerificationDoesNotReadLinksOrPersist(t *testing.T) {
	s, f, in, _ := exchangeCommandsForTest(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f.phase, f.cancel = "cancel verifier", cancel
	v, session, secret, err := s.ExchangeSSOCredential(ctx, in)
	if !errors.Is(err, context.Canceled) || v.ID != "" || session.ID != "" || secret != "" || f.reads != 2 || f.verificationsCalled != 1 || f.transactions+f.generations != 0 {
		t.Fatal("cancelled verifier reached identity lookup/storage", err)
	}
}

func TestSSOExchangeCommandsRejectIncompleteGeneratedCredentialsBeforeTransaction(t *testing.T) {
	for _, field := range []string{"secret", "prefix", "hash"} {
		t.Run(field, func(t *testing.T) {
			s, f, in, _ := exchangeCommandsForTest(t)
			switch field {
			case "secret":
				f.credential.Secret = " "
			case "prefix":
				f.credential.Prefix = " "
			case "hash":
				f.credential.Hash = " "
			}
			v, session, secret, err := s.ExchangeSSOCredential(t.Context(), in)
			if !errors.Is(err, ErrValidation) || v.ID != "" || session.ID != "" || secret != "" || f.generations != 1 || f.transactions != 0 {
				t.Fatal("incomplete session material reached persistence", err)
			}
		})
	}
}

func TestSSOExchangeCommandsRejectWeakOrNoncanonicalIssuedCredential(t *testing.T) {
	for _, change := range []func(*Credential){
		func(c *Credential) { c.Secret = "evysso_weak"; c.Prefix = c.Secret },
		func(c *Credential) { c.Hash = "not-a-persisted-hash" },
	} {
		s, f, input, _ := exchangeCommandsForTest(t)
		change(&f.credential)
		value, session, secret, err := s.ExchangeSSOCredential(t.Context(), input)
		if !errors.Is(err, ErrValidation) || value.ID != "" || session.ID != "" || secret != "" || f.transactions != 0 {
			t.Fatal("weak session material reached transaction", err)
		}
	}
}

func TestSSOExchangeCommandsPersistTightenedPolicyAndBoundDefaultExpiry(t *testing.T) {
	s, f, input, now := exchangeCommandsForTest(t)
	s.config.SessionPolicy = identitydomain.SessionPolicy{MaximumLifetime: time.Hour, IdleTimeout: 5 * time.Minute}
	_, session, secret, err := s.ExchangeSSOCredential(t.Context(), input)
	if err != nil || secret == "" || session.ExpiresAt != now.Add(time.Hour) || session.MaximumLifetimeSeconds != 3600 || session.IdleTimeoutSeconds != 300 || session.LastUsedAt == nil || !session.LastUsedAt.Equal(now) || len(f.sessions) != 1 || f.sessions[0].Hash != f.credential.Hash {
		t.Fatal("tightened lifecycle policy not retained", err)
	}
	input.ExpiresAt = now.Add(2 * time.Hour)
	before := f.generations
	if _, _, secret, err := s.ExchangeSSOCredential(t.Context(), input); !errors.Is(err, ErrValidation) || secret != "" || f.generations != before {
		t.Fatal("explicit over-policy expiry issued a credential", err)
	}
}

func TestSSOExchangeCommandsWithholdSecretWhenCommitOutlivesLifecycle(t *testing.T) {
	s, f, input, now := exchangeCommandsForTest(t)
	at := now
	s.config.Clock = application.ClockFunc(func() time.Time { return at })
	f.commitHook = func() { at = at.Add(30 * time.Minute) }
	verification, session, secret, err := s.ExchangeSSOCredential(t.Context(), input)
	if !errors.Is(err, ErrValidation) || verification.ID != "" || session.ID != "" || secret != "" || len(f.sessions) != 1 || f.sessions[0].Hash == "" || len(f.audits) != 3 {
		t.Fatal("late committed exchange returned unusable material or lost committed history", err)
	}
}

func TestSSOExchangeCommandsRejectUnsafeTextAndTimesBeforeTrustReads(t *testing.T) {
	for _, field := range []string{"provider", "subject", "token", "assertion"} {
		for _, bad := range []string{"value\x00", string([]byte{0xff}), strings.Repeat("x", 65537)} {
			s, f, in, _ := exchangeCommandsForTest(t)
			switch field {
			case "provider":
				in.ProviderID = bad
			case "subject":
				in.Subject = bad
			case "token":
				in.IDToken = bad
			case "assertion":
				in.IDToken = ""
				in.SAMLAssertion = bad
			}
			v, session, secret, err := s.ExchangeSSOCredential(t.Context(), in)
			if !errors.Is(err, ErrValidation) || v.ID != "" || session.ID != "" || secret != "" || f.reads+f.verificationsCalled+f.generations+f.transactions != 0 {
				t.Fatal("unsafe exchange text reached trust or storage", field, err)
			}
		}
	}
	s, f, in, _ := exchangeCommandsForTest(t)
	in.ProviderID = strings.Repeat("x", 1025)
	if _, _, _, err := s.ExchangeSSOCredential(t.Context(), in); !errors.Is(err, ErrValidation) || f.reads != 0 {
		t.Fatal("overlong provider identity reached reader", err)
	}
	for _, invalid := range []time.Time{{}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		s, f, in, _ := exchangeCommandsForTest(t)
		s.config.Clock = application.ClockFunc(func() time.Time { return invalid })
		if _, _, _, err := s.ExchangeSSOCredential(t.Context(), in); !errors.Is(err, ErrValidation) || f.reads != 0 {
			t.Fatal("invalid clock reached trust or storage", err)
		}
	}
}
