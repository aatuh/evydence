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

// Implements only receipt-specific ports: no sessions, users or credentials.
type providerReceiptFixture struct {
	provider                                   identitydomain.SSOProvider
	link                                       identitydomain.UserIdentityLink
	local                                      CredentialVerificationResult
	live                                       ProviderIdentityValidationResult
	request                                    ProviderIdentityValidationRequest
	records                                    []identitydomain.ProviderVerification
	audits                                     []application.AuditEvent
	snapshot                                   SSOExchangeSnapshot
	phase                                      string
	reads, localCalls, liveCalls, transactions int
	cancel                                     context.CancelFunc
}

var errProviderReceipt = errors.New("private provider receipt failure")

func (f *providerReceiptFixture) ReadOwnedSSOProvider(_ context.Context, tenant, id string) (identitydomain.SSOProvider, error) {
	f.reads++
	if f.phase == "provider read" {
		return identitydomain.SSOProvider{}, errProviderReceipt
	}
	if tenant != f.provider.TenantID || id != f.provider.ID {
		return identitydomain.SSOProvider{}, ErrNotFound
	}
	p := cloneSSOProvider(f.provider)
	if f.phase == "foreign provider" {
		p.TenantID = "other"
	}
	return p, nil
}
func (f *providerReceiptFixture) IdentityLink(_ context.Context, tenant, provider, subject string) (identitydomain.UserIdentityLink, bool, error) {
	f.reads++
	if f.phase == "link read" {
		return identitydomain.UserIdentityLink{}, false, errProviderReceipt
	}
	if tenant != f.provider.TenantID || provider != f.provider.ID || subject != "subject" {
		return identitydomain.UserIdentityLink{}, false, ErrNotFound
	}
	return f.link, f.link.ID != "", nil
}
func (f *providerReceiptFixture) Verify(_ context.Context, r CredentialVerificationRequest) (CredentialVerificationResult, error) {
	f.localCalls++
	if f.transactions != 0 || r.Subject != "subject" || r.Now.IsZero() {
		return CredentialVerificationResult{}, errProviderReceipt
	}
	if f.phase == "local failure" {
		return f.local, errProviderReceipt
	}
	if f.phase == "mutating verifier" {
		r.Provider.RoleMapping["security"] = "tenant_admin"
	}
	return f.local, nil
}
func (f *providerReceiptFixture) ValidateProviderIdentity(_ context.Context, r ProviderIdentityValidationRequest) (ProviderIdentityValidationResult, error) {
	f.liveCalls++
	f.request = r
	if f.transactions != 0 {
		return ProviderIdentityValidationResult{}, errProviderReceipt
	}
	if f.cancel != nil {
		f.cancel()
	}
	if f.phase == "live failure" {
		return f.live, errProviderReceipt
	}
	return f.live, nil
}
func (f *providerReceiptFixture) ExecuteProviderVerification(ctx context.Context, fn func(context.Context, ProviderVerificationTransaction) error) error {
	f.transactions++
	oldRecords, oldAudits := len(f.records), len(f.audits)
	var err error
	if f.phase == "nil transaction" {
		err = fn(ctx, nil)
	} else {
		err = fn(ctx, f)
	}
	if err == nil && f.phase == "commit" {
		err = errProviderReceipt
	}
	if err != nil {
		f.records = f.records[:oldRecords]
		f.audits = f.audits[:oldAudits]
	}
	return err
}
func (f *providerReceiptFixture) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if f.phase == "transaction authorization" && f.transactions > 0 {
		return ErrForbidden
	}
	return NewMembershipWriteAuthorizer().Authorize(ctx, a, r)
}
func (f *providerReceiptFixture) ValidateSSOExchangeState(_ context.Context, s SSOExchangeSnapshot) error {
	f.snapshot = cloneSSOExchangeSnapshot(s)
	if f.phase == "snapshot" {
		return ErrConflict
	}
	return nil
}
func (f *providerReceiptFixture) InsertProviderVerification(_ context.Context, r identitydomain.ProviderVerification) error {
	if f.phase == "insert" {
		return errProviderReceipt
	}
	f.records = append(f.records, cloneProviderVerification(r))
	return nil
}
func (f *providerReceiptFixture) AppendAudit(_ context.Context, a application.AuditEvent) (application.AuditReceipt, error) {
	if f.phase == "audit" {
		return application.AuditReceipt{}, errProviderReceipt
	}
	f.audits = append(f.audits, a)
	if f.phase == "cancel after audit" {
		f.cancel()
	}
	return application.AuditReceipt{}, nil
}

func TestProviderReceiptConfigurationContextAndDefensiveSnapshot(t *testing.T) {
	c, f, a, in := newProviderReceiptFixture(t)
	for _, field := range []string{"reader", "transactions", "authorizer", "verifier", "policy", "clock", "ids"} {
		t.Run(field, func(t *testing.T) {
			config := c.config
			switch field {
			case "reader":
				config.Reader = nil
			case "transactions":
				config.Transactions = nil
			case "authorizer":
				config.Authorizer = nil
			case "verifier":
				config.Verifier = nil
			case "policy":
				config.VerificationPolicy = nil
			case "clock":
				config.Clock = nil
			case "ids":
				config.IDs = nil
			}
			if service, err := NewProviderVerificationCommands(config); !errors.Is(err, ErrValidation) || service != nil {
				t.Fatal("incomplete receipt config accepted", field, err)
			}
		})
	}
	//nolint:staticcheck // Nil-context rejection is part of the command contract.
	if _, err := c.VerifyProviderIdentity(nil, a, in); !errors.Is(err, ErrValidation) {
		t.Fatal("nil context accepted", err)
	}
	var absent *ProviderVerificationCommands
	if _, err := absent.VerifyProviderIdentity(t.Context(), a, in); !errors.Is(err, ErrValidation) {
		t.Fatal("nil receiver accepted", err)
	}
	c.config.Clock = application.ClockFunc(func() time.Time { return time.Time{} })
	if _, err := c.VerifyProviderIdentity(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.transactions != 0 {
		t.Fatal("invalid clock wrote receipt", err)
	}
	c, f, a, in = newProviderReceiptFixture(t)
	f.phase = "nil transaction"
	if _, err := c.VerifyProviderIdentity(t.Context(), a, in); !errors.Is(err, ErrValidation) {
		t.Fatal("nil transaction accepted", err)
	}
	c, f, a, in = newProviderReceiptFixture(t)
	f.phase = "mutating verifier"
	in.IDToken = "id-token-secret"
	if _, err := c.VerifyProviderIdentity(t.Context(), a, in); err != nil || f.snapshot.Provider.RoleMapping["security"] != "security_engineer" {
		t.Fatal("verifier mutated decision snapshot", err)
	}
	c, f, a, in = newProviderReceiptFixture(t)
	f.phase = "cancel after audit"
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f.cancel = cancel
	if v, err := c.VerifyProviderIdentity(ctx, a, in); !errors.Is(err, context.Canceled) || v.ID != "" || len(f.records)+len(f.audits) != 0 {
		t.Fatal("canceled transaction published receipt", v, err)
	}
}

type providerReceiptPolicy struct{}

func (providerReceiptPolicy) Assess(v identitydomain.ProviderVerification, _ identitydomain.SSOProvider, supplied bool) identitydomain.ProviderVerification {
	v.Result = "passed"
	if !supplied {
		v.Result = "not_evaluated"
	}
	for _, c := range v.Checks {
		if c.Result == "failed" || c.Result == "error" {
			v.Result = c.Result
		}
	}
	return v
}
func (providerReceiptPolicy) ReturnsFailure(s string) bool { return s == "failed" || s == "error" }
func newProviderReceiptFixture(t *testing.T) (*ProviderVerificationCommands, *providerReceiptFixture, identitydomain.Actor, VerifyProviderIdentityInput) {
	t.Helper()
	f := &providerReceiptFixture{provider: identitydomain.SSOProvider{ID: "provider", TenantID: "tenant", Type: "oidc", Status: "inactive", Issuer: "https://issuer.example.test", GroupsClaim: "groups", RoleMapping: map[string]string{"security": "security_engineer"}}, link: identitydomain.UserIdentityLink{ID: "link", TenantID: "tenant", ProviderID: "provider", Subject: "subject", Verified: true}, local: CredentialVerificationResult{Checks: []identitydomain.VerificationCheck{{Name: "signature", Result: "passed"}}}, live: ProviderIdentityValidationResult{Checks: []identitydomain.VerificationCheck{{Name: "live_subject", Result: "passed"}}, Groups: []string{"security"}}}
	n := 0
	c, err := NewProviderVerificationCommands(ProviderVerificationCommandConfig{Reader: f, Transactions: f, Authorizer: f, Verifier: f, LiveProvider: f, VerificationPolicy: providerReceiptPolicy{}, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC) }), IDs: application.IDGeneratorFunc(func(prefix string) string { n++; return fmt.Sprintf("%s-%d", prefix, n) })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{ScopeIdentityAdmin}}, VerifyProviderIdentityInput{ProviderType: "oidc", ProviderID: "provider", Subject: "subject"}
}
func TestProviderReceiptMetadataLocalAndLiveModes(t *testing.T) {
	for _, mode := range []string{"metadata", "local", "live", "combined", "saml"} {
		t.Run(mode, func(t *testing.T) {
			c, f, a, in := newProviderReceiptFixture(t)
			if mode == "local" || mode == "combined" {
				in.IDToken = "id-token-secret"
			}
			if mode == "live" || mode == "combined" {
				in.AccessToken = "access-token-secret"
			}
			if mode == "saml" {
				f.provider.Type = "saml"
				in.ProviderType = "saml"
				in.SAMLAssertion = "assertion-secret"
			}
			v, err := c.VerifyProviderIdentity(t.Context(), a, in)
			if err != nil || len(f.records) != 1 || len(f.audits) != 1 || !reflect.DeepEqual(v, f.records[0]) {
				t.Fatalf("receipt=%#v err=%v", v, err)
			}
			want := "passed"
			if mode == "metadata" {
				want = "not_evaluated"
			}
			if v.Result != want || v.TenantID != a.TenantID || v.SchemaVersion != identitydomain.ProviderVerificationVersion || v.CreatedAt.IsZero() {
				t.Fatal("receipt identity/state mismatch", v)
			}
			if f.audits[0].ActorID != a.KeyID || f.audits[0].ActorType != "api_key" || f.audits[0].SubjectID != v.ID || f.audits[0].EntryType != "provider_identity.verified" {
				t.Fatal("audit attribution mismatch", f.audits)
			}
			if f.snapshot.UserLoaded || f.snapshot.UserGrantsLoaded || !f.snapshot.IdentityLinkFound || f.snapshot.Provider.Status != "inactive" {
				t.Fatal("receipt changed login semantics", f.snapshot)
			}
			if f.liveCalls > 0 && (f.request.AccessToken != in.AccessToken || f.request.TenantID != a.TenantID || f.request.Issuer != f.provider.Issuer) {
				t.Fatal("provider request mismatch")
			}
		})
	}
}
func TestProviderReceiptFailuresPersistSafeAssessmentButNeverPartialTransaction(t *testing.T) {
	for _, phase := range []string{"local failure", "live failure", "missing link", "unverified link", "foreign link", "missing live provider", "snapshot", "insert", "audit", "commit", "provider read", "link read", "transaction authorization", "foreign provider"} {
		t.Run(phase, func(t *testing.T) {
			c, f, a, in := newProviderReceiptFixture(t)
			f.phase = phase
			in.IDToken = "id-token-secret"
			in.AccessToken = "access-token-secret"
			assessment := false
			want := errProviderReceipt
			switch phase {
			case "local failure", "live failure":
				assessment = true
				want = ErrVerificationFailed
			case "missing link":
				f.link = identitydomain.UserIdentityLink{}
				assessment = true
				want = ErrVerificationFailed
			case "unverified link":
				f.link.Verified = false
				assessment = true
				want = ErrVerificationFailed
			case "foreign link":
				f.link.TenantID = "other"
				want = ErrConflict
			case "missing live provider":
				c.config.LiveProvider = nil
				assessment = true
				want = ErrVerificationFailed
			case "snapshot":
				want = ErrConflict
			case "transaction authorization":
				want = ErrForbidden
			case "foreign provider":
				want = ErrNotFound
			}
			v, err := c.VerifyProviderIdentity(t.Context(), a, in)
			if !errors.Is(err, want) {
				t.Fatalf("err=%v want=%v", err, want)
			}
			if assessment {
				if v.ID == "" || len(f.records) != 1 || len(f.audits) != 1 {
					t.Fatal("failed assessment was not persisted")
				}
			} else if v.ID != "" || len(f.records) != 0 || len(f.audits) != 0 {
				t.Fatal("partial transaction escaped")
			}
		})
	}
}
func TestProviderReceiptValidatesBeforeReadsAndChecksTenantAuthority(t *testing.T) {
	for _, variant := range []string{"missing provider", "wrong type", "oidc assertion", "saml token", "long access", "long subject", "invalid utf8", "nul", "secret subject", "no actor", "no scope", "restricted human", "foreign tenant", "canceled"} {
		t.Run(variant, func(t *testing.T) {
			c, f, a, in := newProviderReceiptFixture(t)
			want := ErrValidation
			ctx := t.Context()
			switch variant {
			case "missing provider":
				in.ProviderID = " "
			case "wrong type":
				in.ProviderType = "unknown"
			case "oidc assertion":
				in.SAMLAssertion = "assertion"
			case "saml token":
				in.ProviderType = "saml"
				in.AccessToken = "access"
			case "long access":
				in.AccessToken = strings.Repeat("x", 16385)
			case "long subject":
				in.Subject = strings.Repeat("x", 65537)
			case "invalid utf8":
				in.IDToken = string([]byte{0xff})
			case "nul":
				in.Subject = "subject\x00"
			case "secret subject":
				in.IDToken = "subject"
			case "no actor":
				a.KeyID = ""
				want = application.ErrUnauthorized
			case "no scope":
				a.Scopes = nil
				want = ErrForbidden
			case "restricted human":
				a.KeyID = ""
				a.UserID = "user"
				a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{ScopeIdentityAdmin}}}
				want = ErrForbidden
			case "foreign tenant":
				a.TenantID = "other"
				want = ErrNotFound
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			}
			if _, err := c.VerifyProviderIdentity(ctx, a, in); !errors.Is(err, want) {
				t.Fatalf("err=%v want=%v", err, want)
			}
			if variant != "foreign tenant" && f.reads != 0 || f.transactions != 0 || f.liveCalls != 0 || f.localCalls != 0 {
				t.Fatal("invalid/unauthorized input reached dependencies")
			}
		})
	}
}
func TestProviderReceiptRedactsEveryCredentialFromProviderOutput(t *testing.T) {
	c, f, a, in := newProviderReceiptFixture(t)
	in.IDToken = "id-token-secret"
	in.AccessToken = "access-token-secret"
	f.local.Checks[0].Detail = in.IDToken
	f.live.Checks[0].Detail = in.AccessToken
	f.live.Limitations = []string{"echo " + in.AccessToken + " and " + in.IDToken}
	v, err := c.VerifyProviderIdentity(t.Context(), a, in)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{in.IDToken, in.AccessToken} {
		if strings.Contains(fmt.Sprintf("%#v %#v %#v", v, f.records, f.audits), secret) {
			t.Fatal("credential escaped")
		}
	}
}
func TestProviderReceiptCancelsAfterProviderAndBoundsUntrustedResult(t *testing.T) {
	c, f, a, in := newProviderReceiptFixture(t)
	in.AccessToken = "access-secret"
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f.cancel = cancel
	if _, err := c.VerifyProviderIdentity(ctx, a, in); !errors.Is(err, context.Canceled) || f.transactions != 0 {
		t.Fatal("cancellation wrote a receipt", err)
	}
	for _, variant := range []string{"checks", "limitations", "groups", "detail", "invalid utf8", "empty checks", "unknown state", "combined budget", "redaction expansion"} {
		t.Run(variant, func(t *testing.T) {
			c, f, a, in := newProviderReceiptFixture(t)
			in.AccessToken = "access-secret"
			switch variant {
			case "redaction expansion":
				in.AccessToken = "xyz"
				f.live.Checks[0].Detail = strings.Repeat("xyz", 20000)
				f.live.Limitations = []string{strings.Repeat("xyz", 20000), strings.Repeat("xyz", 20000), strings.Repeat("xyz", 20000)}
			case "empty checks":
				f.live.Checks = nil
			case "unknown state":
				f.live.Checks[0].Result = "trust_me"
			case "combined budget":
				f.live.Limitations = []string{strings.Repeat("x", 65536), strings.Repeat("x", 65536), strings.Repeat("x", 65536), strings.Repeat("x", 65536)}
			case "checks":
				f.live.Checks = make([]identitydomain.VerificationCheck, 257)
			case "limitations":
				f.live.Limitations = make([]string, 257)
			case "groups":
				f.live.Groups = make([]string, 257)
			case "detail":
				f.live.Checks[0].Detail = strings.Repeat("x", 65537)
			case "invalid utf8":
				f.live.Limitations = []string{string([]byte{0xff})}
			}
			v, err := c.VerifyProviderIdentity(t.Context(), a, in)
			if !errors.Is(err, ErrVerificationFailed) || v.Result != "error" || len(f.records) != 1 || len(f.audits) != 1 {
				t.Fatalf("unsafe provider result: state=%q records=%d audits=%d err=%v", v.Result, len(f.records), len(f.audits), err)
			}
		})
	}
}
