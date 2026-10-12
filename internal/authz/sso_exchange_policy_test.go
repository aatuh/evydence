package authz

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var ssoExchangeCases = []Action{"sso_credentials.exchange"}

func ssoExchangePolicyFixture() SSOExchangeRequest {
	return SSOExchangeRequest{Action: ActionSSOCredentialsExchange, ProviderID: "provider", Subject: "subject", Provider: SSOExchangeProvider{ID: "provider", TenantID: "tenant", Status: "active"}, Link: SSOExchangeLink{ID: "link", TenantID: "tenant", ProviderID: "provider", UserID: "user", Subject: "subject", Verified: true}, User: SSOExchangeUser{ID: "user", TenantID: "tenant", Status: "active"}, LinkFound: true, UserFound: true, VerificationResult: "passed", CredentialChecks: []string{"passed", "passed"}, VerifierCompleted: true, HasCapabilities: true}
}

func TestSSOExchangePolicyRequiresVerifiedBoundCurrentIdentityAndCapability(t *testing.T) {
	r := ssoExchangePolicyFixture()
	before := r
	before.CredentialChecks = append([]string(nil), r.CredentialChecks...)
	if err := AuthorizeSSOExchange(t.Context(), r); err != nil || !reflect.DeepEqual(r, before) {
		t.Fatal("valid verified identity denied or policy mutated proof", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*SSOExchangeRequest)
		want error
	}{
		{"unregistered action", func(r *SSOExchangeRequest) { r.Action = "unregistered" }, ErrForbidden},
		{"admin action", func(r *SSOExchangeRequest) { r.Action = ActionMembershipsManage }, ErrForbidden},
		{"foreign provider", func(r *SSOExchangeRequest) { r.Provider.ID = "foreign" }, ErrNotFound},
		{"inactive provider", func(r *SSOExchangeRequest) { r.Provider.Status = "inactive" }, ErrNotFound},
		{"missing tenant", func(r *SSOExchangeRequest) { r.Provider.TenantID = "" }, ErrNotFound},
		{"missing link", func(r *SSOExchangeRequest) { r.LinkFound = false }, ErrUnauthorized},
		{"unverified link", func(r *SSOExchangeRequest) { r.Link.Verified = false }, ErrUnauthorized},
		{"foreign link tenant", func(r *SSOExchangeRequest) { r.Link.TenantID = "foreign" }, ErrUnauthorized},
		{"foreign link provider", func(r *SSOExchangeRequest) { r.Link.ProviderID = "foreign" }, ErrUnauthorized},
		{"foreign subject", func(r *SSOExchangeRequest) { r.Link.Subject = "foreign" }, ErrUnauthorized},
		{"missing link ID", func(r *SSOExchangeRequest) { r.Link.ID = "" }, ErrUnauthorized},
		{"missing link user", func(r *SSOExchangeRequest) { r.Link.UserID = "" }, ErrUnauthorized},
		{"missing user", func(r *SSOExchangeRequest) { r.UserFound = false }, ErrUnauthorized},
		{"inactive user", func(r *SSOExchangeRequest) { r.User.Status = "inactive" }, ErrUnauthorized},
		{"foreign user", func(r *SSOExchangeRequest) { r.User.ID = "foreign" }, ErrUnauthorized},
		{"foreign user tenant", func(r *SSOExchangeRequest) { r.User.TenantID = "foreign" }, ErrUnauthorized},
		{"verifier error", func(r *SSOExchangeRequest) { r.VerifierCompleted = false }, ErrUnauthorized},
		{"missing checks", func(r *SSOExchangeRequest) { r.CredentialChecks = nil }, ErrUnauthorized},
		{"pending assessment", func(r *SSOExchangeRequest) { r.VerificationResult = "pending" }, ErrUnauthorized},
		{"no current capabilities", func(r *SSOExchangeRequest) { r.HasCapabilities = false }, ErrForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := ssoExchangePolicyFixture()
			tc.edit(&bad)
			if err := AuthorizeSSOExchange(t.Context(), bad); !errors.Is(err, tc.want) {
				t.Fatal("wrong identity/proof acquired session authority", err)
			}
		})
	}
	for _, outcome := range []string{"failed", "error", "pending", "skipped", "not_evaluated", "unknown", " passed ", ""} {
		bad := ssoExchangePolicyFixture()
		bad.CredentialChecks[0] = outcome
		if err := AuthorizeSSOExchange(t.Context(), bad); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("nonpassing check acquired session authority", outcome, err)
		}
		bad = ssoExchangePolicyFixture()
		bad.VerificationResult = outcome
		if err := AuthorizeSSOExchange(t.Context(), bad); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("nonpassing aggregate acquired session authority", outcome, err)
		}
	}
	for _, actor := range []identitydomain.Actor{{TenantID: "tenant", KeyID: "key", Scopes: []string{"*", "admin", "identity:admin"}}, {TenantID: "tenant", KeyID: "key", CollectorID: "collector", Scopes: []string{"*"}}, {TenantID: "tenant", UserID: "user", Scopes: []string{"*"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"*"}}}}} {
		for _, phase := range []Evaluation{ResolvedEvaluation, ScopeEvaluation, TenantEvaluation} {
			if err := Authorize(t.Context(), actor, Request{Action: r.Action, Evaluation: phase}); !errors.Is(err, ErrForbidden) {
				t.Fatal("API actor substituted for a verified exchange credential", phase, err)
			}
		}
	}
}

func TestSSOExchangePolicyPreservesLifetimeLimitsAndCancellation(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	for _, duration := range []time.Duration{time.Hour, 8 * time.Hour, 12 * time.Hour} {
		if err := CheckSSOExchangeSessionLifetime(t.Context(), now, now.Add(duration), now); err != nil {
			t.Fatal("valid session lifetime denied", duration, err)
		}
	}
	for _, args := range [][3]time.Time{{now, now, now}, {now, now.Add(12*time.Hour + time.Nanosecond), now}, {now, now.Add(time.Hour), now.Add(time.Hour)}, {{}, now.Add(time.Hour), now}, {now, now.Add(time.Hour), {}}} {
		if err := CheckSSOExchangeSessionLifetime(t.Context(), args[0], args[1], args[2]); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("expired/expanded lifetime acquired session authority", err)
		}
	}
	r := ssoExchangePolicyFixture()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, check := range []func(context.Context) error{
		func(ctx context.Context) error { return CheckSSOExchangeProvider(ctx, r.Provider, r.ProviderID) },
		func(ctx context.Context) error {
			return CheckSSOCredentialVerification(ctx, r.VerificationResult, true, r.CredentialChecks)
		},
		func(ctx context.Context) error { return CheckSSOExchangeLink(ctx, r.Provider, r.Subject, r.Link, true) },
		func(ctx context.Context) error { return CheckSSOExchangeUser(ctx, r.Provider, r.Link, r.User, true) },
		func(ctx context.Context) error { return AuthorizeSSOExchange(ctx, r) },
		func(ctx context.Context) error {
			return CheckSSOExchangeSessionLifetime(ctx, now, now.Add(time.Hour), now)
		},
	} {
		if err := check(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("canceled exchange policy acquired authority", err)
		}
		var missing context.Context
		if err := check(missing); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("missing context acquired exchange authority", err)
		}
	}
}
