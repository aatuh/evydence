package authz

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"
)

// Exchange policy sees current identity coordinates and safe verification
// outcomes, never raw tokens/assertions, signing material or issued secrets.
type SSOExchangeProvider struct{ ID, TenantID, Status string }
type SSOExchangeLink struct {
	ID, TenantID, ProviderID, UserID, Subject string
	Verified                                  bool
}
type SSOExchangeUser struct{ ID, TenantID, Status string }

type SSOExchangeRequest struct {
	Action               Action
	ProviderID, Subject  string
	Provider             SSOExchangeProvider
	Link                 SSOExchangeLink
	User                 SSOExchangeUser
	LinkFound, UserFound bool
	VerificationResult   string
	CredentialChecks     []string
	VerifierCompleted    bool
	HasCapabilities      bool
}

func ssoExchangePolicyContext(ctx context.Context) error {
	if ctx == nil {
		return ErrUnauthorized
	}
	return ctx.Err()
}

func CheckSSOExchangeProvider(ctx context.Context, provider SSOExchangeProvider, expectedID string) error {
	if err := ssoExchangePolicyContext(ctx); err != nil {
		return err
	}
	if !validPortalPolicyID(expectedID) || !validPortalPolicyID(provider.TenantID) || provider.ID != expectedID || provider.Status != "active" {
		return ErrNotFound
	}
	return nil
}

func CheckSSOCredentialVerification(ctx context.Context, result string, completed bool, checks []string) error {
	if err := ssoExchangePolicyContext(ctx); err != nil {
		return err
	}
	if !completed || result != "passed" || len(checks) == 0 {
		return ErrUnauthorized
	}
	for _, outcome := range checks {
		if outcome != "passed" {
			return ErrUnauthorized
		}
	}
	return nil
}

func CheckSSOExchangeLink(ctx context.Context, provider SSOExchangeProvider, subject string, link SSOExchangeLink, found bool) error {
	if err := ssoExchangePolicyContext(ctx); err != nil {
		return err
	}
	if !found || !validPortalPolicyID(link.ID) || !validPortalPolicyID(link.UserID) || subject == "" || len(subject) > 65536 || strings.TrimSpace(subject) != subject || !utf8.ValidString(subject) || strings.ContainsRune(subject, 0) || link.TenantID != provider.TenantID || link.ProviderID != provider.ID || link.Subject != subject || !link.Verified {
		return ErrUnauthorized
	}
	return nil
}

func CheckSSOExchangeUser(ctx context.Context, provider SSOExchangeProvider, link SSOExchangeLink, user SSOExchangeUser, found bool) error {
	if err := ssoExchangePolicyContext(ctx); err != nil {
		return err
	}
	if !found || user.ID != link.UserID || user.TenantID != provider.TenantID || user.Status != "active" {
		return ErrUnauthorized
	}
	return nil
}

// AuthorizeSSOExchange is not an alternative credential verifier. The verifier
// and versioned assessment must both provide positive proof; merely not being
// failed is insufficient. A session grant does not authorize any later API
// resource operation, which still evaluates current grants independently.
func AuthorizeSSOExchange(ctx context.Context, request SSOExchangeRequest) error {
	if err := ssoExchangePolicyContext(ctx); err != nil {
		return err
	}
	definition, ok := DefinitionFor(request.Action)
	if !ok || definition.Boundary != VerifiedIdentityBoundary {
		return ErrForbidden
	}
	if err := CheckSSOExchangeProvider(ctx, request.Provider, request.ProviderID); err != nil {
		return err
	}
	if err := CheckSSOCredentialVerification(ctx, request.VerificationResult, request.VerifierCompleted, request.CredentialChecks); err != nil {
		return err
	}
	if err := CheckSSOExchangeLink(ctx, request.Provider, request.Subject, request.Link, request.LinkFound); err != nil {
		return err
	}
	if err := CheckSSOExchangeUser(ctx, request.Provider, request.Link, request.User, request.UserFound); err != nil {
		return err
	}
	if !request.HasCapabilities {
		return ErrForbidden
	}
	return nil
}

// CheckSSOExchangeSessionLifetime repeats the existing lifetime rule after
// snapshot locks. Expiry cannot be extended beyond the original 12-hour limit
// by delaying the exchange, nor can an already expired session be issued.
func CheckSSOExchangeSessionLifetime(ctx context.Context, createdAt, expiresAt, now time.Time) error {
	if err := ssoExchangePolicyContext(ctx); err != nil {
		return err
	}
	if createdAt.IsZero() || now.IsZero() || !expiresAt.After(now) || expiresAt.After(createdAt.Add(12*time.Hour)) {
		return ErrUnauthorized
	}
	return nil
}
