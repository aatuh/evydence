package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type VerifyProviderIdentityInput struct {
	ProviderType, ProviderID, Subject, IDToken, SAMLAssertion, AccessToken string
}
type ProviderIdentityValidationRequest struct {
	TenantID, ProviderID, ProviderType, Issuer, Subject, GroupsClaim, AccessToken string
}
type ProviderIdentityValidationResult struct {
	Checks              []identitydomain.VerificationCheck
	Groups, Limitations []string
}
type ProviderIdentityValidator interface {
	ValidateProviderIdentity(context.Context, ProviderIdentityValidationRequest) (ProviderIdentityValidationResult, error)
}
type ProviderVerificationReader interface {
	ReadOwnedSSOProvider(context.Context, string, string) (identitydomain.SSOProvider, error)
	IdentityLink(context.Context, string, string, string) (identitydomain.UserIdentityLink, bool, error)
}

// A receipt transaction cannot issue a session or change provider/link trust.
type ProviderVerificationTransaction interface {
	application.Authorizer
	application.AuditAppender
	ValidateSSOExchangeState(context.Context, SSOExchangeSnapshot) error
	InsertProviderVerification(context.Context, identitydomain.ProviderVerification) error
}
type ProviderVerificationTransactions interface {
	ExecuteProviderVerification(context.Context, func(context.Context, ProviderVerificationTransaction) error) error
}
type ProviderVerificationCommandConfig struct {
	Reader             ProviderVerificationReader
	Transactions       ProviderVerificationTransactions
	Authorizer         application.Authorizer
	Verifier           CredentialVerifier
	LiveProvider       ProviderIdentityValidator // Optional; never inferred from metadata.
	VerificationPolicy ProviderVerificationPolicy
	Clock              application.Clock
	IDs                application.IDGenerator
}
type ProviderVerificationCommands struct {
	config ProviderVerificationCommandConfig
}

func NewProviderVerificationCommands(c ProviderVerificationCommandConfig) (*ProviderVerificationCommands, error) {
	if c.Reader == nil || c.Transactions == nil || c.Authorizer == nil || c.Verifier == nil || c.VerificationPolicy == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &ProviderVerificationCommands{c}, nil
}
func normalizeProviderVerification(in VerifyProviderIdentityInput) (VerifyProviderIdentityInput, error) {
	if !validAPIKeyText(in.ProviderType, 128) || !validAPIKeyText(in.ProviderID, 1024) || !validAPIKeyText(in.Subject, 65536) || !validAPIKeyText(in.IDToken, 65536) || !validAPIKeyText(in.SAMLAssertion, 65536) || !validAPIKeyText(in.AccessToken, 16384) {
		return in, ErrValidation
	}
	in.ProviderType = strings.TrimSpace(in.ProviderType)
	in.ProviderID = strings.TrimSpace(in.ProviderID)
	in.Subject = strings.TrimSpace(in.Subject)
	in.IDToken = strings.TrimSpace(in.IDToken)
	in.SAMLAssertion = strings.TrimSpace(in.SAMLAssertion)
	in.AccessToken = strings.TrimSpace(in.AccessToken)
	if in.ProviderID == "" || in.Subject == "" || (in.ProviderType != "oidc" && in.ProviderType != "saml") || (in.ProviderType == "oidc" && in.SAMLAssertion != "") || (in.ProviderType == "saml" && (in.IDToken != "" || in.AccessToken != "")) {
		return in, ErrValidation
	}
	for _, label := range []string{in.ProviderType, in.ProviderID, in.Subject} {
		if containsCredential(label, in.IDToken, in.SAMLAssertion, in.AccessToken) {
			return in, ErrValidation
		}
	}
	return in, nil
}
func (s *ProviderVerificationCommands) prepare(ctx context.Context, a identitydomain.Actor, in VerifyProviderIdentityInput) (VerifyProviderIdentityInput, identitydomain.SSOProvider, error) {
	if s == nil || ctx == nil {
		return in, identitydomain.SSOProvider{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return in, identitydomain.SSOProvider{}, err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, membershipAuthorization()); err != nil {
		return in, identitydomain.SSOProvider{}, err
	}
	if !validAPIKeyID(a.TenantID) || !validAPIKeyID(actorID(a)) {
		return in, identitydomain.SSOProvider{}, ErrValidation
	}
	in, err := normalizeProviderVerification(in)
	if err != nil {
		return in, identitydomain.SSOProvider{}, err
	}
	p, err := s.config.Reader.ReadOwnedSSOProvider(ctx, a.TenantID, in.ProviderID)
	if err != nil {
		return in, identitydomain.SSOProvider{}, err
	}
	if p.ID != in.ProviderID || p.TenantID != a.TenantID || p.Type != in.ProviderType {
		return in, identitydomain.SSOProvider{}, ErrNotFound
	}
	// Administrative verification may assess an inactive provider. Login has
	// a separate active-provider policy; this receipt does not grant access.
	return in, cloneSSOProvider(p), nil
}
func (s *ProviderVerificationCommands) AuthorizeVerifyProviderIdentity(ctx context.Context, a identitydomain.Actor, in VerifyProviderIdentityInput) error {
	_, _, err := s.prepare(ctx, a, in)
	return err
}
func (s *ProviderVerificationCommands) VerifyProviderIdentity(ctx context.Context, a identitydomain.Actor, in VerifyProviderIdentityInput) (identitydomain.ProviderVerification, error) {
	in, p, err := s.prepare(ctx, a, in)
	if err != nil {
		return identitydomain.ProviderVerification{}, err
	}
	now := s.config.Clock.Now().UTC()
	if now.IsZero() || !validAPIKeyTime(now) {
		return identitydomain.ProviderVerification{}, ErrValidation
	}
	link, found, err := s.config.Reader.IdentityLink(ctx, a.TenantID, p.ID, in.Subject)
	if err != nil {
		return identitydomain.ProviderVerification{}, err
	}
	if found && (link.ID == "" || link.TenantID != a.TenantID || link.ProviderID != p.ID || link.Subject != in.Subject) {
		return identitydomain.ProviderVerification{}, ErrConflict
	}
	snapshot := SSOExchangeSnapshot{Provider: cloneSSOProvider(p), Subject: in.Subject, IdentityLinkFound: found}
	if found {
		snapshot.IdentityLink = link
	}
	checks := []identitydomain.VerificationCheck{}
	limitations := []string{"Verification uses stored provider metadata and configured local token/assertion trust roots; no live provider API or discovery call is made."}
	if in.IDToken != "" || in.SAMLAssertion != "" {
		local, verifyErr := s.config.Verifier.Verify(ctx, CredentialVerificationRequest{Provider: cloneSSOProvider(p), Subject: in.Subject, IDToken: in.IDToken, SAMLAssertion: in.SAMLAssertion, Now: now})
		if validProviderValidationResult(ProviderIdentityValidationResult{Checks: local.Checks}) {
			checks = append(checks, local.Checks...)
		} else {
			verifyErr = ErrValidation
		}
		if verifyErr != nil {
			checks = append(checks, identitydomain.VerificationCheck{Name: "credential_verification", Result: "failed", Detail: "credential verification did not complete"})
		}
	} else {
		limitations = []string{"Verification is limited to stored provider/link metadata because no provider token was supplied."}
	}
	if err := ctx.Err(); err != nil {
		return identitydomain.ProviderVerification{}, err
	}
	if in.AccessToken != "" {
		if s.config.LiveProvider == nil {
			checks = append(checks, identitydomain.VerificationCheck{Name: "live_provider_api_configured", Result: "failed"})
			limitations = []string{"A provider access token was supplied, but no live provider API validator is configured."}
		} else {
			live, liveErr := s.config.LiveProvider.ValidateProviderIdentity(ctx, ProviderIdentityValidationRequest{TenantID: a.TenantID, ProviderID: p.ID, ProviderType: p.Type, Issuer: p.Issuer, Subject: in.Subject, GroupsClaim: p.GroupsClaim, AccessToken: in.AccessToken})
			if err := ctx.Err(); err != nil {
				return identitydomain.ProviderVerification{}, err
			}
			limitations = []string{"Live provider API validation used a supplied OIDC access token; no access token is stored in Evydence records."}
			if !validProviderValidationResult(live) {
				liveErr = ErrValidation
			} else {
				checks = append(checks, live.Checks...)
				if len(live.Limitations) > 0 {
					limitations = append([]string(nil), live.Limitations...)
				}
				// Groups are informational here, not an authorization grant. Only
				// successful provider validation may contribute a mapping count.
				groups := credentialSafeStrings(live.Groups, in.IDToken, in.SAMLAssertion, in.AccessToken)
				if n := len(ProviderGroupGrants(p, groups)); liveErr == nil && n > 0 {
					checks = append(checks, identitydomain.VerificationCheck{Name: "mapped_provider_api_groups", Result: "passed", Detail: fmt.Sprintf("%d provider API group role mapping(s) can be applied to sessions", n)})
				}
			}
			if liveErr != nil {
				checks = append(checks, identitydomain.VerificationCheck{Name: "live_provider_api_validation", Result: "error", Detail: "provider API validation did not complete"})
			}
		}
	}
	linkResult := "failed"
	if found && link.Verified {
		linkResult = "passed"
	}
	checks = append(checks, identitydomain.VerificationCheck{Name: "verified_identity_link", Result: linkResult})
	checks = redactedCredentialChecks(checks, in.IDToken, in.SAMLAssertion, in.AccessToken)
	for i := range limitations {
		limitations[i] = redactExactSecrets(limitations[i], in.IDToken, in.SAMLAssertion, in.AccessToken)
	}
	// Redaction can expand bytes or alter an adapter-supplied check label/state.
	// Recheck the complete sanitized assessment, not just the original output.
	if !validProviderValidationText(ProviderIdentityValidationResult{Checks: checks, Limitations: limitations}) {
		checks = []identitydomain.VerificationCheck{{Name: "provider_verification_output", Result: "error", Detail: "provider verification output did not meet the safe receipt contract"}, {Name: "verified_identity_link", Result: linkResult}}
		limitations = []string{"Provider verification output could not be retained safely; no successful credential assessment is claimed."}
	}
	v := identitydomain.ProviderVerification{ID: s.config.IDs.NewID("pvr"), TenantID: a.TenantID, ProviderType: p.Type, ProviderID: p.ID, Subject: in.Subject, Checks: checks, Limitations: limitations, SchemaVersion: identitydomain.ProviderVerificationVersion, CreatedAt: now}
	v = s.config.VerificationPolicy.Assess(cloneProviderVerification(v), cloneSSOProvider(p), in.IDToken != "" || in.SAMLAssertion != "" || in.AccessToken != "")
	err = s.config.Transactions.ExecuteProviderVerification(ctx, func(ctx context.Context, tx ProviderVerificationTransaction) error {
		if ctx == nil || tx == nil {
			return ErrValidation
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := tx.Authorize(ctx, a, membershipAuthorization()); err != nil {
			return err
		}
		if err := tx.ValidateSSOExchangeState(ctx, cloneSSOExchangeSnapshot(snapshot)); err != nil {
			return err
		}
		if err := tx.InsertProviderVerification(ctx, cloneProviderVerification(v)); err != nil {
			return err
		}
		_, err := tx.AppendAudit(ctx, application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "provider_identity.verified", SubjectType: "provider_identity", SubjectID: v.ID, ActorType: actorType(a), ActorID: actorID(a), OccurredAt: now})
		if err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return identitydomain.ProviderVerification{}, err
	}
	if s.config.VerificationPolicy.ReturnsFailure(v.Result) {
		return cloneProviderVerification(v), ErrVerificationFailed
	}
	return cloneProviderVerification(v), nil
}

// Provider adapters must also bound bytes before decoding. This application
// fence prevents malformed or excessive adapter output from becoming a durable
// receipt/replay; it never truncates checks and then claims success.
func validProviderValidationResult(v ProviderIdentityValidationResult) bool {
	if len(v.Checks) == 0 || len(v.Checks) > 256 || len(v.Groups) > 256 || len(v.Limitations) > 256 {
		return false
	}
	return validProviderValidationText(v)
}

func validProviderValidationText(v ProviderIdentityValidationResult) bool {
	bytes := 0
	for _, c := range v.Checks {
		if strings.TrimSpace(c.Name) == "" || !validAPIKeyText(c.Name, 128) || !validAPIKeyText(c.Result, 64) || !validAPIKeyText(c.Detail, 65536) {
			return false
		}
		switch c.Result {
		case "passed", "failed", "warning", "skipped", "error":
		default:
			return false
		}
		bytes += len(c.Name) + len(c.Result) + len(c.Detail)
	}
	for _, v := range v.Groups {
		if !validAPIKeyText(v, 1024) {
			return false
		}
		bytes += len(v)
	}
	for _, v := range v.Limitations {
		if !validAPIKeyText(v, 65536) {
			return false
		}
		bytes += len(v)
	}
	return bytes <= 262144
}
