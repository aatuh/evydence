package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// SSOExchangeReader reads only the identity coordinates involved in a login.
// The provider ID is the public exchange coordinate; all subsequent reads
// must be scoped to that provider's tenant. Durable adapters must bound rows
// and payload bytes, and reject excess rather than truncate authorization data.
type SSOExchangeReader interface {
	SSOProviderByID(context.Context, string) (identitydomain.SSOProvider, error)
	IdentityLink(context.Context, string, string, string) (identitydomain.UserIdentityLink, bool, error)
	User(context.Context, string, string) (identitydomain.HumanUser, error)
	UserGrants(context.Context, string, string) ([]identitydomain.ResourceGrant, error)
}

type SSOExchangeWrites interface {
	// Recheck and hold every loaded snapshot coordinate stable through commit.
	ValidateSSOExchangeState(context.Context, SSOExchangeSnapshot) error
	InsertProviderVerification(context.Context, identitydomain.ProviderVerification) error
	InsertSSOSession(context.Context, identitydomain.SSOSession) error
}
type SSOExchangeTransaction interface {
	SSOExchangeWrites
	application.AuditAppender
}
type SSOExchangeTransactions interface {
	ExecuteSSOExchange(context.Context, func(context.Context, SSOExchangeTransaction) error) error
}
type SSOExchangeCommandConfig struct {
	Reader             SSOExchangeReader
	Transactions       SSOExchangeTransactions
	Credentials        SessionCredentialManager
	Verifier           CredentialVerifier
	VerificationPolicy ProviderVerificationPolicy
	SessionGrants      SessionGrantPolicy
	Clock              application.Clock
	IDs                application.IDGenerator
}
type SSOExchangeCommands struct{ config SSOExchangeCommandConfig }

func NewSSOExchangeCommands(c SSOExchangeCommandConfig) (*SSOExchangeCommands, error) {
	if c.Reader == nil || c.Transactions == nil || c.Credentials == nil || c.Verifier == nil || c.VerificationPolicy == nil || c.SessionGrants == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &SSOExchangeCommands{config: c}, nil
}

// ExchangeSSOCredential verifies local configured trust before opening the write
// transaction. It is intentionally not an idempotency replay surface: incoming
// credentials and issued secrets must never enter a replay receipt. A repeated
// valid request may issue another session, as in the existing API contract.
func (s *SSOExchangeCommands) ExchangeSSOCredential(ctx context.Context, input ExchangeSSOCredentialInput) (identitydomain.ProviderVerification, identitydomain.SSOSession, string, error) {
	if s == nil || ctx == nil {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
	}
	input.ProviderID = strings.TrimSpace(input.ProviderID)
	input.Subject = strings.TrimSpace(input.Subject)
	input.IDToken = strings.TrimSpace(input.IDToken)
	input.SAMLAssertion = strings.TrimSpace(input.SAMLAssertion)
	if input.ProviderID == "" || input.Subject == "" || (input.IDToken == "" && input.SAMLAssertion == "") || (input.IDToken != "" && input.SAMLAssertion != "") || containsCredential(input.Subject, input.IDToken, input.SAMLAssertion) {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", ErrValidation
	}
	now := s.config.Clock.Now().UTC()
	expiresAt := input.ExpiresAt.UTC()
	if expiresAt.IsZero() {
		expiresAt = now.Add(8 * time.Hour)
	}
	if !expiresAt.After(now) || expiresAt.After(now.Add(12*time.Hour)) {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", ErrValidation
	}
	provider, err := s.config.Reader.SSOProviderByID(ctx, input.ProviderID)
	if err != nil {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
	}
	if provider.ID != input.ProviderID || provider.TenantID == "" || provider.Status != "active" {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", ErrNotFound
	}
	if (provider.Type == "oidc" && input.SAMLAssertion != "") || (provider.Type == "saml" && input.IDToken != "") {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", ErrValidation
	}
	provider = cloneSSOProvider(provider)
	snapshot := SSOExchangeSnapshot{Provider: cloneSSOProvider(provider), Subject: input.Subject}
	credentialResult, verificationErr := s.config.Verifier.Verify(ctx, CredentialVerificationRequest{
		Provider: cloneSSOProvider(provider), Subject: input.Subject, IDToken: input.IDToken,
		SAMLAssertion: input.SAMLAssertion, Now: now,
	})
	if err := ctx.Err(); err != nil {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
	}
	checks := redactedCredentialChecks(credentialResult.Checks, input.IDToken, input.SAMLAssertion)
	if verificationErr != nil {
		checks = append(checks, identitydomain.VerificationCheck{Name: "credential_verification", Result: "failed", Detail: "credential verification did not complete"})
	}
	link, found, err := s.config.Reader.IdentityLink(ctx, provider.TenantID, provider.ID, input.Subject)
	if err != nil {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
	}
	if !found || link.TenantID != provider.TenantID || link.ProviderID != provider.ID || link.Subject != input.Subject || !link.Verified {
		checks = append(checks, identitydomain.VerificationCheck{Name: "verified_identity_link", Result: "failed"})
	} else {
		checks = append(checks, identitydomain.VerificationCheck{Name: "verified_identity_link", Result: "passed"})
	}
	snapshot.IdentityLinkFound = found
	if found {
		snapshot.IdentityLink = link
	}
	verification := identitydomain.ProviderVerification{
		ID: s.config.IDs.NewID("pvr"), TenantID: provider.TenantID, ProviderType: provider.Type,
		ProviderID: provider.ID, Subject: input.Subject, Checks: checks,
		Limitations:   []string{"Credential exchange uses configured local token/assertion trust roots and verified identity links; no live provider API or group synchronization call is made."},
		SchemaVersion: identitydomain.ProviderVerificationVersion, CreatedAt: now,
	}
	verification = s.assess(verification, provider)
	if s.config.VerificationPolicy.ReturnsFailure(verification.Result) {
		return s.persistDenied(ctx, verification, snapshot, ErrVerificationFailed)
	}
	user, err := s.config.Reader.User(ctx, provider.TenantID, link.UserID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
	}
	snapshot.UserLoaded = true
	if err == nil {
		snapshot.UserFound = true
		snapshot.User = cloneHumanUser(user)
	}
	if err != nil || user.ID != link.UserID || user.TenantID != provider.TenantID || user.Status != "active" {
		verification.Checks = append(verification.Checks, identitydomain.VerificationCheck{Name: "active_user", Result: "failed"})
		verification = s.assess(verification, provider)
		return s.persistDenied(ctx, verification, snapshot, ErrVerificationFailed)
	}
	verification.Checks = append(verification.Checks, identitydomain.VerificationCheck{Name: "active_user", Result: "passed"})
	verification = s.assess(verification, provider)
	userGrants, err := s.config.Reader.UserGrants(ctx, provider.TenantID, user.ID)
	if err != nil {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
	}
	snapshot.UserGrantsLoaded = true
	snapshot.UserGrants = cloneGrants(userGrants)
	groups := credentialSafeStrings(credentialResult.Groups, input.IDToken, input.SAMLAssertion)
	mappedGroupGrants := cloneGrants(s.config.SessionGrants.GrantsForProviderGroups(cloneSSOProvider(provider), append([]string(nil), groups...)))
	grants := append(cloneGrants(userGrants), mappedGroupGrants...)
	if len(scopesFromGrants(grants)) == 0 {
		verification.Checks = append(verification.Checks, identitydomain.VerificationCheck{Name: "authorization_grant", Result: "failed"})
		verification = s.assess(verification, provider)
		return s.persistDenied(ctx, verification, snapshot, ErrForbidden)
	}
	if len(groups) > 0 && len(mappedGroupGrants) > 0 {
		verification.Checks = append(verification.Checks, identitydomain.VerificationCheck{
			Name: "mapped_group_roles", Result: "passed",
			Detail: fmt.Sprintf("%d session-scoped provider group role mapping(s) applied", len(mappedGroupGrants)),
		})
		verification = s.assess(verification, provider)
	}
	if err := ctx.Err(); err != nil {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
	}
	credential, err := s.config.Credentials.GenerateSession()
	if err != nil {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
	}
	if !validCredential(credential) {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", ErrValidation
	}
	session := identitydomain.SSOSession{
		ID: s.config.IDs.NewID("sess"), TenantID: provider.TenantID, UserID: user.ID, ProviderID: provider.ID,
		Prefix: credential.Prefix, Groups: append([]string(nil), groups...), ExpiresAt: expiresAt,
		SchemaVersion: identitydomain.SSOSessionSchemaVersion, CreatedAt: now, Hash: credential.Hash,
	}
	if err := s.execute(ctx, snapshot, func(ctx context.Context, tx SSOExchangeTransaction) error {
		if err := s.writeVerification(ctx, tx, verification); err != nil {
			return err
		}
		if err := tx.InsertSSOSession(ctx, cloneSSOSession(session)); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, now, provider.TenantID, "sso_session.created", "human_user", user.ID, provider.ID)
	}); err != nil {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
	}
	return cloneProviderVerification(verification), publicSession(session), credential.Secret, nil
}

func (s *SSOExchangeCommands) assess(v identitydomain.ProviderVerification, p identitydomain.SSOProvider) identitydomain.ProviderVerification {
	return s.config.VerificationPolicy.Assess(cloneProviderVerification(v), cloneSSOProvider(p), true)
}
func (s *SSOExchangeCommands) execute(ctx context.Context, snapshot SSOExchangeSnapshot, fn func(context.Context, SSOExchangeTransaction) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.config.Transactions.ExecuteSSOExchange(ctx, func(ctx context.Context, tx SSOExchangeTransaction) error {
		if ctx == nil || tx == nil {
			return ErrValidation
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := tx.ValidateSSOExchangeState(ctx, cloneSSOExchangeSnapshot(snapshot)); err != nil {
			return err
		}
		if err := fn(ctx, tx); err != nil {
			return err
		}
		return ctx.Err()
	})
}
func (s *SSOExchangeCommands) persistDenied(ctx context.Context, v identitydomain.ProviderVerification, snapshot SSOExchangeSnapshot, denial error) (identitydomain.ProviderVerification, identitydomain.SSOSession, string, error) {
	if err := s.execute(ctx, snapshot, func(ctx context.Context, tx SSOExchangeTransaction) error { return s.writeVerification(ctx, tx, v) }); err != nil {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
	}
	return cloneProviderVerification(v), identitydomain.SSOSession{}, "", denial
}
func (s *SSOExchangeCommands) writeVerification(ctx context.Context, tx SSOExchangeTransaction, v identitydomain.ProviderVerification) error {
	if err := tx.InsertProviderVerification(ctx, cloneProviderVerification(v)); err != nil {
		return err
	}
	return s.appendAudit(ctx, tx, v.CreatedAt, v.TenantID, "provider_identity.verified", "provider_identity", v.ID, v.ProviderID)
}
func (s *SSOExchangeCommands) appendAudit(ctx context.Context, tx SSOExchangeTransaction, now time.Time, tenant, kind, subjectType, subjectID, providerID string) error {
	_, err := tx.AppendAudit(ctx, application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: tenant, EntryType: kind, SubjectType: subjectType, SubjectID: subjectID, ActorType: "sso_provider", ActorID: providerID, OccurredAt: now})
	return err
}

// Adapt the explicit local/legacy identity transaction to the focused port.
// Production composition can provide SSOExchangeTransactions directly without
// constructing Service or configuring its unrelated authentication/admin ports.
type serviceSSOExchangeTransactions struct{ transactions TransactionRunner }
type serviceSSOExchangeTransaction struct {
	SSOExchangeWrites
	application.AuditAppender
}

func (t serviceSSOExchangeTransactions) ExecuteSSOExchange(ctx context.Context, fn func(context.Context, SSOExchangeTransaction) error) error {
	return t.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if tx == nil || tx.Identity() == nil || tx.Audit() == nil {
			return ErrValidation
		}
		return fn(ctx, serviceSSOExchangeTransaction{SSOExchangeWrites: tx.Identity(), AuditAppender: tx.Audit()})
	})
}
