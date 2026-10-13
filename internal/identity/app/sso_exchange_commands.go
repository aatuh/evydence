package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
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
	OIDCAuthenticationRequestConsumer
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
	Reader                 SSOExchangeReader
	Transactions           SSOExchangeTransactions
	Credentials            SessionCredentialManager
	Verifier               CredentialVerifier
	VerificationPolicy     ProviderVerificationPolicy
	SessionGrants          SessionGrantPolicy
	Clock                  application.Clock
	IDs                    application.IDGenerator
	SessionPolicy          identitydomain.SessionPolicy
	AuthenticationRequests OIDCAuthenticationRequestReader
	ProofCredentials       AuthenticationCredentials
}
type SSOExchangeCommands struct{ config SSOExchangeCommandConfig }

func NewSSOExchangeCommands(c SSOExchangeCommandConfig) (*SSOExchangeCommands, error) {
	if c.Reader == nil || c.Transactions == nil || c.Credentials == nil || c.Verifier == nil || c.VerificationPolicy == nil || c.SessionGrants == nil || c.Clock == nil || c.IDs == nil || c.AuthenticationRequests == nil || c.ProofCredentials == nil {
		return nil, ErrValidation
	}
	policy, ok := c.SessionPolicy.Normalized()
	if !ok {
		return nil, ErrValidation
	}
	c.SessionPolicy = policy
	return &SSOExchangeCommands{config: c}, nil
}

// ExchangeSSOCredential verifies local configured trust before opening the write
// transaction. It is intentionally not an idempotency replay surface: incoming
// credentials and issued secrets must never enter a replay receipt. OIDC
// exchanges consume server-owned authentication state exactly once.
func (s *SSOExchangeCommands) ExchangeSSOCredential(ctx context.Context, input ExchangeSSOCredentialInput) (identitydomain.ProviderVerification, identitydomain.SSOSession, string, error) {
	if s == nil || ctx == nil {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
	}
	if !validAPIKeyText(input.ProviderID, 1024) || !validAPIKeyText(input.Subject, 65536) || !validAPIKeyText(input.IDToken, 65536) || !validAPIKeyText(input.SAMLAssertion, 65536) || !validAPIKeyText(input.AuthenticationRequestID, 1024) || !validAPIKeyText(input.StateSecret, 128) || !validAPIKeyText(input.Delivery, 16) || (!input.ExpiresAt.IsZero() && !validAPIKeyTime(input.ExpiresAt)) {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", ErrValidation
	}
	input.ProviderID = strings.TrimSpace(input.ProviderID)
	input.Subject = strings.TrimSpace(input.Subject)
	input.IDToken = strings.TrimSpace(input.IDToken)
	input.SAMLAssertion = strings.TrimSpace(input.SAMLAssertion)
	if input.ProviderID == "" || input.Subject == "" || (input.IDToken == "" && input.SAMLAssertion == "") || (input.IDToken != "" && input.SAMLAssertion != "") || containsCredential(input.Subject, input.IDToken, input.SAMLAssertion, input.StateSecret) {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", ErrValidation
	}
	now := s.config.Clock.Now().UTC()
	expiresAt := input.ExpiresAt.UTC()
	if now.IsZero() || !validAPIKeyTime(now) || (!expiresAt.IsZero() && !validAPIKeyTime(expiresAt)) {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", ErrValidation
	}
	if expiresAt.IsZero() {
		expiresAt = now.Add(8 * time.Hour)
		if expiresAt.After(now.Add(s.config.SessionPolicy.MaximumLifetime)) {
			expiresAt = now.Add(s.config.SessionPolicy.MaximumLifetime)
		}
	}
	if !validAPIKeyTime(expiresAt) || !expiresAt.After(now) || expiresAt.After(now.Add(s.config.SessionPolicy.MaximumLifetime)) {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", ErrValidation
	}
	provider, err := s.config.Reader.SSOProviderByID(ctx, input.ProviderID)
	if err != nil {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
	}
	providerBinding := authz.SSOExchangeProvider{ID: provider.ID, TenantID: provider.TenantID, Status: provider.Status}
	if err := authz.CheckSSOExchangeProvider(ctx, providerBinding, input.ProviderID); err != nil {
		if errors.Is(err, authz.ErrNotFound) {
			return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", ErrNotFound
		}
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
	}
	if (provider.Type == "oidc" && input.SAMLAssertion != "") || (provider.Type == "saml" && input.IDToken != "") {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", ErrValidation
	}
	if provider.Type != "oidc" && (input.AuthenticationRequestID != "" || input.StateSecret != "" || input.Delivery == "browser") {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", ErrValidation
	}
	provider = cloneSSOProvider(provider)
	snapshot := SSOExchangeSnapshot{Provider: cloneSSOProvider(provider), Subject: input.Subject}
	if provider.Type == "oidc" {
		request, err := s.boundOIDCRequest(ctx, provider, input, now)
		if err != nil {
			return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
		}
		snapshot.AuthenticationRequest = &request
	}
	credentialResult, verificationErr := s.config.Verifier.Verify(ctx, CredentialVerificationRequest{
		Provider: cloneSSOProvider(provider), Subject: input.Subject, IDToken: input.IDToken,
		SAMLAssertion: input.SAMLAssertion, Now: now,
	})
	if err := ctx.Err(); err != nil {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
	}
	checks := redactedCredentialChecks(credentialResult.Checks, input.IDToken, input.SAMLAssertion, input.StateSecret, credentialResult.Nonce)
	if provider.Type == "oidc" && verificationErr == nil {
		request := snapshot.AuthenticationRequest
		if credentialResult.Nonce == "" || containsCredential(input.Subject, credentialResult.Nonce) || !s.config.ProofCredentials.Equal(request.NonceHash, s.config.ProofCredentials.Hash(credentialResult.Nonce)) || credentialResult.IssuedAt.IsZero() || credentialResult.IssuedAt.Before(request.CreatedAt.Add(-time.Minute)) || credentialResult.IssuedAt.After(now.Add(time.Minute)) || !credentialResult.ExpiresAt.After(now) {
			return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", ErrUnauthorized
		}
		verified := len(credentialResult.Checks) > 0
		for _, check := range credentialResult.Checks {
			verified = verified && check.Result == "passed"
		}
		if verified {
			checks = append(checks, identitydomain.VerificationCheck{Name: "nonce_state_binding", Result: "passed"})
			snapshot.ProofExpiresAt = credentialResult.ExpiresAt
		}
	}
	credentialChecks := make([]string, len(checks))
	for i, check := range checks {
		credentialChecks[i] = check.Result
	}
	if verificationErr != nil {
		checks = append(checks, identitydomain.VerificationCheck{Name: "credential_verification", Result: "failed", Detail: "credential verification did not complete"})
	}
	link, found, err := s.config.Reader.IdentityLink(ctx, provider.TenantID, provider.ID, input.Subject)
	if err != nil {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
	}
	linkBinding := authz.SSOExchangeLink{ID: link.ID, TenantID: link.TenantID, ProviderID: link.ProviderID, UserID: link.UserID, Subject: link.Subject, Verified: link.Verified}
	linkAuthority := authz.CheckSSOExchangeLink(ctx, providerBinding, input.Subject, linkBinding, found)
	if linkAuthority != nil {
		if !errors.Is(linkAuthority, authz.ErrUnauthorized) {
			return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", linkAuthority
		}
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
	credentialAuthority := authz.CheckSSOCredentialVerification(ctx, verification.Result, verificationErr == nil, credentialChecks)
	if credentialAuthority != nil && !errors.Is(credentialAuthority, authz.ErrUnauthorized) {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", credentialAuthority
	}
	if s.config.VerificationPolicy.ReturnsFailure(verification.Result) || credentialAuthority != nil || linkAuthority != nil {
		if !s.config.VerificationPolicy.ReturnsFailure(verification.Result) {
			verification.Checks = append(verification.Checks, identitydomain.VerificationCheck{Name: "credential_authority", Result: "failed"})
			verification = s.assess(verification, provider)
		}
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
	userBinding := authz.SSOExchangeUser{ID: user.ID, TenantID: user.TenantID, Status: user.Status}
	if authorityErr := authz.CheckSSOExchangeUser(ctx, providerBinding, linkBinding, userBinding, err == nil); authorityErr != nil {
		if !errors.Is(authorityErr, authz.ErrUnauthorized) {
			return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", authorityErr
		}
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
	groups := credentialSafeStrings(credentialResult.Groups, input.IDToken, input.SAMLAssertion, input.StateSecret, credentialResult.Nonce)
	mappedGroupGrants := cloneGrants(s.config.SessionGrants.GrantsForProviderGroups(cloneSSOProvider(provider), append([]string(nil), groups...)))
	grants := append(cloneGrants(userGrants), mappedGroupGrants...)
	policy := authz.SSOExchangeRequest{Action: authz.ActionSSOCredentialsExchange, ProviderID: input.ProviderID, Subject: input.Subject, Provider: providerBinding, Link: linkBinding, User: userBinding, LinkFound: found, UserFound: snapshot.UserFound, VerificationResult: verification.Result, CredentialChecks: credentialChecks, VerifierCompleted: verificationErr == nil, HasCapabilities: len(scopesFromGrants(grants)) != 0}
	if authorityErr := authz.AuthorizeSSOExchange(ctx, policy); authorityErr != nil {
		if !errors.Is(authorityErr, authz.ErrForbidden) {
			if errors.Is(authorityErr, authz.ErrUnauthorized) || errors.Is(authorityErr, authz.ErrNotFound) {
				return s.persistDenied(ctx, verification, snapshot, ErrVerificationFailed)
			}
			return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", authorityErr
		}
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
	if !validIssuedSessionCredential(credential) {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", ErrValidation
	}
	session := identitydomain.SSOSession{
		ID: s.config.IDs.NewID("sess"), TenantID: provider.TenantID, UserID: user.ID, ProviderID: provider.ID,
		Prefix: credential.Prefix, Groups: append([]string(nil), groups...), ExpiresAt: expiresAt,
		SchemaVersion: identitydomain.SSOSessionSchemaVersion, CreatedAt: now, Hash: credential.Hash,
	}
	session.LastUsedAt = &now
	session.MaximumLifetimeSeconds = int64(s.config.SessionPolicy.MaximumLifetime / time.Second)
	session.IdleTimeoutSeconds = int64(s.config.SessionPolicy.IdleTimeout / time.Second)
	if err := s.execute(ctx, snapshot, func(ctx context.Context, tx SSOExchangeTransaction) error {
		policy.VerificationResult = verification.Result
		if err := authz.AuthorizeSSOExchange(ctx, policy); err != nil {
			return err
		}
		at := s.config.Clock.Now().UTC()
		if !validAPIKeyTime(at) {
			return ErrValidation
		}
		if err := authz.CheckSSOExchangeSessionLifetime(ctx, now, expiresAt, at); err != nil {
			if errors.Is(err, authz.ErrUnauthorized) {
				return ErrValidation
			}
			return err
		}
		if err := s.writeVerification(ctx, tx, verification); err != nil {
			return err
		}
		if err := tx.InsertSSOSession(ctx, cloneSSOSession(session)); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, now, provider.TenantID, "sso_session.created", "human_user", user.ID, provider.ID); err != nil {
			return err
		}
		if !session.ActiveAt(s.config.Clock.Now().UTC()) {
			return ErrValidation
		}
		return nil
	}); err != nil {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
	}
	if !session.ActiveAt(s.config.Clock.Now().UTC()) {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", ErrValidation
	}
	if snapshot.AuthenticationRequest != nil && (!snapshot.ProofExpiresAt.After(s.config.Clock.Now().UTC()) || !snapshot.AuthenticationRequest.ExpiresAt.After(s.config.Clock.Now().UTC())) {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", ErrUnauthorized
	}
	return cloneProviderVerification(verification), publicSession(session), credential.Secret, nil
}

func (s *SSOExchangeCommands) boundOIDCRequest(ctx context.Context, p identitydomain.SSOProvider, in ExchangeSSOCredentialInput, now time.Time) (identitydomain.OIDCAuthenticationRequest, error) {
	id := strings.TrimSpace(in.AuthenticationRequestID)
	if id == "" || in.StateSecret == "" {
		return identitydomain.OIDCAuthenticationRequest{}, ErrUnauthorized
	}
	if len(in.StateSecret) != len("evylogin_")+43 || !strings.HasPrefix(in.StateSecret, "evylogin_") || !validIssuedOIDCCredential(Credential{Secret: in.StateSecret, Prefix: in.StateSecret[:12], Hash: s.config.ProofCredentials.Hash(in.StateSecret)}, "evylogin_") {
		return identitydomain.OIDCAuthenticationRequest{}, ErrUnauthorized
	}
	delivery := in.Delivery
	if delivery == "" {
		delivery = "api"
	}
	if delivery != "api" && delivery != "browser" {
		return identitydomain.OIDCAuthenticationRequest{}, ErrValidation
	}
	r, err := s.config.AuthenticationRequests.ReadOIDCAuthenticationRequest(ctx, p.TenantID, p.ID, id)
	if err != nil {
		return identitydomain.OIDCAuthenticationRequest{}, authenticationError(ctx)
	}
	fingerprint, err := OIDCProviderTrustFingerprint(p)
	if err != nil || r.ID != id || r.TenantID != p.TenantID || r.ProviderID != p.ID || r.Delivery != delivery || r.TrustFingerprint != fingerprint || !r.PendingAt(now) || !s.config.ProofCredentials.Equal(r.StateHash, s.config.ProofCredentials.Hash(in.StateSecret)) {
		return identitydomain.OIDCAuthenticationRequest{}, ErrUnauthorized
	}
	return r, nil
}

func (s *SSOExchangeCommands) assess(v identitydomain.ProviderVerification, p identitydomain.SSOProvider) identitydomain.ProviderVerification {
	return s.config.VerificationPolicy.Assess(cloneProviderVerification(v), cloneSSOProvider(p), true)
}
func (s *SSOExchangeCommands) execute(ctx context.Context, snapshot SSOExchangeSnapshot, fn func(context.Context, SSOExchangeTransaction) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := s.config.Transactions.ExecuteSSOExchange(ctx, func(ctx context.Context, tx SSOExchangeTransaction) error {
		if ctx == nil || tx == nil {
			return ErrValidation
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := tx.ValidateSSOExchangeState(ctx, cloneSSOExchangeSnapshot(snapshot)); err != nil {
			return err
		}
		consume := snapshot.AuthenticationRequest != nil && !snapshot.ProofExpiresAt.IsZero()
		var consumedAt time.Time
		if consume {
			var err error
			consumedAt, err = tx.ConsumeOIDCAuthenticationRequest(ctx, *snapshot.AuthenticationRequest, s.config.Clock)
			if err != nil {
				return err
			}
			if !snapshot.ProofExpiresAt.After(consumedAt) {
				return ErrUnauthorized
			}
		}
		if err := fn(ctx, tx); err != nil {
			return err
		}
		if consume {
			request := snapshot.AuthenticationRequest
			if err := s.appendAudit(ctx, tx, consumedAt, request.TenantID, "oidc_authentication_request.consumed", "oidc_authentication_request", request.ID, request.ProviderID); err != nil {
				return err
			}
			if !snapshot.ProofExpiresAt.After(s.config.Clock.Now().UTC()) || !request.ExpiresAt.After(s.config.Clock.Now().UTC()) {
				return ErrUnauthorized
			}
		}
		return ctx.Err()
	})
	if err != nil {
		return err
	}
	return ctx.Err()
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
	identity Repository
	application.AuditAppender
}

func (t serviceSSOExchangeTransactions) ExecuteSSOExchange(ctx context.Context, fn func(context.Context, SSOExchangeTransaction) error) error {
	return t.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if tx == nil || tx.Identity() == nil || tx.Audit() == nil {
			return ErrValidation
		}
		return fn(ctx, serviceSSOExchangeTransaction{identity: tx.Identity(), AuditAppender: tx.Audit()})
	})
}

func (t serviceSSOExchangeTransaction) ValidateSSOExchangeState(ctx context.Context, s SSOExchangeSnapshot) error {
	return t.identity.ValidateSSOExchangeState(ctx, s)
}
func (t serviceSSOExchangeTransaction) InsertProviderVerification(ctx context.Context, v identitydomain.ProviderVerification) error {
	return t.identity.InsertProviderVerification(ctx, v)
}
func (t serviceSSOExchangeTransaction) InsertSSOSession(ctx context.Context, v identitydomain.SSOSession) error {
	return t.identity.InsertSSOSession(ctx, v)
}
func (t serviceSSOExchangeTransaction) ConsumeOIDCAuthenticationRequest(ctx context.Context, v identitydomain.OIDCAuthenticationRequest, c application.Clock) (time.Time, error) {
	consumer, ok := t.identity.(OIDCAuthenticationRequestConsumer)
	if !ok {
		return time.Time{}, ErrValidation
	}
	return consumer.ConsumeOIDCAuthenticationRequest(ctx, v, c)
}

type serviceOIDCRequestReader struct{ reader Reader }

func (r serviceOIDCRequestReader) ReadOIDCAuthenticationRequest(ctx context.Context, tenant, provider, id string) (identitydomain.OIDCAuthenticationRequest, error) {
	reader, ok := r.reader.(OIDCAuthenticationRequestReader)
	if !ok {
		return identitydomain.OIDCAuthenticationRequest{}, ErrValidation
	}
	return reader.ReadOIDCAuthenticationRequest(ctx, tenant, provider, id)
}
