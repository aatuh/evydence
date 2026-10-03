package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

const userIdentityLinkSchemaVersion = "user-identity-link.v1.0.0"

// GrantTargetResolver validates subjects owned by identity/integration and
// resource targets owned by other contexts without exposing their repositories
// to identity commands.
type GrantTargetResolver interface {
	ValidateSubject(context.Context, string, string, string) error
	ValidateResource(context.Context, string, string, string) error
}

// SessionGrantPolicy maps provider-verified group values to session grants.
// It must ignore unknown groups and invalid roles.
type SessionGrantPolicy interface {
	GrantsForProviderGroups(identitydomain.SSOProvider, []string) []identitydomain.ResourceGrant
}

// TrustMaterialValidator validates and defensively copies provider trust
// material before it enters a command transaction.
type TrustMaterialValidator interface {
	NormalizeJWKS(map[string]any) (map[string]any, error)
	NormalizeSAMLSigningCertificates([]string) ([]string, error)
}

type CanonicalHasher interface {
	Hash(any) (string, error)
}

type OIDCDiscoveryRequest struct {
	TenantID   string
	ProviderID string
	Issuer     string
}

type OIDCDiscoveryResult struct {
	Issuer string
	JWKS   map[string]any
}

type OIDCDiscovery interface {
	FetchOIDCTrustMaterial(context.Context, OIDCDiscoveryRequest) (OIDCDiscoveryResult, error)
}

type CredentialVerificationRequest struct {
	Provider      identitydomain.SSOProvider
	Subject       string
	IDToken       string
	SAMLAssertion string
	Now           time.Time
}

type CredentialVerificationResult struct {
	Checks []identitydomain.VerificationCheck
	// Groups are trusted only after ProviderVerificationPolicy assesses all
	// credential checks as successful.
	Groups []string
}

// SSOExchangeSnapshot captures every mutable identity record used to decide an
// SSO exchange. Repository validation runs inside the write transaction and
// must reject a mismatch (including a previously absent link becoming
// present), while keeping the validated rows/ranges stable through commit.
// UserGrants are compared as a set; their slice order is not significant.
type SSOExchangeSnapshot struct {
	Provider          identitydomain.SSOProvider
	Subject           string
	IdentityLink      identitydomain.UserIdentityLink
	IdentityLinkFound bool
	User              identitydomain.HumanUser
	UserLoaded        bool
	UserFound         bool
	UserGrants        []identitydomain.ResourceGrant
	UserGrantsLoaded  bool
}

// CredentialVerifier validates signatures, issuer, audience/client ID,
// subject, expiry, and verified-email evidence. Implementations must never
// return a raw credential in checks or errors.
type CredentialVerifier interface {
	Verify(context.Context, CredentialVerificationRequest) (CredentialVerificationResult, error)
}

// ProviderVerificationPolicy owns conservative check aggregation and the
// versioned assurance profile attached to a provider verification record.
type ProviderVerificationPolicy interface {
	Assess(identitydomain.ProviderVerification, identitydomain.SSOProvider, bool) identitydomain.ProviderVerification
	ReturnsFailure(string) bool
}

type CreateOrganizationInput struct {
	Name string
	Slug string
}

type CreateUserInput struct {
	OrganizationID string
	Email          string
	DisplayName    string
}

type CreateRoleBindingInput struct {
	SubjectType  string
	SubjectID    string
	Role         string
	ResourceType string
	ResourceID   string
}

type CreateSSOProviderInput struct {
	Name                    string
	Type                    string
	Issuer                  string
	ClientID                string
	GroupsClaim             string
	RoleMapping             map[string]string
	JWKS                    map[string]any
	SAMLSigningCertificates []string
}

type UpdateSSOProviderTrustMaterialInput struct {
	JWKS                    map[string]any
	SAMLSigningCertificates []string
}

type LinkSSOIdentityInput struct {
	UserID     string
	ProviderID string
	Subject    string
	Email      string
	Verified   bool
}

type CreateSSOSessionInput struct {
	UserID     string
	ProviderID string
	ExpiresAt  time.Time
}

type ExchangeSSOCredentialInput struct {
	ProviderID    string
	Subject       string
	IDToken       string
	SAMLAssertion string
	ExpiresAt     time.Time
}

func (s *Service) CreateOrganization(ctx context.Context, actor identitydomain.Actor, input CreateOrganizationInput) (identitydomain.Organization, error) {
	if err := contextError(ctx); err != nil {
		return identitydomain.Organization{}, err
	}
	if err := s.authorizeIdentityAdmin(ctx, actor); err != nil {
		return identitydomain.Organization{}, err
	}
	input, err := normalizeMembershipOrganization(actor.TenantID, input)
	if err != nil {
		return identitydomain.Organization{}, err
	}
	existing, found, err := s.reader.OrganizationBySlug(ctx, actor.TenantID, input.Slug)
	if err != nil {
		return identitydomain.Organization{}, err
	}
	if found {
		if existing.TenantID != actor.TenantID {
			return identitydomain.Organization{}, ErrNotFound
		}
		return identitydomain.Organization{}, ErrConflict
	}
	now := s.clock.Now().UTC()
	organization := identitydomain.Organization{
		ID: s.ids.NewID("org"), TenantID: actor.TenantID, Name: input.Name, Slug: input.Slug,
		Status: "active", SchemaVersion: identitydomain.OrganizationSchemaVersion, CreatedAt: now,
	}
	if err := s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Identity().InsertOrganization(ctx, organization); err != nil {
			return err
		}
		return s.appendActorAudit(ctx, tx, actor, now, "organization.created", "organization", organization.ID, "", "")
	}); err != nil {
		return identitydomain.Organization{}, err
	}
	return organization, nil
}

func (s *Service) CreateUser(ctx context.Context, actor identitydomain.Actor, input CreateUserInput) (identitydomain.HumanUser, error) {
	if err := contextError(ctx); err != nil {
		return identitydomain.HumanUser{}, err
	}
	if err := s.authorizeIdentityAdmin(ctx, actor); err != nil {
		return identitydomain.HumanUser{}, err
	}
	input, err := normalizeMembershipUser(actor.TenantID, input)
	if err != nil {
		return identitydomain.HumanUser{}, err
	}
	if input.OrganizationID != "" {
		organization, err := s.reader.Organization(ctx, actor.TenantID, input.OrganizationID)
		if err != nil {
			return identitydomain.HumanUser{}, err
		}
		if organization.ID != input.OrganizationID || organization.TenantID != actor.TenantID {
			return identitydomain.HumanUser{}, ErrNotFound
		}
	}
	existing, found, err := s.reader.UserByEmail(ctx, actor.TenantID, input.Email)
	if err != nil {
		return identitydomain.HumanUser{}, err
	}
	if found {
		if existing.TenantID != actor.TenantID {
			return identitydomain.HumanUser{}, ErrNotFound
		}
		return identitydomain.HumanUser{}, ErrConflict
	}
	now := s.clock.Now().UTC()
	user := identitydomain.HumanUser{
		ID: s.ids.NewID("usr"), TenantID: actor.TenantID, OrganizationID: input.OrganizationID,
		Email: input.Email, DisplayName: input.DisplayName, Status: "active",
		SchemaVersion: identitydomain.HumanUserSchemaVersion, CreatedAt: now,
	}
	if err := s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Identity().InsertHumanUser(ctx, user); err != nil {
			return err
		}
		return s.appendActorAudit(ctx, tx, actor, now, "user.created", "human_user", user.ID, "", "")
	}); err != nil {
		return identitydomain.HumanUser{}, err
	}
	return user, nil
}

func (s *Service) DeactivateUser(ctx context.Context, actor identitydomain.Actor, id string) (identitydomain.HumanUser, error) {
	if err := contextError(ctx); err != nil {
		return identitydomain.HumanUser{}, err
	}
	if err := s.authorizeIdentityAdmin(ctx, actor); err != nil {
		return identitydomain.HumanUser{}, err
	}
	id = strings.TrimSpace(id)
	user, err := s.reader.User(ctx, actor.TenantID, id)
	if err != nil {
		return identitydomain.HumanUser{}, err
	}
	if user.ID != id || user.TenantID != actor.TenantID {
		return identitydomain.HumanUser{}, ErrNotFound
	}
	if user.Status == "deactivated" {
		return identitydomain.HumanUser{}, ErrConflict
	}
	now := s.clock.Now().UTC()
	user = cloneHumanUser(user)
	user.Status = "deactivated"
	user.DeactivatedAt = &now
	if err := s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Identity().DeactivateHumanUser(ctx, user); err != nil {
			return err
		}
		return s.appendActorAudit(ctx, tx, actor, now, "user.deactivated", "human_user", user.ID, "", "")
	}); err != nil {
		return identitydomain.HumanUser{}, err
	}
	return user, nil
}

func (s *Service) CreateRoleBinding(ctx context.Context, actor identitydomain.Actor, input CreateRoleBindingInput) (identitydomain.RoleBinding, error) {
	if err := contextError(ctx); err != nil {
		return identitydomain.RoleBinding{}, err
	}
	if err := s.authorizeIdentityAdmin(ctx, actor); err != nil {
		return identitydomain.RoleBinding{}, err
	}
	input, err := normalizeRoleBindingInput(actor.TenantID, input)
	if err != nil {
		return identitydomain.RoleBinding{}, err
	}
	if err := s.grantTargets.ValidateSubject(ctx, actor.TenantID, input.SubjectType, input.SubjectID); err != nil {
		return identitydomain.RoleBinding{}, err
	}
	if err := s.grantTargets.ValidateResource(ctx, actor.TenantID, input.ResourceType, input.ResourceID); err != nil {
		return identitydomain.RoleBinding{}, err
	}
	now := s.clock.Now().UTC()
	binding := identitydomain.RoleBinding{
		ID: s.ids.NewID("rbac"), TenantID: actor.TenantID, SubjectType: input.SubjectType,
		SubjectID: input.SubjectID, Role: input.Role, ResourceType: input.ResourceType,
		ResourceID: input.ResourceID, SchemaVersion: identitydomain.RoleBindingSchemaVersion, CreatedAt: now,
	}
	if err := s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Identity().InsertRoleBinding(ctx, binding); err != nil {
			return err
		}
		return s.appendActorAudit(ctx, tx, actor, now, "role_binding.created", "role_binding", binding.ID, "", "")
	}); err != nil {
		return identitydomain.RoleBinding{}, err
	}
	return binding, nil
}

func (s *Service) ListRoleBindings(ctx context.Context, actor identitydomain.Actor) ([]identitydomain.RoleBinding, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := s.authorizeIdentityAdmin(ctx, actor); err != nil {
		return nil, err
	}
	bindings, err := s.reader.ListRoleBindings(ctx, actor.TenantID)
	if err != nil {
		return nil, err
	}
	result := make([]identitydomain.RoleBinding, 0, len(bindings))
	for _, binding := range bindings {
		if binding.TenantID == actor.TenantID {
			result = append(result, binding)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (s *Service) CreateSSOProvider(ctx context.Context, actor identitydomain.Actor, input CreateSSOProviderInput) (identitydomain.SSOProvider, error) {
	if err := contextError(ctx); err != nil {
		return identitydomain.SSOProvider{}, err
	}
	if err := s.authorizeIdentityAdmin(ctx, actor); err != nil {
		return identitydomain.SSOProvider{}, err
	}
	input, err := normalizeSSOProviderInput(input, s.trustMaterial)
	if err != nil {
		return identitydomain.SSOProvider{}, ErrValidation
	}
	now := s.clock.Now().UTC()
	provider := identitydomain.SSOProvider{
		ID: s.ids.NewID("sso"), TenantID: actor.TenantID, Name: input.Name, Type: input.Type,
		Issuer: input.Issuer, ClientID: input.ClientID, GroupsClaim: input.GroupsClaim,
		RoleMapping: cloneStringMap(input.RoleMapping), JWKS: cloneAnyMap(input.JWKS),
		SAMLSigningCertificates: append([]string(nil), input.SAMLSigningCertificates...), Status: "active",
		SchemaVersion: identitydomain.SSOProviderSchemaVersion, CreatedAt: now,
	}
	if err := s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Identity().InsertSSOProvider(ctx, provider); err != nil {
			return err
		}
		return s.appendActorAudit(ctx, tx, actor, now, "sso_provider.created", "sso_provider", provider.ID, "", "")
	}); err != nil {
		return identitydomain.SSOProvider{}, err
	}
	return cloneSSOProvider(provider), nil
}

func (s *Service) UpdateSSOProviderTrustMaterial(ctx context.Context, actor identitydomain.Actor, id string, input UpdateSSOProviderTrustMaterialInput) (identitydomain.SSOProvider, error) {
	if err := contextError(ctx); err != nil {
		return identitydomain.SSOProvider{}, err
	}
	if err := s.authorizeIdentityAdmin(ctx, actor); err != nil {
		return identitydomain.SSOProvider{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return identitydomain.SSOProvider{}, ErrValidation
	}
	jwks, err := s.trustMaterial.NormalizeJWKS(input.JWKS)
	if err != nil {
		return identitydomain.SSOProvider{}, ErrValidation
	}
	certificates, err := s.trustMaterial.NormalizeSAMLSigningCertificates(input.SAMLSigningCertificates)
	if err != nil {
		return identitydomain.SSOProvider{}, ErrValidation
	}
	provider, err := s.reader.SSOProvider(ctx, actor.TenantID, id)
	if err != nil {
		return identitydomain.SSOProvider{}, err
	}
	if provider.ID != id || provider.TenantID != actor.TenantID {
		return identitydomain.SSOProvider{}, ErrNotFound
	}
	expected := cloneSSOProvider(provider)
	provider = cloneSSOProvider(provider)
	switch provider.Type {
	case "oidc":
		if len(jwks) == 0 || len(certificates) != 0 {
			return identitydomain.SSOProvider{}, ErrValidation
		}
		provider.JWKS = cloneAnyMap(jwks)
		provider.SAMLSigningCertificates = nil
	case "saml":
		if len(certificates) == 0 || len(jwks) != 0 {
			return identitydomain.SSOProvider{}, ErrValidation
		}
		provider.JWKS = nil
		provider.SAMLSigningCertificates = append([]string(nil), certificates...)
	default:
		return identitydomain.SSOProvider{}, ErrValidation
	}
	now := s.clock.Now().UTC()
	provider.TrustMaterialUpdatedAt = &now
	payloadHash, err := s.canonicalHasher.Hash(struct {
		ProviderID              string         `json:"provider_id"`
		JWKS                    map[string]any `json:"jwks,omitempty"`
		SAMLSigningCertificates []string       `json:"saml_signing_certificates,omitempty"`
		UpdatedAt               string         `json:"updated_at"`
	}{ProviderID: provider.ID, JWKS: provider.JWKS, SAMLSigningCertificates: provider.SAMLSigningCertificates, UpdatedAt: now.Format(time.RFC3339Nano)})
	if err != nil {
		return identitydomain.SSOProvider{}, err
	}
	if err := s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Identity().CompareAndSwapSSOProviderTrustMaterial(ctx, expected, provider); err != nil {
			return err
		}
		return s.appendActorAudit(ctx, tx, actor, now, "sso_provider.trust_material_updated", "sso_provider", provider.ID, payloadHash, "")
	}); err != nil {
		return identitydomain.SSOProvider{}, err
	}
	return cloneSSOProvider(provider), nil
}

func (s *Service) RefreshSSOProviderOIDCTrustMaterial(ctx context.Context, actor identitydomain.Actor, id string) (identitydomain.SSOProvider, error) {
	if err := contextError(ctx); err != nil {
		return identitydomain.SSOProvider{}, err
	}
	if err := s.authorizeIdentityAdmin(ctx, actor); err != nil {
		return identitydomain.SSOProvider{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" || s.oidcDiscovery == nil {
		return identitydomain.SSOProvider{}, ErrValidation
	}
	provider, err := s.reader.SSOProvider(ctx, actor.TenantID, id)
	if err != nil {
		return identitydomain.SSOProvider{}, err
	}
	if provider.ID != id || provider.TenantID != actor.TenantID {
		return identitydomain.SSOProvider{}, ErrNotFound
	}
	if provider.Type != "oidc" {
		return identitydomain.SSOProvider{}, ErrValidation
	}
	result, err := s.oidcDiscovery.FetchOIDCTrustMaterial(ctx, OIDCDiscoveryRequest{TenantID: actor.TenantID, ProviderID: provider.ID, Issuer: provider.Issuer})
	if err != nil || normalizedIssuer(result.Issuer) != normalizedIssuer(provider.Issuer) {
		return identitydomain.SSOProvider{}, ErrVerificationFailed
	}
	jwks, err := s.trustMaterial.NormalizeJWKS(result.JWKS)
	if err != nil || len(jwks) == 0 {
		return identitydomain.SSOProvider{}, ErrVerificationFailed
	}
	expected := cloneSSOProvider(provider)
	current := cloneSSOProvider(provider)
	now := s.clock.Now().UTC()
	current.JWKS = cloneAnyMap(jwks)
	current.SAMLSigningCertificates = nil
	current.TrustMaterialUpdatedAt = &now
	payloadHash, err := s.canonicalHasher.Hash(struct {
		ProviderID string         `json:"provider_id"`
		Issuer     string         `json:"issuer"`
		JWKS       map[string]any `json:"jwks"`
		UpdatedAt  string         `json:"updated_at"`
	}{ProviderID: current.ID, Issuer: current.Issuer, JWKS: current.JWKS, UpdatedAt: now.Format(time.RFC3339Nano)})
	if err != nil {
		return identitydomain.SSOProvider{}, err
	}
	if err := s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Identity().CompareAndSwapSSOProviderTrustMaterial(ctx, expected, current); err != nil {
			return err
		}
		return s.appendActorAudit(ctx, tx, actor, now, "sso_provider.oidc_trust_material_refreshed", "sso_provider", current.ID, payloadHash, "")
	}); err != nil {
		return identitydomain.SSOProvider{}, err
	}
	return cloneSSOProvider(current), nil
}

func (s *Service) LinkSSOIdentity(ctx context.Context, actor identitydomain.Actor, input LinkSSOIdentityInput) (identitydomain.UserIdentityLink, error) {
	if err := contextError(ctx); err != nil {
		return identitydomain.UserIdentityLink{}, err
	}
	if err := s.authorizeIdentityAdmin(ctx, actor); err != nil {
		return identitydomain.UserIdentityLink{}, err
	}
	input.UserID = strings.TrimSpace(input.UserID)
	input.ProviderID = strings.TrimSpace(input.ProviderID)
	input.Subject = strings.TrimSpace(input.Subject)
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	if input.UserID == "" || input.ProviderID == "" || input.Subject == "" || input.Email == "" || !input.Verified {
		return identitydomain.UserIdentityLink{}, ErrValidation
	}
	user, err := s.reader.User(ctx, actor.TenantID, input.UserID)
	if err != nil {
		return identitydomain.UserIdentityLink{}, err
	}
	if user.ID != input.UserID || user.TenantID != actor.TenantID || user.Email != input.Email {
		return identitydomain.UserIdentityLink{}, ErrNotFound
	}
	provider, err := s.reader.SSOProvider(ctx, actor.TenantID, input.ProviderID)
	if err != nil {
		return identitydomain.UserIdentityLink{}, err
	}
	if provider.ID != input.ProviderID || provider.TenantID != actor.TenantID {
		return identitydomain.UserIdentityLink{}, ErrNotFound
	}
	now := s.clock.Now().UTC()
	link := identitydomain.UserIdentityLink{
		ID: s.ids.NewID("uil"), TenantID: actor.TenantID, UserID: user.ID, ProviderID: provider.ID,
		Subject: input.Subject, Email: input.Email, Verified: true,
		SchemaVersion: userIdentityLinkSchemaVersion, CreatedAt: now,
	}
	if err := s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Identity().InsertUserIdentityLink(ctx, link); err != nil {
			return err
		}
		return s.appendActorAudit(ctx, tx, actor, now, "identity_link.created", "human_user", user.ID, "", "")
	}); err != nil {
		return identitydomain.UserIdentityLink{}, err
	}
	return link, nil
}

func (s *Service) CreateSSOSession(ctx context.Context, actor identitydomain.Actor, input CreateSSOSessionInput) (identitydomain.SSOSession, string, error) {
	if err := contextError(ctx); err != nil {
		return identitydomain.SSOSession{}, "", err
	}
	if err := s.authorizeIdentityAdmin(ctx, actor); err != nil {
		return identitydomain.SSOSession{}, "", err
	}
	input.UserID = strings.TrimSpace(input.UserID)
	input.ProviderID = strings.TrimSpace(input.ProviderID)
	now := s.clock.Now().UTC()
	if input.UserID == "" || input.ProviderID == "" || !input.ExpiresAt.After(now) {
		return identitydomain.SSOSession{}, "", ErrValidation
	}
	user, err := s.reader.User(ctx, actor.TenantID, input.UserID)
	if err != nil {
		return identitydomain.SSOSession{}, "", err
	}
	if user.ID != input.UserID || user.TenantID != actor.TenantID || user.Status != "active" {
		return identitydomain.SSOSession{}, "", ErrNotFound
	}
	provider, err := s.reader.SSOProvider(ctx, actor.TenantID, input.ProviderID)
	if err != nil {
		return identitydomain.SSOSession{}, "", err
	}
	if provider.ID != input.ProviderID || provider.TenantID != actor.TenantID {
		return identitydomain.SSOSession{}, "", ErrNotFound
	}
	credential, err := s.sessionCredentials.GenerateSession()
	if err != nil {
		return identitydomain.SSOSession{}, "", err
	}
	if !validCredential(credential) {
		return identitydomain.SSOSession{}, "", ErrValidation
	}
	session := identitydomain.SSOSession{
		ID: s.ids.NewID("sess"), TenantID: actor.TenantID, UserID: user.ID, ProviderID: provider.ID,
		Prefix: credential.Prefix, ExpiresAt: input.ExpiresAt.UTC(), SchemaVersion: identitydomain.SSOSessionSchemaVersion,
		CreatedAt: now, Hash: credential.Hash,
	}
	if err := s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Identity().InsertSSOSession(ctx, session); err != nil {
			return err
		}
		return s.appendActorAudit(ctx, tx, actor, now, "sso_session.created", "human_user", user.ID, "", "")
	}); err != nil {
		return identitydomain.SSOSession{}, "", err
	}
	return publicSession(session), credential.Secret, nil
}

func (s *Service) ExchangeSSOCredential(ctx context.Context, input ExchangeSSOCredentialInput) (identitydomain.ProviderVerification, identitydomain.SSOSession, string, error) {
	if err := contextError(ctx); err != nil {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
	}
	input.ProviderID = strings.TrimSpace(input.ProviderID)
	input.Subject = strings.TrimSpace(input.Subject)
	input.IDToken = strings.TrimSpace(input.IDToken)
	input.SAMLAssertion = strings.TrimSpace(input.SAMLAssertion)
	if input.ProviderID == "" || input.Subject == "" || (input.IDToken == "" && input.SAMLAssertion == "") || (input.IDToken != "" && input.SAMLAssertion != "") || containsCredential(input.Subject, input.IDToken, input.SAMLAssertion) {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", ErrValidation
	}
	now := s.clock.Now().UTC()
	expiresAt := input.ExpiresAt.UTC()
	if expiresAt.IsZero() {
		expiresAt = now.Add(8 * time.Hour)
	}
	if !expiresAt.After(now) || expiresAt.After(now.Add(12*time.Hour)) {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", ErrValidation
	}
	provider, err := s.reader.SSOProviderByID(ctx, input.ProviderID)
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
	credentialResult, verificationErr := s.credentialVerifier.Verify(ctx, CredentialVerificationRequest{
		Provider: cloneSSOProvider(provider), Subject: input.Subject, IDToken: input.IDToken,
		SAMLAssertion: input.SAMLAssertion, Now: now,
	})
	checks := redactedCredentialChecks(credentialResult.Checks, input.IDToken, input.SAMLAssertion)
	if verificationErr != nil {
		checks = append(checks, identitydomain.VerificationCheck{Name: "credential_verification", Result: "failed", Detail: "credential verification did not complete"})
	}
	link, found, err := s.reader.IdentityLink(ctx, provider.TenantID, provider.ID, input.Subject)
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
		ID: s.ids.NewID("pvr"), TenantID: provider.TenantID, ProviderType: provider.Type,
		ProviderID: provider.ID, Subject: input.Subject, Checks: checks,
		Limitations:   []string{"Credential exchange uses configured local token/assertion trust roots and verified identity links; no live provider API or group synchronization call is made."},
		SchemaVersion: identitydomain.ProviderVerificationVersion, CreatedAt: now,
	}
	verification = s.verificationPolicy.Assess(verification, provider, true)
	if s.verificationPolicy.ReturnsFailure(verification.Result) {
		if err := s.persistProviderVerification(ctx, verification, provider, snapshot); err != nil {
			return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
		}
		return cloneProviderVerification(verification), identitydomain.SSOSession{}, "", ErrVerificationFailed
	}
	user, err := s.reader.User(ctx, provider.TenantID, link.UserID)
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
		verification = s.verificationPolicy.Assess(verification, provider, true)
		if err := s.persistProviderVerification(ctx, verification, provider, snapshot); err != nil {
			return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
		}
		return cloneProviderVerification(verification), identitydomain.SSOSession{}, "", ErrVerificationFailed
	}
	verification.Checks = append(verification.Checks, identitydomain.VerificationCheck{Name: "active_user", Result: "passed"})
	verification = s.verificationPolicy.Assess(verification, provider, true)
	userGrants, err := s.reader.UserGrants(ctx, provider.TenantID, user.ID)
	if err != nil {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
	}
	snapshot.UserGrantsLoaded = true
	snapshot.UserGrants = cloneGrants(userGrants)
	groups := credentialSafeStrings(credentialResult.Groups, input.IDToken, input.SAMLAssertion)
	mappedGroupGrants := cloneGrants(s.sessionGrants.GrantsForProviderGroups(provider, groups))
	grants := append(cloneGrants(userGrants), mappedGroupGrants...)
	if len(scopesFromGrants(grants)) == 0 {
		verification.Checks = append(verification.Checks, identitydomain.VerificationCheck{Name: "authorization_grant", Result: "failed"})
		verification = s.verificationPolicy.Assess(verification, provider, true)
		if err := s.persistProviderVerification(ctx, verification, provider, snapshot); err != nil {
			return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
		}
		return cloneProviderVerification(verification), identitydomain.SSOSession{}, "", ErrForbidden
	}
	if len(groups) > 0 && len(mappedGroupGrants) > 0 {
		verification.Checks = append(verification.Checks, identitydomain.VerificationCheck{
			Name: "mapped_group_roles", Result: "passed",
			Detail: fmt.Sprintf("%d session-scoped provider group role mapping(s) applied", len(mappedGroupGrants)),
		})
		verification = s.verificationPolicy.Assess(verification, provider, true)
	}
	credential, err := s.sessionCredentials.GenerateSession()
	if err != nil {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
	}
	if !validCredential(credential) {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", ErrValidation
	}
	session := identitydomain.SSOSession{
		ID: s.ids.NewID("sess"), TenantID: provider.TenantID, UserID: user.ID, ProviderID: provider.ID,
		Prefix: credential.Prefix, Groups: append([]string(nil), groups...), ExpiresAt: expiresAt,
		SchemaVersion: identitydomain.SSOSessionSchemaVersion, CreatedAt: now, Hash: credential.Hash,
	}
	if err := s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Identity().ValidateSSOExchangeState(ctx, cloneSSOExchangeSnapshot(snapshot)); err != nil {
			return err
		}
		if err := tx.Identity().InsertProviderVerification(ctx, verification); err != nil {
			return err
		}
		if err := s.appendProviderAudit(ctx, tx, provider, now, verification.ID); err != nil {
			return err
		}
		if err := tx.Identity().InsertSSOSession(ctx, session); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, now, provider.TenantID, "sso_session.created", "human_user", user.ID, "sso_provider", provider.ID, "", "")
	}); err != nil {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
	}
	return cloneProviderVerification(verification), publicSession(session), credential.Secret, nil
}

func (s *Service) RevokeSSOSession(ctx context.Context, actor identitydomain.Actor, id string) (identitydomain.SSOSession, error) {
	if err := contextError(ctx); err != nil {
		return identitydomain.SSOSession{}, err
	}
	if err := s.authorizeIdentityAdmin(ctx, actor); err != nil {
		return identitydomain.SSOSession{}, err
	}
	return s.revokeSession(ctx, actor, strings.TrimSpace(id), false)
}

func (s *Service) RevokeCurrentSSOSession(ctx context.Context, actor identitydomain.Actor) (identitydomain.SSOSession, error) {
	if err := contextError(ctx); err != nil {
		return identitydomain.SSOSession{}, err
	}
	if strings.TrimSpace(actor.UserID) == "" || strings.TrimSpace(actor.SessionID) == "" {
		return identitydomain.SSOSession{}, ErrForbidden
	}
	return s.revokeSession(ctx, actor, strings.TrimSpace(actor.SessionID), true)
}

func (s *Service) revokeSession(ctx context.Context, actor identitydomain.Actor, id string, requireSelf bool) (identitydomain.SSOSession, error) {
	session, err := s.reader.SSOSession(ctx, actor.TenantID, id)
	if err != nil {
		return identitydomain.SSOSession{}, err
	}
	if session.ID != id || session.TenantID != actor.TenantID {
		return identitydomain.SSOSession{}, ErrNotFound
	}
	if requireSelf && (session.UserID != actor.UserID || session.ID != actor.SessionID) {
		return identitydomain.SSOSession{}, ErrNotFound
	}
	if session.RevokedAt != nil {
		return identitydomain.SSOSession{}, ErrConflict
	}
	now := s.clock.Now().UTC()
	session = cloneSSOSession(session)
	session.RevokedAt = &now
	if err := s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Identity().RevokeSSOSession(ctx, session); err != nil {
			return err
		}
		return s.appendActorAudit(ctx, tx, actor, now, "sso_session.revoked", "sso_session", session.ID, "", "")
	}); err != nil {
		return identitydomain.SSOSession{}, err
	}
	return publicSession(session), nil
}

func (s *Service) persistProviderVerification(ctx context.Context, verification identitydomain.ProviderVerification, provider identitydomain.SSOProvider, snapshot SSOExchangeSnapshot) error {
	return s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Identity().ValidateSSOExchangeState(ctx, cloneSSOExchangeSnapshot(snapshot)); err != nil {
			return err
		}
		if err := tx.Identity().InsertProviderVerification(ctx, verification); err != nil {
			return err
		}
		return s.appendProviderAudit(ctx, tx, provider, verification.CreatedAt, verification.ID)
	})
}

func (s *Service) appendProviderAudit(ctx context.Context, tx Transaction, provider identitydomain.SSOProvider, now time.Time, verificationID string) error {
	return s.appendAudit(ctx, tx, now, provider.TenantID, "provider_identity.verified", "provider_identity", verificationID, "sso_provider", provider.ID, "", "")
}

func (s *Service) appendActorAudit(ctx context.Context, tx Transaction, actor identitydomain.Actor, now time.Time, entryType, subjectType, subjectID, payloadHash, signatureRef string) error {
	return s.appendAudit(ctx, tx, now, actor.TenantID, entryType, subjectType, subjectID, actorType(actor), actorID(actor), payloadHash, signatureRef)
}

func (s *Service) appendAudit(ctx context.Context, tx Transaction, now time.Time, tenantID, entryType, subjectType, subjectID, auditActorType, auditActorID, payloadHash, signatureRef string) error {
	_, err := tx.Audit().AppendAudit(ctx, application.AuditEvent{
		ID: s.ids.NewID("ace"), TenantID: tenantID, EntryType: entryType, SubjectType: subjectType,
		SubjectID: subjectID, ActorType: auditActorType, ActorID: auditActorID, OccurredAt: now,
		PayloadHash: payloadHash, SignatureRef: signatureRef,
	})
	return err
}

func (s *Service) authorizeIdentityAdmin(ctx context.Context, actor identitydomain.Actor) error {
	return s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeIdentityAdmin, ScopeOnly: true, TenantWide: true})
}

func actorType(actor identitydomain.Actor) string {
	if actor.CollectorID != "" {
		return "collector"
	}
	if actor.UserID != "" {
		return "human_user"
	}
	return "api_key"
}

func actorID(actor identitydomain.Actor) string {
	if actor.CollectorID != "" {
		return actor.CollectorID
	}
	if actor.UserID != "" {
		return actor.UserID
	}
	return actor.KeyID
}

func validRoleSubject(value string) bool { return value == "user" || value == "collector" }

func validRole(value string) bool {
	switch value {
	case "tenant_admin", "security_engineer", "release_manager", "customer_verifier", "collector":
		return true
	default:
		return false
	}
}

func validSSOType(value string) bool { return value == "oidc" || value == "saml" }

func normalizedIssuer(value string) string { return strings.TrimRight(strings.TrimSpace(value), "/") }

func validCredential(value Credential) bool {
	return strings.TrimSpace(value.Secret) != "" && strings.TrimSpace(value.Prefix) != "" && strings.TrimSpace(value.Hash) != ""
}

func publicSession(value identitydomain.SSOSession) identitydomain.SSOSession {
	value = cloneSSOSession(value)
	value.Hash = ""
	return value
}

func cloneHumanUser(value identitydomain.HumanUser) identitydomain.HumanUser {
	value.DeactivatedAt = cloneTime(value.DeactivatedAt)
	return value
}

func cloneSSOSession(value identitydomain.SSOSession) identitydomain.SSOSession {
	value.Groups = append([]string(nil), value.Groups...)
	value.RevokedAt = cloneTime(value.RevokedAt)
	return value
}

func cloneSSOProvider(value identitydomain.SSOProvider) identitydomain.SSOProvider {
	value.RoleMapping = cloneStringMap(value.RoleMapping)
	value.JWKS = cloneAnyMap(value.JWKS)
	value.SAMLSigningCertificates = append([]string(nil), value.SAMLSigningCertificates...)
	value.TrustMaterialUpdatedAt = cloneTime(value.TrustMaterialUpdatedAt)
	return value
}

func cloneProviderVerification(value identitydomain.ProviderVerification) identitydomain.ProviderVerification {
	value.Checks = cloneVerificationChecks(value.Checks)
	value.Profile.RequiredChecks = append([]string(nil), value.Profile.RequiredChecks...)
	value.Profile.TrustMaterial = append([]string(nil), value.Profile.TrustMaterial...)
	value.Profile.Limitations = append([]string(nil), value.Profile.Limitations...)
	value.Limitations = append([]string(nil), value.Limitations...)
	return value
}

func cloneSSOExchangeSnapshot(value SSOExchangeSnapshot) SSOExchangeSnapshot {
	value.Provider = cloneSSOProvider(value.Provider)
	value.User = cloneHumanUser(value.User)
	value.UserGrants = cloneGrants(value.UserGrants)
	return value
}

func cloneVerificationChecks(values []identitydomain.VerificationCheck) []identitydomain.VerificationCheck {
	return append([]identitydomain.VerificationCheck(nil), values...)
}

func redactedCredentialChecks(values []identitydomain.VerificationCheck, credentials ...string) []identitydomain.VerificationCheck {
	result := cloneVerificationChecks(values)
	for index := range result {
		result[index].Name = redactExactSecrets(result[index].Name, credentials...)
		result[index].Result = redactExactSecrets(result[index].Result, credentials...)
		result[index].Detail = redactExactSecrets(result[index].Detail, credentials...)
	}
	return result
}

func redactExactSecrets(value string, secrets ...string) string {
	for _, secret := range secrets {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[redacted]")
		}
	}
	return value
}

func credentialSafeStrings(values []string, credentials ...string) []string {
	safe := make([]string, 0, len(values))
	for _, value := range values {
		if !containsCredential(value, credentials...) {
			safe = append(safe, value)
		}
	}
	return sortedUniqueStrings(safe)
}

func containsCredential(value string, credentials ...string) bool {
	for _, credential := range credentials {
		if credential != "" && strings.Contains(value, credential) {
			return true
		}
	}
	return false
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func cloneAnyMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]any, len(values))
	for key, value := range values {
		result[key] = cloneAny(value)
	}
	return result
}

func cloneAny(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneAnyMap(typed)
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = cloneAny(item)
		}
		return result
	case []string:
		return append([]string(nil), typed...)
	default:
		return typed
	}
}

func sortedUniqueStrings(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
