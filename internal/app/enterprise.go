package app

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

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

type CreateLegalHoldInput struct {
	ScopeType string
	ScopeID   string
	Reason    string
	Owner     string
}

type CreateRetentionOverrideInput struct {
	ScopeType      string
	ScopeID        string
	RetentionUntil time.Time
	Reason         string
	Owner          string
}

type CreateCustomerPortalAccessInput struct {
	PackageID     string
	CustomerName  string
	ReviewerName  string
	ReviewerEmail string
	RequireNDA    bool
	Watermark     string
	ExpiresAt     time.Time
}

type CustomerPortalAcceptanceInput struct {
	NDAAccepted   bool
	NDAAcceptedBy string
}

type CreateQuestionnaireTemplateInput struct {
	Name      string
	Version   string
	Questions []domain.QuestionnaireQuestion
}

type CreateQuestionnairePackageInput struct {
	TemplateID string
	PackageID  string
	ProductID  string
	ReleaseID  string
}

type CreateQuestionnaireAnswerLibraryEntryInput struct {
	QuestionID   string
	EvidenceType string
	ControlID    string
	ProductID    string
	ReleaseID    string
	Answer       string
	EvidenceIDs  []string
	Limitations  []string
}

type ListQuestionnaireAnswerLibraryInput struct {
	QuestionID string
	ProductID  string
	ReleaseID  string
}

type CreateCommercialCollectorInput struct {
	Name          string
	Provider      string
	Version       string
	ManifestHash  string
	AllowedScopes []string
}

func (s identityService) CreateOrganization(ctx context.Context, actor domain.Actor, in CreateOrganizationInput) (domain.Organization, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.Organization{}, err
	}
	if err := require(actor, ScopeIdentityAdmin); err != nil {
		return domain.Organization{}, err
	}
	in.Name, in.Slug = strings.TrimSpace(in.Name), strings.TrimSpace(in.Slug)
	if in.Name == "" || in.Slug == "" {
		return domain.Organization{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, existing := range l.organizations {
		if existing.TenantID == actor.TenantID && existing.Slug == in.Slug {
			return domain.Organization{}, ErrConflict
		}
	}
	org := domain.Organization{ID: newID("org"), TenantID: actor.TenantID, Name: in.Name, Slug: in.Slug, Status: "active", SchemaVersion: domain.OrganizationSchemaVersion, CreatedAt: l.now()}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Identity.InsertOrganization(ctx, org); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(org.CreatedAt, actor.TenantID, "organization.created", "organization", org.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.Organization{}, err
		}
		l.organizations[org.ID] = org
		l.publishCommittedAuditEntryLocked(entry)
		return org, nil
	}
	l.organizations[org.ID] = org
	_, _ = l.appendChainLocked(actor.TenantID, "organization.created", "organization", org.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.Organization{}, err
	}
	return org, nil
}

func (s identityService) CreateUser(ctx context.Context, actor domain.Actor, in CreateUserInput) (domain.HumanUser, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.HumanUser{}, err
	}
	if err := require(actor, ScopeIdentityAdmin); err != nil {
		return domain.HumanUser{}, err
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	name := strings.TrimSpace(in.DisplayName)
	if email == "" || !strings.Contains(email, "@") || name == "" {
		return domain.HumanUser{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if in.OrganizationID != "" {
		org, ok := l.organizations[strings.TrimSpace(in.OrganizationID)]
		if !ok || org.TenantID != actor.TenantID {
			return domain.HumanUser{}, ErrNotFound
		}
	}
	for _, existing := range l.users {
		if existing.TenantID == actor.TenantID && existing.Email == email {
			return domain.HumanUser{}, ErrConflict
		}
	}
	user := domain.HumanUser{ID: newID("usr"), TenantID: actor.TenantID, OrganizationID: strings.TrimSpace(in.OrganizationID), Email: email, DisplayName: name, Status: "active", SchemaVersion: domain.HumanUserSchemaVersion, CreatedAt: l.now()}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Identity.InsertHumanUser(ctx, user); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(user.CreatedAt, actor.TenantID, "user.created", "human_user", user.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.HumanUser{}, err
		}
		l.users[user.ID] = user
		l.publishCommittedAuditEntryLocked(entry)
		return user, nil
	}
	l.users[user.ID] = user
	_, _ = l.appendChainLocked(actor.TenantID, "user.created", "human_user", user.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.HumanUser{}, err
	}
	return user, nil
}

func (s identityService) DeactivateUser(ctx context.Context, actor domain.Actor, id string) (domain.HumanUser, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.HumanUser{}, err
	}
	if err := require(actor, ScopeIdentityAdmin); err != nil {
		return domain.HumanUser{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	user, ok := l.users[strings.TrimSpace(id)]
	if !ok || user.TenantID != actor.TenantID {
		return domain.HumanUser{}, ErrNotFound
	}
	if user.Status == "deactivated" {
		return domain.HumanUser{}, ErrConflict
	}
	now := l.now()
	user.Status = "deactivated"
	user.DeactivatedAt = &now
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Identity.DeactivateHumanUser(ctx, user); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(now, actor.TenantID, "user.deactivated", "human_user", user.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.HumanUser{}, err
		}
		l.users[user.ID] = user
		l.publishCommittedAuditEntryLocked(entry)
		return user, nil
	}
	l.users[user.ID] = user
	_, _ = l.appendChainLocked(actor.TenantID, "user.deactivated", "human_user", user.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.HumanUser{}, err
	}
	return user, nil
}

func (s identityService) CreateRoleBinding(ctx context.Context, actor domain.Actor, in CreateRoleBindingInput) (domain.RoleBinding, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.RoleBinding{}, err
	}
	if err := require(actor, ScopeIdentityAdmin); err != nil {
		return domain.RoleBinding{}, err
	}
	in.SubjectType, in.SubjectID = strings.TrimSpace(in.SubjectType), strings.TrimSpace(in.SubjectID)
	in.Role, in.ResourceType, in.ResourceID = strings.TrimSpace(in.Role), strings.TrimSpace(in.ResourceType), strings.TrimSpace(in.ResourceID)
	if !validRoleSubject(in.SubjectType) || in.SubjectID == "" || !validRole(in.Role) {
		return domain.RoleBinding{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ensureRoleSubjectLocked(actor.TenantID, in.SubjectType, in.SubjectID); err != nil {
		return domain.RoleBinding{}, err
	}
	if err := l.ensureRoleResourceLocked(actor.TenantID, in.ResourceType, in.ResourceID); err != nil {
		return domain.RoleBinding{}, err
	}
	binding := domain.RoleBinding{ID: newID("rbac"), TenantID: actor.TenantID, SubjectType: in.SubjectType, SubjectID: in.SubjectID, Role: in.Role, ResourceType: in.ResourceType, ResourceID: in.ResourceID, SchemaVersion: domain.RoleBindingSchemaVersion, CreatedAt: l.now()}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Identity.InsertRoleBinding(ctx, binding); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(binding.CreatedAt, actor.TenantID, "role_binding.created", "role_binding", binding.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.RoleBinding{}, err
		}
		l.roleBindings[binding.ID] = binding
		l.publishCommittedAuditEntryLocked(entry)
		return binding, nil
	}
	l.roleBindings[binding.ID] = binding
	_, _ = l.appendChainLocked(actor.TenantID, "role_binding.created", "role_binding", binding.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.RoleBinding{}, err
	}
	return binding, nil
}

func (s identityService) ListRoleBindings(ctx context.Context, actor domain.Actor) ([]domain.RoleBinding, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeIdentityAdmin); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []domain.RoleBinding{}
	for _, binding := range l.roleBindings {
		if binding.TenantID == actor.TenantID {
			out = append(out, binding)
		}
	}
	return out, nil
}

func (s identityService) CreateSSOProvider(ctx context.Context, actor domain.Actor, in CreateSSOProviderInput) (domain.SSOProvider, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.SSOProvider{}, err
	}
	if err := require(actor, ScopeIdentityAdmin); err != nil {
		return domain.SSOProvider{}, err
	}
	in.Name, in.Type, in.Issuer, in.ClientID = strings.TrimSpace(in.Name), strings.TrimSpace(in.Type), strings.TrimSpace(in.Issuer), strings.TrimSpace(in.ClientID)
	if in.Name == "" || !validSSOType(in.Type) || !strings.HasPrefix(in.Issuer, "https://") || in.ClientID == "" {
		return domain.SSOProvider{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	jwks, err := normalizeJWKS(in.JWKS)
	if err != nil {
		return domain.SSOProvider{}, ErrValidation
	}
	samlCerts, err := normalizeSAMLSigningCertificates(in.SAMLSigningCertificates)
	if err != nil {
		return domain.SSOProvider{}, ErrValidation
	}
	provider := domain.SSOProvider{ID: newID("sso"), TenantID: actor.TenantID, Name: in.Name, Type: in.Type, Issuer: in.Issuer, ClientID: in.ClientID, GroupsClaim: strings.TrimSpace(in.GroupsClaim), RoleMapping: cloneStringMap(in.RoleMapping), JWKS: jwks, SAMLSigningCertificates: samlCerts, Status: "active", SchemaVersion: domain.SSOProviderSchemaVersion, CreatedAt: l.now()}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Identity.InsertSSOProvider(ctx, provider); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(provider.CreatedAt, actor.TenantID, "sso_provider.created", "sso_provider", provider.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.SSOProvider{}, err
		}
		l.ssoProviders[provider.ID] = provider
		l.publishCommittedAuditEntryLocked(entry)
		return provider, nil
	}
	l.ssoProviders[provider.ID] = provider
	_, _ = l.appendChainLocked(actor.TenantID, "sso_provider.created", "sso_provider", provider.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.SSOProvider{}, err
	}
	return provider, nil
}

func (s identityService) UpdateSSOProviderTrustMaterial(ctx context.Context, actor domain.Actor, id string, in UpdateSSOProviderTrustMaterialInput) (domain.SSOProvider, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.SSOProvider{}, err
	}
	if err := require(actor, ScopeIdentityAdmin); err != nil {
		return domain.SSOProvider{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return domain.SSOProvider{}, ErrValidation
	}
	jwks, err := normalizeJWKS(in.JWKS)
	if err != nil {
		return domain.SSOProvider{}, ErrValidation
	}
	samlCerts, err := normalizeSAMLSigningCertificates(in.SAMLSigningCertificates)
	if err != nil {
		return domain.SSOProvider{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	provider, ok := l.ssoProviders[id]
	if !ok || provider.TenantID != actor.TenantID {
		return domain.SSOProvider{}, ErrNotFound
	}
	switch provider.Type {
	case "oidc":
		if len(jwks) == 0 || len(samlCerts) != 0 {
			return domain.SSOProvider{}, ErrValidation
		}
		provider.JWKS = jwks
		provider.SAMLSigningCertificates = nil
	case "saml":
		if len(samlCerts) == 0 || len(jwks) != 0 {
			return domain.SSOProvider{}, ErrValidation
		}
		provider.SAMLSigningCertificates = samlCerts
		provider.JWKS = nil
	default:
		return domain.SSOProvider{}, ErrValidation
	}
	now := l.now()
	provider.TrustMaterialUpdatedAt = &now
	materialHash, err := canonicalAnyHash(struct {
		ProviderID              string         `json:"provider_id"`
		JWKS                    map[string]any `json:"jwks,omitempty"`
		SAMLSigningCertificates []string       `json:"saml_signing_certificates,omitempty"`
		UpdatedAt               string         `json:"updated_at"`
	}{
		ProviderID:              provider.ID,
		JWKS:                    provider.JWKS,
		SAMLSigningCertificates: provider.SAMLSigningCertificates,
		UpdatedAt:               now.Format(time.RFC3339Nano),
	})
	if err != nil {
		return domain.SSOProvider{}, err
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Identity.UpdateSSOProviderTrustMaterial(ctx, provider); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(now, actor.TenantID, "sso_provider.trust_material_updated", "sso_provider", provider.ID, actorType(actor), actorID(actor), materialHash, ""))
			return err
		}); err != nil {
			return domain.SSOProvider{}, err
		}
		l.ssoProviders[provider.ID] = provider
		l.publishCommittedAuditEntryLocked(entry)
		return provider, nil
	}
	l.ssoProviders[provider.ID] = provider
	_, _ = l.appendChainLocked(actor.TenantID, "sso_provider.trust_material_updated", "sso_provider", provider.ID, actorType(actor), actorID(actor), materialHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.SSOProvider{}, err
	}
	return provider, nil
}

func (s identityService) RefreshSSOProviderOIDCTrustMaterial(ctx context.Context, actor domain.Actor, id string) (domain.SSOProvider, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.SSOProvider{}, err
	}
	if err := require(actor, ScopeIdentityAdmin); err != nil {
		return domain.SSOProvider{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return domain.SSOProvider{}, ErrValidation
	}
	discovery := l.oidc
	if discovery == nil {
		return domain.SSOProvider{}, ErrValidation
	}
	l.mu.Lock()
	provider, ok := l.ssoProviders[id]
	if !ok || provider.TenantID != actor.TenantID {
		l.mu.Unlock()
		return domain.SSOProvider{}, ErrNotFound
	}
	if provider.Type != "oidc" {
		l.mu.Unlock()
		return domain.SSOProvider{}, ErrValidation
	}
	l.mu.Unlock()

	result, err := discovery.FetchOIDCTrustMaterial(ctx, OIDCDiscoveryRequest{TenantID: actor.TenantID, ProviderID: provider.ID, Issuer: provider.Issuer})
	if err != nil {
		return domain.SSOProvider{}, ErrVerificationFailed
	}
	if strings.TrimRight(strings.TrimSpace(result.Issuer), "/") != strings.TrimRight(provider.Issuer, "/") {
		return domain.SSOProvider{}, ErrVerificationFailed
	}
	jwks, err := normalizeJWKS(result.JWKS)
	if err != nil {
		return domain.SSOProvider{}, ErrVerificationFailed
	}
	if len(jwks) == 0 {
		return domain.SSOProvider{}, ErrVerificationFailed
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	current, ok := l.ssoProviders[id]
	if !ok || current.TenantID != actor.TenantID {
		return domain.SSOProvider{}, ErrNotFound
	}
	if current.Type != "oidc" || current.Issuer != provider.Issuer {
		return domain.SSOProvider{}, ErrVerificationFailed
	}
	now := l.now()
	current.JWKS = jwks
	current.SAMLSigningCertificates = nil
	current.TrustMaterialUpdatedAt = &now
	materialHash, err := canonicalAnyHash(struct {
		ProviderID string         `json:"provider_id"`
		Issuer     string         `json:"issuer"`
		JWKS       map[string]any `json:"jwks"`
		UpdatedAt  string         `json:"updated_at"`
	}{
		ProviderID: current.ID,
		Issuer:     current.Issuer,
		JWKS:       current.JWKS,
		UpdatedAt:  now.Format(time.RFC3339Nano),
	})
	if err != nil {
		return domain.SSOProvider{}, err
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Identity.UpdateSSOProviderTrustMaterial(ctx, current); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(now, actor.TenantID, "sso_provider.oidc_trust_material_refreshed", "sso_provider", current.ID, actorType(actor), actorID(actor), materialHash, ""))
			return err
		}); err != nil {
			return domain.SSOProvider{}, err
		}
		l.ssoProviders[current.ID] = current
		l.publishCommittedAuditEntryLocked(entry)
		return current, nil
	}
	l.ssoProviders[current.ID] = current
	_, _ = l.appendChainLocked(actor.TenantID, "sso_provider.oidc_trust_material_refreshed", "sso_provider", current.ID, actorType(actor), actorID(actor), materialHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.SSOProvider{}, err
	}
	return current, nil
}

func (s identityService) LinkSSOIdentity(ctx context.Context, actor domain.Actor, in LinkSSOIdentityInput) (domain.UserIdentityLink, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.UserIdentityLink{}, err
	}
	if err := require(actor, ScopeIdentityAdmin); err != nil {
		return domain.UserIdentityLink{}, err
	}
	in.UserID, in.ProviderID, in.Subject = strings.TrimSpace(in.UserID), strings.TrimSpace(in.ProviderID), strings.TrimSpace(in.Subject)
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if in.UserID == "" || in.ProviderID == "" || in.Subject == "" || email == "" || !in.Verified {
		return domain.UserIdentityLink{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	user, ok := l.users[in.UserID]
	if !ok || user.TenantID != actor.TenantID || user.Email != email {
		return domain.UserIdentityLink{}, ErrNotFound
	}
	provider, ok := l.ssoProviders[in.ProviderID]
	if !ok || provider.TenantID != actor.TenantID {
		return domain.UserIdentityLink{}, ErrNotFound
	}
	link := domain.UserIdentityLink{ID: newID("uil"), TenantID: actor.TenantID, UserID: user.ID, ProviderID: provider.ID, Subject: in.Subject, Email: email, Verified: true, SchemaVersion: "user-identity-link.v1.0.0", CreatedAt: l.now()}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Identity.InsertUserIdentityLink(ctx, link); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(link.CreatedAt, actor.TenantID, "identity_link.created", "human_user", user.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.UserIdentityLink{}, err
		}
		l.identityLinks[link.ID] = link
		l.publishCommittedAuditEntryLocked(entry)
		return link, nil
	}
	l.identityLinks[link.ID] = link
	_, _ = l.appendChainLocked(actor.TenantID, "identity_link.created", "human_user", user.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.UserIdentityLink{}, err
	}
	return link, nil
}

func (s identityService) CreateSSOSession(ctx context.Context, actor domain.Actor, in CreateSSOSessionInput) (domain.SSOSession, string, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.SSOSession{}, "", err
	}
	if err := require(actor, ScopeIdentityAdmin); err != nil {
		return domain.SSOSession{}, "", err
	}
	if strings.TrimSpace(in.UserID) == "" || strings.TrimSpace(in.ProviderID) == "" || !in.ExpiresAt.After(l.now()) {
		return domain.SSOSession{}, "", ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	user, ok := l.users[strings.TrimSpace(in.UserID)]
	if !ok || user.TenantID != actor.TenantID || user.Status != "active" {
		return domain.SSOSession{}, "", ErrNotFound
	}
	provider, ok := l.ssoProviders[strings.TrimSpace(in.ProviderID)]
	if !ok || provider.TenantID != actor.TenantID {
		return domain.SSOSession{}, "", ErrNotFound
	}
	secret := "evysso_" + randomToken(32)
	session := domain.SSOSession{ID: newID("sess"), TenantID: actor.TenantID, UserID: user.ID, ProviderID: provider.ID, Prefix: secretPrefix(secret), ExpiresAt: in.ExpiresAt.UTC(), SchemaVersion: domain.SSOSessionSchemaVersion, CreatedAt: l.now(), Hash: l.hashSecret(secret)}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Identity.InsertSSOSession(ctx, session); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(session.CreatedAt, actor.TenantID, "sso_session.created", "human_user", user.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.SSOSession{}, "", err
		}
		l.ssoSessions[session.ID] = session
		l.publishCommittedAuditEntryLocked(entry)
		public := session
		public.Hash = ""
		return public, secret, nil
	}
	l.ssoSessions[session.ID] = session
	_, _ = l.appendChainLocked(actor.TenantID, "sso_session.created", "human_user", user.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistCriticalStateLocked(ctx); err != nil {
		return domain.SSOSession{}, "", err
	}
	session.Hash = ""
	return session, secret, nil
}

func (s identityService) ExchangeSSOCredential(ctx context.Context, in ExchangeSSOCredentialInput) (domain.ProviderVerification, domain.SSOSession, string, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.ProviderVerification{}, domain.SSOSession{}, "", err
	}
	providerID, subject := strings.TrimSpace(in.ProviderID), strings.TrimSpace(in.Subject)
	idToken, samlAssertion := strings.TrimSpace(in.IDToken), strings.TrimSpace(in.SAMLAssertion)
	if providerID == "" || subject == "" || (idToken == "" && samlAssertion == "") || (idToken != "" && samlAssertion != "") {
		return domain.ProviderVerification{}, domain.SSOSession{}, "", ErrValidation
	}
	expiresAt := in.ExpiresAt.UTC()
	now := l.now()
	if expiresAt.IsZero() {
		expiresAt = now.Add(8 * time.Hour)
	}
	if !expiresAt.After(now) || expiresAt.After(now.Add(12*time.Hour)) {
		return domain.ProviderVerification{}, domain.SSOSession{}, "", ErrValidation
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	provider, ok := l.ssoProviders[providerID]
	if !ok || provider.Status != "active" {
		return domain.ProviderVerification{}, domain.SSOSession{}, "", ErrNotFound
	}
	if (provider.Type == "oidc" && samlAssertion != "") || (provider.Type == "saml" && idToken != "") {
		return domain.ProviderVerification{}, domain.SSOSession{}, "", ErrValidation
	}
	checks := []domain.VerifyCheck{}
	if idToken != "" {
		tokenChecks, _ := verifyOIDCIDToken(provider, subject, idToken, now)
		checks = append(checks, tokenChecks...)
	}
	if samlAssertion != "" {
		assertionChecks, _ := verifySAMLAssertion(provider, subject, samlAssertion, now)
		checks = append(checks, assertionChecks...)
	}

	var link domain.UserIdentityLink
	for _, candidate := range l.identityLinks {
		if candidate.TenantID == provider.TenantID && candidate.ProviderID == provider.ID && candidate.Subject == subject && candidate.Verified {
			link = candidate
			break
		}
	}
	if link.ID == "" {
		checks = append(checks, domain.VerifyCheck{Name: "verified_identity_link", Result: "failed"})
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "verified_identity_link", Result: "passed"})
	}

	verification := domain.ProviderVerification{
		ID:            newID("pvr"),
		TenantID:      provider.TenantID,
		ProviderType:  provider.Type,
		ProviderID:    provider.ID,
		Subject:       subject,
		Checks:        checks,
		Limitations:   []string{"Credential exchange uses configured local token/assertion trust roots and verified identity links; no live provider API or group synchronization call is made."},
		SchemaVersion: domain.ProviderVerificationVersion,
		CreatedAt:     now,
	}
	reassessProviderVerification(&verification, provider, true)
	if verificationReturnsFailure(verification.Result) {
		if err := s.persistProviderVerificationLocked(ctx, verification, provider); err != nil {
			return domain.ProviderVerification{}, domain.SSOSession{}, "", err
		}
		return verification, domain.SSOSession{}, "", ErrVerificationFailed
	}
	user, ok := l.users[link.UserID]
	if !ok || user.TenantID != provider.TenantID || user.Status != "active" {
		verification.Checks = append(verification.Checks, domain.VerifyCheck{Name: "active_user", Result: "failed"})
		reassessProviderVerification(&verification, provider, true)
		if err := s.persistProviderVerificationLocked(ctx, verification, provider); err != nil {
			return domain.ProviderVerification{}, domain.SSOSession{}, "", err
		}
		return verification, domain.SSOSession{}, "", ErrVerificationFailed
	}
	verification.Checks = append(verification.Checks, domain.VerifyCheck{Name: "active_user", Result: "passed"})
	reassessProviderVerification(&verification, provider, true)

	groups := oidcGroupsFromVerifiedToken(provider, idToken)
	grants := append(l.resourceGrantsForUserLocked(user.ID), resourceGrantsForProviderGroups(provider, groups)...)
	if len(scopesFromResourceGrants(grants)) == 0 {
		verification.Checks = append(verification.Checks, domain.VerifyCheck{Name: "authorization_grant", Result: "failed"})
		reassessProviderVerification(&verification, provider, true)
		if err := s.persistProviderVerificationLocked(ctx, verification, provider); err != nil {
			return domain.ProviderVerification{}, domain.SSOSession{}, "", err
		}
		return verification, domain.SSOSession{}, "", ErrForbidden
	}
	if len(groups) > 0 && len(resourceGrantsForProviderGroups(provider, groups)) > 0 {
		verification.Checks = append(verification.Checks, domain.VerifyCheck{Name: "mapped_group_roles", Result: "passed", Detail: fmt.Sprintf("%d session-scoped provider group role mapping(s) applied", len(resourceGrantsForProviderGroups(provider, groups)))})
		reassessProviderVerification(&verification, provider, true)
	}

	secret := "evysso_" + randomToken(32)
	session := domain.SSOSession{ID: newID("sess"), TenantID: provider.TenantID, UserID: user.ID, ProviderID: provider.ID, Prefix: secretPrefix(secret), Groups: groups, ExpiresAt: expiresAt, SchemaVersion: domain.SSOSessionSchemaVersion, CreatedAt: now, Hash: l.hashSecret(secret)}
	if l.unitOfWork != nil {
		entries := []domain.AuditChainEntry{}
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Identity.InsertProviderVerification(ctx, verification); err != nil {
				return err
			}
			entry, err := repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(now, provider.TenantID, "provider_identity.verified", "provider_identity", verification.ID, "sso_provider", provider.ID, "", ""))
			if err != nil {
				return err
			}
			entries = append(entries, entry)
			if err := repos.Identity.InsertSSOSession(ctx, session); err != nil {
				return err
			}
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(now, provider.TenantID, "sso_session.created", "human_user", user.ID, "sso_provider", provider.ID, "", ""))
			if err != nil {
				return err
			}
			entries = append(entries, entry)
			return nil
		}); err != nil {
			return domain.ProviderVerification{}, domain.SSOSession{}, "", err
		}
		l.providerVerifications[verification.ID] = verification
		l.ssoSessions[session.ID] = session
		for _, entry := range entries {
			l.publishCommittedAuditEntryLocked(entry)
		}
		public := session
		public.Hash = ""
		return verification, public, secret, nil
	}
	l.providerVerifications[verification.ID] = verification
	l.ssoSessions[session.ID] = session
	_, _ = l.appendChainLocked(provider.TenantID, "sso_session.created", "human_user", user.ID, "sso_provider", provider.ID, "", "")
	if err := l.persistCriticalStateLocked(ctx); err != nil {
		return domain.ProviderVerification{}, domain.SSOSession{}, "", err
	}
	session.Hash = ""
	return verification, session, secret, nil
}

// persistProviderVerificationLocked records an exchange outcome and its audit
// entry before making it visible through the local read model. The caller
// holds l.mu and never includes the presented credential in the record.
func (s identityService) persistProviderVerificationLocked(ctx context.Context, verification domain.ProviderVerification, provider domain.SSOProvider) error {
	l := s.ledger
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Identity.InsertProviderVerification(ctx, verification); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(verification.CreatedAt, provider.TenantID, "provider_identity.verified", "provider_identity", verification.ID, "sso_provider", provider.ID, "", ""))
			return err
		}); err != nil {
			return err
		}
		l.providerVerifications[verification.ID] = verification
		l.publishCommittedAuditEntryLocked(entry)
		return nil
	}
	l.providerVerifications[verification.ID] = verification
	_, _ = l.appendChainLocked(provider.TenantID, "provider_identity.verified", "provider_identity", verification.ID, "sso_provider", provider.ID, "", "")
	return l.persistLocked(ctx)
}

func (s identityService) RevokeSSOSession(ctx context.Context, actor domain.Actor, id string) (domain.SSOSession, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.SSOSession{}, err
	}
	if err := require(actor, ScopeIdentityAdmin); err != nil {
		return domain.SSOSession{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	session, ok := l.ssoSessions[strings.TrimSpace(id)]
	if !ok || session.TenantID != actor.TenantID {
		return domain.SSOSession{}, ErrNotFound
	}
	if session.RevokedAt != nil {
		return domain.SSOSession{}, ErrConflict
	}
	now := l.now()
	session.RevokedAt = &now
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Identity.RevokeSSOSession(ctx, session); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(now, actor.TenantID, "sso_session.revoked", "sso_session", session.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.SSOSession{}, err
		}
		l.ssoSessions[session.ID] = session
		l.publishCommittedAuditEntryLocked(entry)
		public := session
		public.Hash = ""
		return public, nil
	}
	l.ssoSessions[session.ID] = session
	_, _ = l.appendChainLocked(actor.TenantID, "sso_session.revoked", "sso_session", session.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistCriticalStateLocked(ctx); err != nil {
		return domain.SSOSession{}, err
	}
	session.Hash = ""
	return session, nil
}

func (s identityService) RevokeCurrentSSOSession(ctx context.Context, actor domain.Actor) (domain.SSOSession, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.SSOSession{}, err
	}
	if strings.TrimSpace(actor.UserID) == "" || strings.TrimSpace(actor.SessionID) == "" {
		return domain.SSOSession{}, ErrForbidden
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	session, ok := l.ssoSessions[strings.TrimSpace(actor.SessionID)]
	if !ok || session.TenantID != actor.TenantID || session.UserID != actor.UserID {
		return domain.SSOSession{}, ErrNotFound
	}
	if session.RevokedAt != nil {
		return domain.SSOSession{}, ErrConflict
	}
	now := l.now()
	session.RevokedAt = &now
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Identity.RevokeSSOSession(ctx, session); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(now, actor.TenantID, "sso_session.revoked", "sso_session", session.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.SSOSession{}, err
		}
		l.ssoSessions[session.ID] = session
		l.publishCommittedAuditEntryLocked(entry)
		public := session
		public.Hash = ""
		return public, nil
	}
	l.ssoSessions[session.ID] = session
	_, _ = l.appendChainLocked(actor.TenantID, "sso_session.revoked", "sso_session", session.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistCriticalStateLocked(ctx); err != nil {
		return domain.SSOSession{}, err
	}
	session.Hash = ""
	return session, nil
}

func (l *Ledger) InstanceAdminSnapshot(ctx context.Context, actor domain.Actor) (domain.InstanceAdminSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return domain.InstanceAdminSnapshot{}, err
	}
	if err := require(actor, ScopeInstanceAdmin); err != nil {
		return domain.InstanceAdminSnapshot{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return domain.InstanceAdminSnapshot{ReportType: "instance_admin_snapshot", TenantCount: len(l.tenants), ResourceCounts: map[string]int{"tenants": len(l.tenants), "users": len(l.users), "collectors": len(l.collectors), "evidence": len(l.evidence)}, Limitations: []string{"Instance admin diagnostics expose operational counts only and not raw evidence payloads or secrets."}, GeneratedAt: l.now()}, nil
}

func (l *Ledger) CreateLegalHold(ctx context.Context, actor domain.Actor, in CreateLegalHoldInput) (domain.LegalHold, error) {
	if err := ctx.Err(); err != nil {
		return domain.LegalHold{}, err
	}
	if err := require(actor, ScopeAdmin); err != nil {
		return domain.LegalHold{}, err
	}
	in.ScopeType, in.ScopeID, in.Reason, in.Owner = strings.TrimSpace(in.ScopeType), strings.TrimSpace(in.ScopeID), strings.TrimSpace(in.Reason), strings.TrimSpace(in.Owner)
	if !validRetentionScope(in.ScopeType) || in.ScopeID == "" || in.Reason == "" || in.Owner == "" {
		return domain.LegalHold{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ensureRetentionScopeLocked(actor.TenantID, in.ScopeType, in.ScopeID); err != nil {
		return domain.LegalHold{}, err
	}
	hold := domain.LegalHold{ID: newID("lh"), TenantID: actor.TenantID, ScopeType: in.ScopeType, ScopeID: in.ScopeID, Reason: in.Reason, Owner: in.Owner, SchemaVersion: domain.LegalHoldSchemaVersion, CreatedAt: l.now()}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Governance.InsertLegalHold(ctx, hold); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(hold.CreatedAt, actor.TenantID, "legal_hold.created", in.ScopeType, in.ScopeID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.LegalHold{}, err
		}
		l.legalHolds[hold.ID] = hold
		l.publishCommittedAuditEntryLocked(entry)
		return hold, nil
	}
	l.legalHolds[hold.ID] = hold
	_, _ = l.appendChainLocked(actor.TenantID, "legal_hold.created", in.ScopeType, in.ScopeID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.LegalHold{}, err
	}
	return hold, nil
}

func (l *Ledger) CreateRetentionOverride(ctx context.Context, actor domain.Actor, in CreateRetentionOverrideInput) (domain.RetentionOverride, error) {
	if err := ctx.Err(); err != nil {
		return domain.RetentionOverride{}, err
	}
	if err := require(actor, ScopeAdmin); err != nil {
		return domain.RetentionOverride{}, err
	}
	in.ScopeType, in.ScopeID, in.Reason, in.Owner = strings.TrimSpace(in.ScopeType), strings.TrimSpace(in.ScopeID), strings.TrimSpace(in.Reason), strings.TrimSpace(in.Owner)
	if !validRetentionScope(in.ScopeType) || in.ScopeID == "" || in.Reason == "" || in.Owner == "" || !in.RetentionUntil.After(l.now()) {
		return domain.RetentionOverride{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ensureRetentionScopeLocked(actor.TenantID, in.ScopeType, in.ScopeID); err != nil {
		return domain.RetentionOverride{}, err
	}
	override := domain.RetentionOverride{ID: newID("ro"), TenantID: actor.TenantID, ScopeType: in.ScopeType, ScopeID: in.ScopeID, RetentionUntil: in.RetentionUntil.UTC(), Reason: in.Reason, Owner: in.Owner, SchemaVersion: domain.RetentionOverrideSchemaVersion, CreatedAt: l.now()}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Governance.InsertRetentionOverride(ctx, override); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(override.CreatedAt, actor.TenantID, "retention_override.created", in.ScopeType, in.ScopeID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.RetentionOverride{}, err
		}
		l.retentionOverrides[override.ID] = override
		l.publishCommittedAuditEntryLocked(entry)
		return override, nil
	}
	l.retentionOverrides[override.ID] = override
	_, _ = l.appendChainLocked(actor.TenantID, "retention_override.created", in.ScopeType, in.ScopeID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.RetentionOverride{}, err
	}
	return override, nil
}

func (s packageReportService) RetentionReport(ctx context.Context, actor domain.Actor, scopeType, scopeID string) (domain.RetentionReport, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.RetentionReport{}, err
	}
	if err := require(actor, ScopeAdmin); err != nil {
		return domain.RetentionReport{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	holds := []domain.LegalHold{}
	for _, hold := range l.legalHolds {
		if hold.TenantID == actor.TenantID && (scopeType == "" || (hold.ScopeType == scopeType && hold.ScopeID == scopeID)) {
			holds = append(holds, hold)
		}
	}
	overrides := []domain.RetentionOverride{}
	for _, override := range l.retentionOverrides {
		if override.TenantID == actor.TenantID && (scopeType == "" || (override.ScopeType == scopeType && override.ScopeID == scopeID)) {
			overrides = append(overrides, override)
		}
	}
	return domain.RetentionReport{ReportType: "retention", ScopeType: scopeType, ScopeID: scopeID, LegalHolds: holds, RetentionOverrides: overrides, Limitations: []string{"Retention reports describe Evydence records and do not replace external storage lifecycle verification."}, GeneratedAt: l.now()}, nil
}

func (s identityService) CreateCustomerPortalAccess(ctx context.Context, actor domain.Actor, in CreateCustomerPortalAccessInput) (domain.CustomerPortalAccess, string, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.CustomerPortalAccess{}, "", err
	}
	if err := require(actor, ScopePackageWrite); err != nil {
		return domain.CustomerPortalAccess{}, "", err
	}
	in.PackageID, in.CustomerName = strings.TrimSpace(in.PackageID), cleanExternalLabel(in.CustomerName)
	in.ReviewerName = cleanExternalLabel(in.ReviewerName)
	in.ReviewerEmail = cleanReviewerEmail(in.ReviewerEmail)
	in.Watermark = cleanExternalLabel(in.Watermark)
	if in.PackageID == "" || in.CustomerName == "" || !in.ExpiresAt.After(l.now()) {
		return domain.CustomerPortalAccess{}, "", ErrValidation
	}
	if in.ReviewerEmail != "" && !validReviewerEmail(in.ReviewerEmail) {
		return domain.CustomerPortalAccess{}, "", ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	pkg, ok := l.customerPackages[in.PackageID]
	if !ok || pkg.TenantID != actor.TenantID {
		return domain.CustomerPortalAccess{}, "", ErrNotFound
	}
	secret := "evycp_" + randomToken(32)
	accessID := newID("cpa")
	watermark := in.Watermark
	if watermark == "" {
		watermark = packageDistributionWatermark(pkg, portalReviewerLabel(in.CustomerName, in.ReviewerName, in.ReviewerEmail), accessID)
	}
	access := domain.CustomerPortalAccess{ID: accessID, TenantID: actor.TenantID, PackageID: pkg.ID, CustomerName: in.CustomerName, ReviewerName: in.ReviewerName, ReviewerEmail: in.ReviewerEmail, RequireNDA: in.RequireNDA, Watermark: watermark, Prefix: secretPrefix(secret), ExpiresAt: in.ExpiresAt.UTC(), SchemaVersion: domain.CustomerPortalAccessVersion, CreatedAt: l.now(), Hash: l.hashSecret(secret)}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Identity.InsertCustomerPortalAccess(ctx, access); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(access.CreatedAt, actor.TenantID, "customer_portal_access.created", "customer_security_package", pkg.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.CustomerPortalAccess{}, "", err
		}
		l.portalAccess[access.ID] = access
		l.publishCommittedAuditEntryLocked(entry)
		public := access
		public.Hash = ""
		return public, secret, nil
	}
	l.portalAccess[access.ID] = access
	_, _ = l.appendChainLocked(actor.TenantID, "customer_portal_access.created", "customer_security_package", pkg.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistCriticalStateLocked(ctx); err != nil {
		return domain.CustomerPortalAccess{}, "", err
	}
	access.Hash = ""
	return access, secret, nil
}

func (s identityService) ListCustomerPortalAccess(ctx context.Context, actor domain.Actor, packageID string) ([]domain.CustomerPortalAccess, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopePackageRead); err != nil {
		return nil, err
	}
	packageID = strings.TrimSpace(packageID)
	l.mu.Lock()
	defer l.mu.Unlock()
	if packageID != "" {
		pkg, ok := l.customerPackages[packageID]
		if !ok || pkg.TenantID != actor.TenantID {
			return nil, ErrNotFound
		}
	}
	accesses := []domain.CustomerPortalAccess{}
	for _, access := range l.portalAccess {
		if access.TenantID != actor.TenantID || (packageID != "" && access.PackageID != packageID) {
			continue
		}
		access.Hash = ""
		accesses = append(accesses, access)
	}
	sort.Slice(accesses, func(i, j int) bool {
		if accesses[i].CreatedAt.Equal(accesses[j].CreatedAt) {
			return accesses[i].ID < accesses[j].ID
		}
		return accesses[i].CreatedAt.Before(accesses[j].CreatedAt)
	})
	return accesses, nil
}

func (s identityService) RevokeCustomerPortalAccess(ctx context.Context, actor domain.Actor, id string) (domain.CustomerPortalAccess, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.CustomerPortalAccess{}, err
	}
	if err := require(actor, ScopePackageWrite); err != nil {
		return domain.CustomerPortalAccess{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return domain.CustomerPortalAccess{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	access, ok := l.portalAccess[id]
	if !ok || access.TenantID != actor.TenantID {
		return domain.CustomerPortalAccess{}, ErrNotFound
	}
	if access.RevokedAt == nil {
		previous := access
		now := l.now()
		access.RevokedAt = &now
		if l.unitOfWork != nil {
			var entry domain.AuditChainEntry
			if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
				if err := repos.Identity.UpdateCustomerPortalAccess(ctx, previous, access); err != nil {
					return err
				}
				var err error
				entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(now, access.TenantID, "customer_portal_access.revoked", "customer_portal_access", access.ID, actorType(actor), actorID(actor), "", ""))
				return err
			}); err != nil {
				return domain.CustomerPortalAccess{}, err
			}
			l.portalAccess[id] = access
			l.publishCommittedAuditEntryLocked(entry)
			public := access
			public.Hash = ""
			return public, nil
		}
		l.portalAccess[id] = access
		_, _ = l.appendChainLocked(access.TenantID, "customer_portal_access.revoked", "customer_portal_access", access.ID, actorType(actor), actorID(actor), "", "")
		if err := l.persistCriticalStateLocked(ctx); err != nil {
			return domain.CustomerPortalAccess{}, err
		}
	}
	access.Hash = ""
	return access, nil
}

func (s identityService) AccessCustomerPortalPackage(ctx context.Context, token string) (domain.CustomerSecurityPackage, error) {
	return s.AccessCustomerPortalPackageWithAcceptance(ctx, token, CustomerPortalAcceptanceInput{})
}

func (s identityService) AccessCustomerPortalPackageWithAcceptance(ctx context.Context, token string, in CustomerPortalAcceptanceInput) (domain.CustomerSecurityPackage, error) {
	return s.accessCustomerPortalPackage(ctx, token, in, "customer_portal_package.accessed")
}

func (s identityService) accessCustomerPortalPackage(ctx context.Context, token string, in CustomerPortalAcceptanceInput, successEntryType string) (domain.CustomerSecurityPackage, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.CustomerSecurityPackage{}, err
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return domain.CustomerSecurityPackage{}, ErrUnauthorized
	}
	prefix := secretPrefix(token)
	hash := l.hashSecret(token)
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, access := range l.portalAccess {
		if !secretHashEqual(access.Hash, hash) || access.RevokedAt != nil || !access.ExpiresAt.After(l.now()) {
			if access.Prefix == prefix && access.RevokedAt == nil && access.ExpiresAt.After(l.now()) {
				previous := access
				now := l.now()
				access.FailedAccessCount++
				if access.RevokedAt == nil && access.FailedAccessCount >= customerPortalFailedAccessLimit {
					access.RevokedAt = &now
				}
				access.LastFailedAt = &now
				effects := []customerPortalAuditEffect{{EntryType: "customer_portal_package.access_failed", SubjectType: "customer_portal_access", SubjectID: access.ID, ActorID: "unverified"}}
				if access.RevokedAt != nil && access.FailedAccessCount == customerPortalFailedAccessLimit {
					effects = append(effects, customerPortalAuditEffect{EntryType: "customer_portal_access.revoked_after_failed_access", SubjectType: "customer_portal_access", SubjectID: access.ID, ActorID: "unverified"})
				}
				if err := s.persistCustomerPortalAccessUpdateLocked(ctx, previous, access, effects); err != nil {
					return domain.CustomerSecurityPackage{}, ErrUnauthorized
				}
			}
			continue
		}
		pkg, ok := l.customerPackages[access.PackageID]
		if !ok || pkg.TenantID != access.TenantID || !pkg.ExpiresAt.After(l.now()) {
			return domain.CustomerSecurityPackage{}, ErrNotFound
		}
		if access.RequireNDA && access.NDAAcceptedAt == nil {
			acceptedBy := cleanExternalLabel(in.NDAAcceptedBy)
			if !in.NDAAccepted || acceptedBy == "" {
				if err := s.persistCustomerPortalAccessUpdateLocked(ctx, access, access, []customerPortalAuditEffect{{EntryType: "customer_portal_package.nda_required", SubjectType: "customer_portal_access", SubjectID: access.ID, ActorID: access.ID, PayloadHash: pkg.ManifestHash}}); err != nil {
					return domain.CustomerSecurityPackage{}, err
				}
				return domain.CustomerSecurityPackage{}, ErrForbidden
			}
			now := l.now()
			access.NDAAcceptedAt = &now
			access.NDAAcceptedBy = acceptedBy
		}
		previous := l.portalAccess[id]
		access.AccessCount++
		now := l.now()
		access.LastAccessedAt = &now
		effects := []customerPortalAuditEffect{}
		if previous.NDAAcceptedAt == nil && access.NDAAcceptedAt != nil {
			effects = append(effects, customerPortalAuditEffect{EntryType: "customer_portal_package.nda_accepted", SubjectType: "customer_portal_access", SubjectID: access.ID, ActorID: access.ID, PayloadHash: pkg.ManifestHash})
		}
		effects = append(effects,
			customerPortalAuditEffect{EntryType: successEntryType, SubjectType: "customer_portal_access", SubjectID: access.ID, ActorID: access.ID, PayloadHash: pkg.ManifestHash},
			customerPortalAuditEffect{EntryType: successEntryType, SubjectType: "customer_security_package", SubjectID: pkg.ID, ActorID: access.ID, PayloadHash: pkg.ManifestHash},
		)
		if err := s.persistCustomerPortalAccessUpdateLocked(ctx, previous, access, effects); err != nil {
			return domain.CustomerSecurityPackage{}, err
		}
		return packageWithDistributionWatermark(pkg, access), nil
	}
	return domain.CustomerSecurityPackage{}, ErrUnauthorized
}

type customerPortalAuditEffect struct {
	EntryType   string
	SubjectType string
	SubjectID   string
	ActorID     string
	PayloadHash string
}

// persistCustomerPortalAccessUpdateLocked uses the previous counters and
// revocation state as an optimistic predicate. A token-dependent update is
// therefore committed with its audit trail or remains invisible on conflict.
func (s identityService) persistCustomerPortalAccessUpdateLocked(ctx context.Context, previous, current domain.CustomerPortalAccess, effects []customerPortalAuditEffect) error {
	l := s.ledger
	if l.unitOfWork != nil {
		entries := []domain.AuditChainEntry{}
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Identity.UpdateCustomerPortalAccess(ctx, previous, current); err != nil {
				return err
			}
			for _, effect := range effects {
				entry, err := repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(l.now(), current.TenantID, effect.EntryType, effect.SubjectType, effect.SubjectID, "customer_portal", effect.ActorID, effect.PayloadHash, ""))
				if err != nil {
					return err
				}
				entries = append(entries, entry)
			}
			return nil
		}); err != nil {
			return err
		}
		l.portalAccess[current.ID] = current
		for _, entry := range entries {
			l.publishCommittedAuditEntryLocked(entry)
		}
		return nil
	}
	l.portalAccess[current.ID] = current
	for _, effect := range effects {
		_, _ = l.appendChainLocked(current.TenantID, effect.EntryType, effect.SubjectType, effect.SubjectID, "customer_portal", effect.ActorID, effect.PayloadHash, "")
	}
	return l.persistCriticalStateLocked(ctx)
}

func cleanReviewerEmail(value string) string {
	return strings.ToLower(cleanExternalLabel(value))
}

func validReviewerEmail(value string) bool {
	if strings.ContainsAny(value, " \t\r\n") {
		return false
	}
	at := strings.IndexByte(value, '@')
	return at > 0 && at < len(value)-1 && strings.Contains(value[at+1:], ".")
}

func (s packageReportService) CreateQuestionnaireTemplate(ctx context.Context, actor domain.Actor, in CreateQuestionnaireTemplateInput) (domain.QuestionnaireTemplate, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.QuestionnaireTemplate{}, err
	}
	if err := require(actor, ScopePackageWrite); err != nil {
		return domain.QuestionnaireTemplate{}, err
	}
	in.Name, in.Version = strings.TrimSpace(in.Name), strings.TrimSpace(in.Version)
	if in.Name == "" || in.Version == "" || len(in.Questions) == 0 {
		return domain.QuestionnaireTemplate{}, ErrValidation
	}
	questions := append([]domain.QuestionnaireQuestion(nil), in.Questions...)
	for i := range questions {
		questions[i].ID = strings.TrimSpace(questions[i].ID)
		questions[i].Prompt = strings.TrimSpace(questions[i].Prompt)
		questions[i].EvidenceType = strings.TrimSpace(questions[i].EvidenceType)
		if questions[i].ID == "" || questions[i].Prompt == "" {
			return domain.QuestionnaireTemplate{}, ErrValidation
		}
		questions[i].AllowedFields = sortedStrings(questions[i].AllowedFields)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	tpl := domain.QuestionnaireTemplate{ID: newID("qt"), TenantID: actor.TenantID, Name: in.Name, Version: in.Version, Questions: questions, SchemaVersion: domain.QuestionnaireTemplateVersion, CreatedAt: l.now()}
	l.questionTemplates[tpl.ID] = tpl
	_, _ = l.appendChainLocked(actor.TenantID, "questionnaire_template.created", "questionnaire_template", tpl.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.QuestionnaireTemplate{}, err
	}
	return tpl, nil
}

func (s packageReportService) CreateQuestionnairePackage(ctx context.Context, actor domain.Actor, in CreateQuestionnairePackageInput) (domain.QuestionnairePackage, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.QuestionnairePackage{}, err
	}
	if err := require(actor, ScopePackageWrite); err != nil {
		return domain.QuestionnairePackage{}, err
	}
	in.TemplateID, in.PackageID = strings.TrimSpace(in.TemplateID), strings.TrimSpace(in.PackageID)
	in.ProductID, in.ReleaseID = strings.TrimSpace(in.ProductID), strings.TrimSpace(in.ReleaseID)
	l.mu.Lock()
	defer l.mu.Unlock()
	tpl, ok := l.questionTemplates[in.TemplateID]
	if !ok || tpl.TenantID != actor.TenantID {
		return domain.QuestionnairePackage{}, ErrNotFound
	}
	if in.PackageID != "" {
		pkg, ok := l.customerPackages[in.PackageID]
		if !ok || pkg.TenantID != actor.TenantID {
			return domain.QuestionnairePackage{}, ErrNotFound
		}
	}
	if in.ProductID != "" || in.ReleaseID != "" {
		if err := l.ensureScopeLocked(actor.TenantID, in.ProductID, "", in.ReleaseID); err != nil {
			return domain.QuestionnairePackage{}, err
		}
	}
	responses := []domain.QuestionnaireResponse{}
	for _, question := range tpl.Questions {
		responses = append(responses, l.questionnaireResponseForQuestionLocked(actor.TenantID, question, in.ProductID, in.ReleaseID))
	}
	hash, err := canonicalAnyHash(responses)
	if err != nil {
		return domain.QuestionnairePackage{}, err
	}
	pkg := domain.QuestionnairePackage{ID: newID("qp"), TenantID: actor.TenantID, TemplateID: tpl.ID, PackageID: in.PackageID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Responses: responses, ManifestHash: hash, SchemaVersion: domain.QuestionnairePackageVersion, CreatedAt: l.now()}
	l.questionPackages[pkg.ID] = pkg
	_, _ = l.appendChainLocked(actor.TenantID, "questionnaire_package.generated", "questionnaire_package", pkg.ID, actorType(actor), actorID(actor), hash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.QuestionnairePackage{}, err
	}
	return pkg, nil
}

func (s packageReportService) CreateQuestionnaireAnswerLibraryEntry(ctx context.Context, actor domain.Actor, in CreateQuestionnaireAnswerLibraryEntryInput) (domain.QuestionnaireAnswerLibraryEntry, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.QuestionnaireAnswerLibraryEntry{}, err
	}
	if err := require(actor, ScopePackageWrite); err != nil {
		return domain.QuestionnaireAnswerLibraryEntry{}, err
	}
	in.QuestionID, in.EvidenceType, in.ControlID = strings.TrimSpace(in.QuestionID), strings.TrimSpace(in.EvidenceType), strings.TrimSpace(in.ControlID)
	in.ProductID, in.ReleaseID = strings.TrimSpace(in.ProductID), strings.TrimSpace(in.ReleaseID)
	in.Answer = strings.TrimSpace(in.Answer)
	if in.Answer == "" || (in.QuestionID == "" && in.EvidenceType == "" && in.ControlID == "") {
		return domain.QuestionnaireAnswerLibraryEntry{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if in.ProductID != "" || in.ReleaseID != "" {
		if err := l.ensureScopeLocked(actor.TenantID, in.ProductID, "", in.ReleaseID); err != nil {
			return domain.QuestionnaireAnswerLibraryEntry{}, err
		}
		if err := l.authorizeResourceLocked(actor, ScopePackageWrite, resourceRefs{ProductID: in.ProductID, ReleaseID: in.ReleaseID}); err != nil {
			return domain.QuestionnaireAnswerLibraryEntry{}, err
		}
	}
	if in.ControlID != "" {
		control, ok := l.controls[in.ControlID]
		if !ok || control.TenantID != actor.TenantID {
			return domain.QuestionnaireAnswerLibraryEntry{}, ErrNotFound
		}
	}
	evidenceIDs := sortedStrings(in.EvidenceIDs)
	for _, id := range evidenceIDs {
		item, ok := l.evidence[id]
		if !ok || item.TenantID != actor.TenantID || !evidenceMatchesRefs(item, resourceRefs{ProductID: in.ProductID, ReleaseID: in.ReleaseID}) {
			return domain.QuestionnaireAnswerLibraryEntry{}, ErrNotFound
		}
	}
	entry := domain.QuestionnaireAnswerLibraryEntry{
		ID:            newID("qal"),
		TenantID:      actor.TenantID,
		QuestionID:    in.QuestionID,
		EvidenceType:  in.EvidenceType,
		ControlID:     in.ControlID,
		ProductID:     in.ProductID,
		ReleaseID:     in.ReleaseID,
		Answer:        in.Answer,
		EvidenceIDs:   evidenceIDs,
		Limitations:   sortedStrings(in.Limitations),
		SchemaVersion: domain.QuestionnaireAnswerLibraryVersion,
		CreatedAt:     l.now(),
	}
	if len(entry.Limitations) == 0 {
		entry.Limitations = []string{"Answer library entries are reusable drafts and require human review before external use."}
	}
	l.answerLibrary[entry.ID] = entry
	_, _ = l.appendChainLocked(actor.TenantID, "questionnaire_answer_library.created", "questionnaire_answer_library", entry.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.QuestionnaireAnswerLibraryEntry{}, err
	}
	return entry, nil
}

func (s packageReportService) ListQuestionnaireAnswerLibrary(ctx context.Context, actor domain.Actor, in ListQuestionnaireAnswerLibraryInput) ([]domain.QuestionnaireAnswerLibraryEntry, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopePackageRead); err != nil {
		return nil, err
	}
	in.QuestionID, in.ProductID, in.ReleaseID = strings.TrimSpace(in.QuestionID), strings.TrimSpace(in.ProductID), strings.TrimSpace(in.ReleaseID)
	l.mu.Lock()
	defer l.mu.Unlock()
	if in.ProductID != "" || in.ReleaseID != "" {
		if err := l.ensureScopeLocked(actor.TenantID, in.ProductID, "", in.ReleaseID); err != nil {
			return nil, err
		}
		if err := l.authorizeResourceLocked(actor, ScopePackageRead, resourceRefs{ProductID: in.ProductID, ReleaseID: in.ReleaseID}); err != nil {
			return nil, err
		}
	}
	out := []domain.QuestionnaireAnswerLibraryEntry{}
	for _, entry := range l.answerLibrary {
		if entry.TenantID != actor.TenantID {
			continue
		}
		if in.QuestionID != "" && entry.QuestionID != in.QuestionID {
			continue
		}
		if in.ProductID != "" && entry.ProductID != "" && entry.ProductID != in.ProductID {
			continue
		}
		if in.ReleaseID != "" && entry.ReleaseID != "" && entry.ReleaseID != in.ReleaseID {
			continue
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (l *Ledger) CreateCommercialCollectorDefinition(ctx context.Context, actor domain.Actor, in CreateCommercialCollectorInput) (domain.CommercialCollectorDefinition, error) {
	if err := ctx.Err(); err != nil {
		return domain.CommercialCollectorDefinition{}, err
	}
	if err := require(actor, ScopeCollectorAdmin); err != nil {
		return domain.CommercialCollectorDefinition{}, err
	}
	in.Name, in.Provider, in.Version = strings.TrimSpace(in.Name), strings.TrimSpace(in.Provider), strings.TrimSpace(in.Version)
	if in.Name == "" || in.Provider == "" || in.Version == "" || !validDigest(in.ManifestHash) || !validCollectorScopes(in.AllowedScopes) {
		return domain.CommercialCollectorDefinition{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, existing := range l.commercialCollectors {
		if existing.TenantID == actor.TenantID && existing.Name == in.Name && existing.Provider == in.Provider && existing.Version == in.Version {
			return domain.CommercialCollectorDefinition{}, ErrConflict
		}
	}
	def := domain.CommercialCollectorDefinition{ID: newID("ccol"), TenantID: actor.TenantID, Name: in.Name, Provider: in.Provider, Version: in.Version, ManifestHash: in.ManifestHash, AllowedScopes: sortedStrings(in.AllowedScopes), Status: "available", SchemaVersion: domain.CommercialCollectorVersion, CreatedAt: l.now()}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Enterprise.InsertCommercialCollectorDefinition(ctx, def); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(def.CreatedAt, actor.TenantID, "commercial_collector.created", "commercial_collector", def.ID, actorType(actor), actorID(actor), in.ManifestHash, ""))
			return err
		}); err != nil {
			return domain.CommercialCollectorDefinition{}, err
		}
		l.commercialCollectors[def.ID] = def
		l.publishCommittedAuditEntryLocked(entry)
		return def, nil
	}
	l.commercialCollectors[def.ID] = def
	_, _ = l.appendChainLocked(actor.TenantID, "commercial_collector.created", "commercial_collector", def.ID, actorType(actor), actorID(actor), in.ManifestHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.CommercialCollectorDefinition{}, err
	}
	return def, nil
}

func (l *Ledger) ListCommercialCollectorDefinitions(ctx context.Context, actor domain.Actor) ([]domain.CommercialCollectorDefinition, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeCollectorRead); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []domain.CommercialCollectorDefinition{}
	for _, def := range l.commercialCollectors {
		if def.TenantID == actor.TenantID {
			out = append(out, def)
		}
	}
	return out, nil
}

func (l *Ledger) ensureRoleSubjectLocked(tenantID, subjectType, subjectID string) error {
	switch subjectType {
	case "user":
		user, ok := l.users[subjectID]
		if !ok || user.TenantID != tenantID {
			return ErrNotFound
		}
	case "collector":
		collector, ok := l.collectors[subjectID]
		if !ok || collector.TenantID != tenantID {
			return ErrNotFound
		}
	default:
		return ErrValidation
	}
	return nil
}

func (l *Ledger) ensureRetentionScopeLocked(tenantID, scopeType, scopeID string) error {
	switch scopeType {
	case "tenant":
		if tenant, ok := l.tenants[scopeID]; !ok || tenant.ID != tenantID {
			return ErrNotFound
		}
	case "product", "project", "release":
		return l.ensureScopeLocked(tenantID, ternary(scopeType == "product", scopeID, ""), ternary(scopeType == "project", scopeID, ""), ternary(scopeType == "release", scopeID, ""))
	case "evidence":
		item, ok := l.evidence[scopeID]
		if !ok || item.TenantID != tenantID {
			return ErrNotFound
		}
	default:
		return ErrValidation
	}
	return nil
}

func (l *Ledger) ensureRoleResourceLocked(tenantID, resourceType, resourceID string) error {
	switch resourceType {
	case "":
		if resourceID != "" {
			return ErrValidation
		}
	case "tenant":
		if resourceID == "" {
			return nil
		}
		tenant, ok := l.tenants[resourceID]
		if !ok || tenant.ID != tenantID {
			return ErrNotFound
		}
	case "product":
		product, ok := l.products[resourceID]
		if resourceID == "" || !ok || product.TenantID != tenantID {
			return ErrNotFound
		}
	case "project":
		project, ok := l.projects[resourceID]
		if resourceID == "" || !ok || project.TenantID != tenantID {
			return ErrNotFound
		}
	case "release":
		release, ok := l.releases[resourceID]
		if resourceID == "" || !ok || release.TenantID != tenantID {
			return ErrNotFound
		}
	case "customer_security_package":
		pkg, ok := l.customerPackages[resourceID]
		if resourceID == "" || !ok || pkg.TenantID != tenantID {
			return ErrNotFound
		}
	case "evidence_bundle":
		bundle, ok := l.evidenceBundles[resourceID]
		if resourceID == "" || !ok || bundle.TenantID != tenantID {
			return ErrNotFound
		}
	default:
		return ErrValidation
	}
	return nil
}

func validRoleSubject(value string) bool {
	return value == "user" || value == "collector"
}

func validRole(value string) bool {
	switch value {
	case "tenant_admin", "security_engineer", "release_manager", "customer_verifier", "collector":
		return true
	default:
		return false
	}
}

func (l *Ledger) resourceGrantsForUserLocked(userID string) []domain.ResourceGrant {
	grants := []domain.ResourceGrant{}
	for _, binding := range l.roleBindings {
		if binding.SubjectType != "user" || binding.SubjectID != userID {
			continue
		}
		scopes := scopesForRole(binding.Role)
		if len(scopes) == 0 {
			continue
		}
		grants = append(grants, domain.ResourceGrant{
			Role:         binding.Role,
			ResourceType: binding.ResourceType,
			ResourceID:   binding.ResourceID,
			Scopes:       scopes,
		})
	}
	return grants
}

func (l *Ledger) resourceGrantsForSSOSessionLocked(session domain.SSOSession) []domain.ResourceGrant {
	provider, ok := l.ssoProviders[session.ProviderID]
	if !ok || provider.TenantID != session.TenantID {
		return nil
	}
	return resourceGrantsForProviderGroups(provider, session.Groups)
}

func resourceGrantsForProviderGroups(provider domain.SSOProvider, groups []string) []domain.ResourceGrant {
	if provider.GroupsClaim == "" || len(provider.RoleMapping) == 0 || len(groups) == 0 {
		return nil
	}
	grants := []domain.ResourceGrant{}
	for _, group := range groups {
		role := strings.TrimSpace(provider.RoleMapping[group])
		if !validRole(role) {
			continue
		}
		scopes := scopesForRole(role)
		if len(scopes) == 0 {
			continue
		}
		grants = append(grants, domain.ResourceGrant{Role: role, Scopes: scopes})
	}
	return grants
}

func scopesFromResourceGrants(grants []domain.ResourceGrant) []string {
	scopes := map[string]struct{}{}
	for _, grant := range grants {
		for _, scope := range grant.Scopes {
			scopes[scope] = struct{}{}
		}
	}
	out := make([]string, 0, len(scopes))
	for scope := range scopes {
		out = append(out, scope)
	}
	return sortedStrings(out)
}

type resourceRefs struct {
	ProductID          string
	ProjectID          string
	ReleaseID          string
	ArtifactID         string
	BuildID            string
	DeploymentID       string
	EnvironmentID      string
	IncidentID         string
	SecurityScanID     string
	SourceRepositoryID string
	CustomerPackageID  string
	EvidenceBundleID   string
}

func refsForEvidence(item domain.EvidenceItem) resourceRefs {
	return resourceRefs{ProductID: item.ProductID, ProjectID: item.ProjectID, ReleaseID: item.ReleaseID}
}

func (l *Ledger) authorizeResourceLocked(actor domain.Actor, scope string, refs resourceRefs) error {
	if l.resourceAllowedLocked(actor, scope, refs) {
		return nil
	}
	return ErrForbidden
}

func (l *Ledger) resourceAllowedLocked(actor domain.Actor, scope string, refs resourceRefs) bool {
	if !humanSessionActor(actor) {
		return true
	}
	for _, grant := range actor.ResourceGrants {
		if !grantHasScope(grant, scope) {
			continue
		}
		if l.grantCoversResourceLocked(actor.TenantID, grant, refs) {
			return true
		}
	}
	return false
}

func humanSessionActor(actor domain.Actor) bool {
	return actor.UserID != "" && actor.KeyID == "" && actor.CollectorID == ""
}

func grantHasScope(grant domain.ResourceGrant, scope string) bool {
	for _, got := range grant.Scopes {
		if got == "*" || got == scope || got == ScopeAdmin {
			return true
		}
	}
	return false
}

func (l *Ledger) grantCoversResourceLocked(tenantID string, grant domain.ResourceGrant, refs resourceRefs) bool {
	switch grant.ResourceType {
	case "", "tenant":
		return grant.ResourceID == "" || grant.ResourceID == tenantID
	case "product":
		return grant.ResourceID != "" && l.productCoversRefsLocked(tenantID, grant.ResourceID, refs)
	case "project":
		return grant.ResourceID != "" && l.projectCoversRefsLocked(tenantID, grant.ResourceID, refs)
	case "release":
		return grant.ResourceID != "" && l.releaseCoversRefsLocked(tenantID, grant.ResourceID, refs)
	case "customer_security_package":
		return refs.CustomerPackageID != "" && refs.CustomerPackageID == grant.ResourceID
	case "evidence_bundle":
		return refs.EvidenceBundleID != "" && refs.EvidenceBundleID == grant.ResourceID
	default:
		return false
	}
}

func (l *Ledger) productCoversRefsLocked(tenantID, productID string, refs resourceRefs) bool {
	if refs == (resourceRefs{}) {
		return false
	}
	if refs.ProductID != "" && refs.ProductID != productID {
		return false
	}
	if refs.ProjectID != "" {
		project, ok := l.projects[refs.ProjectID]
		if !ok || project.TenantID != tenantID || project.ProductID != productID {
			return false
		}
	}
	if refs.SourceRepositoryID != "" {
		repo, ok := l.repositories[refs.SourceRepositoryID]
		if !ok || repo.TenantID != tenantID {
			return false
		}
		if repo.ProjectID == "" {
			return false
		}
		project, ok := l.projects[repo.ProjectID]
		if !ok || project.TenantID != tenantID || project.ProductID != productID {
			return false
		}
	}
	if refs.ReleaseID != "" {
		release, ok := l.releases[refs.ReleaseID]
		if !ok || release.TenantID != tenantID || release.ProductID != productID {
			return false
		}
	}
	if refs.BuildID != "" {
		build, ok := l.buildRuns[refs.BuildID]
		if !ok || build.TenantID != tenantID {
			return false
		}
		if build.ReleaseID != "" {
			release, ok := l.releases[build.ReleaseID]
			if !ok || release.TenantID != tenantID || release.ProductID != productID {
				return false
			}
		}
		if build.ProjectID != "" {
			project, ok := l.projects[build.ProjectID]
			if !ok || project.TenantID != tenantID || project.ProductID != productID {
				return false
			}
		}
	}
	if refs.EnvironmentID != "" {
		env, ok := l.environments[refs.EnvironmentID]
		if !ok || env.TenantID != tenantID || env.ProductID != productID {
			return false
		}
	}
	if refs.DeploymentID != "" {
		deployment, ok := l.deployments[refs.DeploymentID]
		if !ok || deployment.TenantID != tenantID {
			return false
		}
		release, ok := l.releases[deployment.ReleaseID]
		if !ok || release.TenantID != tenantID || release.ProductID != productID {
			return false
		}
	}
	if refs.IncidentID != "" {
		incident, ok := l.incidents[refs.IncidentID]
		if !ok || incident.TenantID != tenantID || incident.ProductID != productID {
			return false
		}
	}
	if refs.SecurityScanID != "" {
		scan, ok := l.securityScans[refs.SecurityScanID]
		if !ok || scan.TenantID != tenantID {
			return false
		}
		if scan.ProductID != "" && scan.ProductID != productID {
			return false
		}
		if scan.ReleaseID != "" {
			release, ok := l.releases[scan.ReleaseID]
			if !ok || release.TenantID != tenantID || release.ProductID != productID {
				return false
			}
		}
	}
	if refs.ArtifactID != "" && !l.artifactCoversProductLocked(tenantID, refs.ArtifactID, productID) {
		return false
	}
	if refs.CustomerPackageID != "" {
		pkg, ok := l.customerPackages[refs.CustomerPackageID]
		if !ok || pkg.TenantID != tenantID || pkg.ProductID != productID {
			return false
		}
	}
	if refs.EvidenceBundleID != "" {
		bundle, ok := l.evidenceBundles[refs.EvidenceBundleID]
		if !ok || bundle.TenantID != tenantID {
			return false
		}
		if bundle.ReleaseID != "" {
			release, ok := l.releases[bundle.ReleaseID]
			if !ok || release.TenantID != tenantID || release.ProductID != productID {
				return false
			}
		}
	}
	return true
}

func (l *Ledger) projectCoversRefsLocked(tenantID, projectID string, refs resourceRefs) bool {
	if refs.ProjectID != "" {
		project, ok := l.projects[refs.ProjectID]
		return ok && project.TenantID == tenantID && project.ID == projectID
	}
	if refs.SourceRepositoryID != "" {
		repo, ok := l.repositories[refs.SourceRepositoryID]
		return ok && repo.TenantID == tenantID && repo.ProjectID == projectID
	}
	if refs.BuildID != "" {
		build, ok := l.buildRuns[refs.BuildID]
		return ok && build.TenantID == tenantID && build.ProjectID == projectID
	}
	return false
}

func (l *Ledger) releaseCoversRefsLocked(tenantID, releaseID string, refs resourceRefs) bool {
	if refs.ReleaseID != "" {
		release, ok := l.releases[refs.ReleaseID]
		return ok && release.TenantID == tenantID && release.ID == releaseID
	}
	if refs.CustomerPackageID != "" {
		pkg, ok := l.customerPackages[refs.CustomerPackageID]
		return ok && pkg.TenantID == tenantID && pkg.ReleaseID == releaseID
	}
	if refs.EvidenceBundleID != "" {
		bundle, ok := l.evidenceBundles[refs.EvidenceBundleID]
		return ok && bundle.TenantID == tenantID && bundle.ReleaseID == releaseID
	}
	if refs.BuildID != "" {
		build, ok := l.buildRuns[refs.BuildID]
		return ok && build.TenantID == tenantID && build.ReleaseID == releaseID
	}
	if refs.DeploymentID != "" {
		deployment, ok := l.deployments[refs.DeploymentID]
		return ok && deployment.TenantID == tenantID && deployment.ReleaseID == releaseID
	}
	if refs.IncidentID != "" {
		incident, ok := l.incidents[refs.IncidentID]
		return ok && incident.TenantID == tenantID && incident.ReleaseID == releaseID
	}
	if refs.SecurityScanID != "" {
		scan, ok := l.securityScans[refs.SecurityScanID]
		return ok && scan.TenantID == tenantID && scan.ReleaseID == releaseID
	}
	if refs.ArtifactID != "" && l.artifactCoversReleaseLocked(tenantID, refs.ArtifactID, releaseID) {
		return true
	}
	return false
}

func (l *Ledger) artifactCoversProductLocked(tenantID, artifactID, productID string) bool {
	for _, item := range l.evidence {
		if item.TenantID == tenantID && item.ProductID == productID && evidenceReferencesArtifact(item, artifactID) {
			return true
		}
	}
	for _, build := range l.buildRuns {
		if build.TenantID != tenantID {
			continue
		}
		for _, output := range build.Outputs {
			if output.ArtifactID != artifactID {
				continue
			}
			release, ok := l.releases[build.ReleaseID]
			if ok && release.TenantID == tenantID && release.ProductID == productID {
				return true
			}
		}
	}
	return false
}

func (l *Ledger) artifactCoversReleaseLocked(tenantID, artifactID, releaseID string) bool {
	for _, item := range l.evidence {
		if item.TenantID == tenantID && item.ReleaseID == releaseID && evidenceReferencesArtifact(item, artifactID) {
			return true
		}
	}
	for _, build := range l.buildRuns {
		if build.TenantID != tenantID || build.ReleaseID != releaseID {
			continue
		}
		for _, output := range build.Outputs {
			if output.ArtifactID == artifactID {
				return true
			}
		}
	}
	return false
}

func evidenceReferencesArtifact(item domain.EvidenceItem, artifactID string) bool {
	for _, ref := range item.SubjectRefs {
		if ref.Type == "artifact" && ref.ID == artifactID {
			return true
		}
	}
	return false
}

func scopesForRole(role string) []string {
	switch role {
	case "tenant_admin":
		return []string{"*"}
	case "security_engineer":
		return []string{
			ScopeEvidenceRead, ScopeEvidenceWrite,
			ScopeSecurityRead, ScopeSecurityWrite,
			ScopeControlsRead, ScopeControlsWrite,
			ScopePolicyRead, ScopePolicyWrite,
			ScopeVerifyRead, ScopeReportRead,
		}
	case "release_manager":
		return []string{
			ScopeProductRead, ScopeProjectRead,
			ScopeReleaseRead, ScopeReleaseWrite,
			ScopeEvidenceRead, ScopeEvidenceWrite,
			ScopeBuildRead, ScopeBundleRead, ScopeBundleWrite,
			ScopeVerifyRead, ScopeReportRead,
		}
	case "customer_verifier":
		return []string{ScopePackageRead, ScopeBundleRead, ScopeVerifyRead, ScopeReportRead}
	case "collector":
		return []string{ScopeEvidenceWrite, ScopeBuildWrite, ScopeBundleWrite}
	default:
		return nil
	}
}

func oidcGroupsFromVerifiedToken(provider domain.SSOProvider, token string) []string {
	claimName := strings.TrimSpace(provider.GroupsClaim)
	if claimName == "" || token == "" || provider.Type != "oidc" {
		return nil
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil
	}
	return sortedStrings(stringClaimValues(claims[claimName]))
}

func stringClaimValues(value any) []string {
	seen := map[string]struct{}{}
	out := []string{}
	add := func(raw string) {
		item := strings.TrimSpace(raw)
		if item == "" {
			return
		}
		if _, ok := seen[item]; ok {
			return
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	switch got := value.(type) {
	case string:
		add(got)
	case []any:
		for _, item := range got {
			if text, ok := item.(string); ok {
				add(text)
			}
		}
	}
	return out
}

func validSSOType(value string) bool {
	return value == "oidc" || value == "saml"
}

func normalizeJWKS(jwks map[string]any) (map[string]any, error) {
	if len(jwks) == 0 {
		return nil, nil
	}
	body, err := json.Marshal(jwks)
	if err != nil || len(body) > 64*1024 {
		return nil, ErrValidation
	}
	var normalized map[string]any
	if err := json.Unmarshal(body, &normalized); err != nil {
		return nil, err
	}
	keys, ok := normalized["keys"].([]any)
	if !ok || len(keys) == 0 || len(keys) > 10 {
		return nil, ErrValidation
	}
	for _, raw := range keys {
		key, ok := raw.(map[string]any)
		if !ok {
			return nil, ErrValidation
		}
		kty, _ := key["kty"].(string)
		kid, _ := key["kid"].(string)
		if strings.TrimSpace(kid) == "" {
			return nil, ErrValidation
		}
		switch kty {
		case "OKP":
			crv, _ := key["crv"].(string)
			x, _ := key["x"].(string)
			if crv != "Ed25519" || strings.TrimSpace(x) == "" {
				return nil, ErrValidation
			}
		case "RSA":
			n, _ := key["n"].(string)
			e, _ := key["e"].(string)
			if strings.TrimSpace(n) == "" || strings.TrimSpace(e) == "" {
				return nil, ErrValidation
			}
		default:
			return nil, ErrValidation
		}
	}
	return normalized, nil
}

func normalizeSAMLSigningCertificates(certs []string) ([]string, error) {
	if len(certs) == 0 {
		return nil, nil
	}
	if len(certs) > 5 {
		return nil, ErrValidation
	}
	out := make([]string, 0, len(certs))
	for _, raw := range certs {
		value := strings.TrimSpace(raw)
		if value == "" || len(value) > 16*1024 {
			return nil, ErrValidation
		}
		block, _ := pem.Decode([]byte(value))
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, ErrValidation
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrValidation
		}
		if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
			return nil, ErrValidation
		}
		out = append(out, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
	}
	return out, nil
}

func validRetentionScope(value string) bool {
	switch value {
	case "tenant", "product", "project", "release", "evidence":
		return true
	default:
		return false
	}
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, v := range in {
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

func ternary(ok bool, a, b string) string {
	if ok {
		return a
	}
	return b
}
