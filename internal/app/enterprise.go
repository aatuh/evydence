package app

import (
	"context"
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
	Name        string
	Type        string
	Issuer      string
	ClientID    string
	GroupsClaim string
	RoleMapping map[string]string
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
	PackageID    string
	CustomerName string
	ExpiresAt    time.Time
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

type CreateCommercialCollectorInput struct {
	Name          string
	Provider      string
	Version       string
	ManifestHash  string
	AllowedScopes []string
}

func (l *Ledger) CreateOrganization(ctx context.Context, actor domain.Actor, in CreateOrganizationInput) (domain.Organization, error) {
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
	l.organizations[org.ID] = org
	_, _ = l.appendChainLocked(actor.TenantID, "organization.created", "organization", org.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.Organization{}, err
	}
	return org, nil
}

func (l *Ledger) CreateUser(ctx context.Context, actor domain.Actor, in CreateUserInput) (domain.HumanUser, error) {
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
	l.users[user.ID] = user
	_, _ = l.appendChainLocked(actor.TenantID, "user.created", "human_user", user.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.HumanUser{}, err
	}
	return user, nil
}

func (l *Ledger) DeactivateUser(ctx context.Context, actor domain.Actor, id string) (domain.HumanUser, error) {
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
	l.users[user.ID] = user
	_, _ = l.appendChainLocked(actor.TenantID, "user.deactivated", "human_user", user.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.HumanUser{}, err
	}
	return user, nil
}

func (l *Ledger) CreateRoleBinding(ctx context.Context, actor domain.Actor, in CreateRoleBindingInput) (domain.RoleBinding, error) {
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
	binding := domain.RoleBinding{ID: newID("rbac"), TenantID: actor.TenantID, SubjectType: in.SubjectType, SubjectID: in.SubjectID, Role: in.Role, ResourceType: in.ResourceType, ResourceID: in.ResourceID, SchemaVersion: domain.RoleBindingSchemaVersion, CreatedAt: l.now()}
	l.roleBindings[binding.ID] = binding
	_, _ = l.appendChainLocked(actor.TenantID, "role_binding.created", "role_binding", binding.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.RoleBinding{}, err
	}
	return binding, nil
}

func (l *Ledger) ListRoleBindings(ctx context.Context, actor domain.Actor) ([]domain.RoleBinding, error) {
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

func (l *Ledger) CreateSSOProvider(ctx context.Context, actor domain.Actor, in CreateSSOProviderInput) (domain.SSOProvider, error) {
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
	provider := domain.SSOProvider{ID: newID("sso"), TenantID: actor.TenantID, Name: in.Name, Type: in.Type, Issuer: in.Issuer, ClientID: in.ClientID, GroupsClaim: strings.TrimSpace(in.GroupsClaim), RoleMapping: cloneStringMap(in.RoleMapping), Status: "active", SchemaVersion: domain.SSOProviderSchemaVersion, CreatedAt: l.now()}
	l.ssoProviders[provider.ID] = provider
	_, _ = l.appendChainLocked(actor.TenantID, "sso_provider.created", "sso_provider", provider.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.SSOProvider{}, err
	}
	return provider, nil
}

func (l *Ledger) LinkSSOIdentity(ctx context.Context, actor domain.Actor, in LinkSSOIdentityInput) (domain.UserIdentityLink, error) {
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
	l.identityLinks[link.ID] = link
	_, _ = l.appendChainLocked(actor.TenantID, "identity_link.created", "human_user", user.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.UserIdentityLink{}, err
	}
	return link, nil
}

func (l *Ledger) CreateSSOSession(ctx context.Context, actor domain.Actor, in CreateSSOSessionInput) (domain.SSOSession, string, error) {
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
	l.ssoSessions[session.ID] = session
	_, _ = l.appendChainLocked(actor.TenantID, "sso_session.created", "human_user", user.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.SSOSession{}, "", err
	}
	session.Hash = ""
	return session, secret, nil
}

func (l *Ledger) RevokeSSOSession(ctx context.Context, actor domain.Actor, id string) (domain.SSOSession, error) {
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
	l.ssoSessions[session.ID] = session
	_, _ = l.appendChainLocked(actor.TenantID, "sso_session.revoked", "sso_session", session.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
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
	l.retentionOverrides[override.ID] = override
	_, _ = l.appendChainLocked(actor.TenantID, "retention_override.created", in.ScopeType, in.ScopeID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.RetentionOverride{}, err
	}
	return override, nil
}

func (l *Ledger) RetentionReport(ctx context.Context, actor domain.Actor, scopeType, scopeID string) (domain.RetentionReport, error) {
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

func (l *Ledger) CreateCustomerPortalAccess(ctx context.Context, actor domain.Actor, in CreateCustomerPortalAccessInput) (domain.CustomerPortalAccess, string, error) {
	if err := ctx.Err(); err != nil {
		return domain.CustomerPortalAccess{}, "", err
	}
	if err := require(actor, ScopePackageWrite); err != nil {
		return domain.CustomerPortalAccess{}, "", err
	}
	in.PackageID, in.CustomerName = strings.TrimSpace(in.PackageID), strings.TrimSpace(in.CustomerName)
	if in.PackageID == "" || in.CustomerName == "" || !in.ExpiresAt.After(l.now()) {
		return domain.CustomerPortalAccess{}, "", ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	pkg, ok := l.customerPackages[in.PackageID]
	if !ok || pkg.TenantID != actor.TenantID {
		return domain.CustomerPortalAccess{}, "", ErrNotFound
	}
	secret := "evycp_" + randomToken(32)
	access := domain.CustomerPortalAccess{ID: newID("cpa"), TenantID: actor.TenantID, PackageID: pkg.ID, CustomerName: in.CustomerName, Prefix: secretPrefix(secret), ExpiresAt: in.ExpiresAt.UTC(), SchemaVersion: domain.CustomerPortalAccessVersion, CreatedAt: l.now(), Hash: l.hashSecret(secret)}
	l.portalAccess[access.ID] = access
	_, _ = l.appendChainLocked(actor.TenantID, "customer_portal_access.created", "customer_security_package", pkg.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.CustomerPortalAccess{}, "", err
	}
	access.Hash = ""
	return access, secret, nil
}

func (l *Ledger) AccessCustomerPortalPackage(ctx context.Context, token string) (domain.CustomerSecurityPackage, error) {
	if err := ctx.Err(); err != nil {
		return domain.CustomerSecurityPackage{}, err
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return domain.CustomerSecurityPackage{}, ErrUnauthorized
	}
	hash := l.hashSecret(token)
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, access := range l.portalAccess {
		if access.Hash != hash || access.RevokedAt != nil || !access.ExpiresAt.After(l.now()) {
			continue
		}
		pkg, ok := l.customerPackages[access.PackageID]
		if !ok || pkg.TenantID != access.TenantID || !pkg.ExpiresAt.After(l.now()) {
			return domain.CustomerSecurityPackage{}, ErrNotFound
		}
		access.AccessCount++
		l.portalAccess[id] = access
		_, _ = l.appendChainLocked(access.TenantID, "customer_portal_package.accessed", "customer_security_package", pkg.ID, "customer_portal", access.ID, pkg.ManifestHash, "")
		if err := l.persistLocked(ctx); err != nil {
			return domain.CustomerSecurityPackage{}, err
		}
		return pkg, nil
	}
	return domain.CustomerSecurityPackage{}, ErrUnauthorized
}

func (l *Ledger) CreateQuestionnaireTemplate(ctx context.Context, actor domain.Actor, in CreateQuestionnaireTemplateInput) (domain.QuestionnaireTemplate, error) {
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

func (l *Ledger) CreateQuestionnairePackage(ctx context.Context, actor domain.Actor, in CreateQuestionnairePackageInput) (domain.QuestionnairePackage, error) {
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
		evidenceIDs := []string{}
		for _, item := range l.evidence {
			if item.TenantID == actor.TenantID && (in.ProductID == "" || item.ProductID == in.ProductID) && (in.ReleaseID == "" || item.ReleaseID == in.ReleaseID) && (question.EvidenceType == "" || item.Type == question.EvidenceType) {
				evidenceIDs = append(evidenceIDs, item.ID)
			}
		}
		answer := "No matching evidence was linked for this question."
		if len(evidenceIDs) > 0 {
			answer = "Evidence is available for review in the linked evidence records."
		}
		responses = append(responses, domain.QuestionnaireResponse{QuestionID: question.ID, Answer: answer, EvidenceIDs: sortedStrings(evidenceIDs), Limitations: []string{"Questionnaire responses summarize recorded evidence and require human review."}})
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

func (l *Ledger) scopesForUserLocked(userID string) []string {
	scopes := map[string]struct{}{}
	for _, binding := range l.roleBindings {
		if binding.SubjectType != "user" || binding.SubjectID != userID {
			continue
		}
		for _, scope := range scopesForRole(binding.Role) {
			scopes[scope] = struct{}{}
		}
	}
	out := make([]string, 0, len(scopes))
	for scope := range scopes {
		out = append(out, scope)
	}
	return sortedStrings(out)
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

func validSSOType(value string) bool {
	return value == "oidc" || value == "saml"
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
