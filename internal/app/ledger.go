package app

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/aatuh/evydence/internal/domain"
)

const (
	ScopeAdmin           = "admin"
	ScopeProductWrite    = "product:write"
	ScopeProductRead     = "product:read"
	ScopeProjectWrite    = "project:write"
	ScopeProjectRead     = "project:read"
	ScopeReleaseWrite    = "release:write"
	ScopeReleaseRead     = "release:read"
	ScopeEvidenceWrite   = "evidence:write"
	ScopeEvidenceRead    = "evidence:read"
	ScopeBundleWrite     = "bundle:write"
	ScopeBundleRead      = "bundle:read"
	ScopeVerifyRead      = "verify:read"
	ScopeKeysAdmin       = "keys:admin"
	ScopeCollectorAdmin  = "collector:admin"
	ScopeCollectorRead   = "collector:read"
	ScopeBuildWrite      = "build:write"
	ScopeBuildRead       = "build:read"
	ScopeSourceWrite     = "source:write"
	ScopeSourceRead      = "source:read"
	ScopeDeploymentWrite = "deployment:write"
	ScopeDeploymentRead  = "deployment:read"
	ScopeIncidentWrite   = "incident:write"
	ScopeIncidentRead    = "incident:read"
	ScopeSecurityWrite   = "security:write"
	ScopeSecurityRead    = "security:read"
	ScopePolicyWrite     = "policy:write"
	ScopePolicyRead      = "policy:read"
	ScopePackageWrite    = "package:write"
	ScopePackageRead     = "package:read"
	ScopeControlsAdmin   = "controls:admin"
	ScopeControlsRead    = "controls:read"
	ScopeControlsWrite   = "controls:write"
	ScopeReportRead      = "report:read"
	ScopeIdentityAdmin   = "identity:admin"
	ScopeInstanceAdmin   = "instance:admin"
)

const customerPortalFailedAccessLimit = 5

type Config struct {
	APIKeyPepper string
	Now          func() time.Time
	Store        Store
	ObjectStore  ObjectStore
	Retention    ObjectRetentionVerifier
	Signer       SigningExecutor
	OIDC         OIDCDiscoveryClient
	Transparency TransparencyProofFetcher
	Outbox       Outbox
	// WorkerOwnedParserSideEffects stores accepted parser records first and
	// lets outbox workers populate parser-derived fields from raw payloads.
	WorkerOwnedParserSideEffects bool
}

type Ledger struct {
	mu sync.Mutex

	pepper             []byte
	now                func() time.Time
	store              Store
	objects            ObjectStore
	retention          ObjectRetentionVerifier
	signer             SigningExecutor
	oidc               OIDCDiscoveryClient
	transparencyProofs TransparencyProofFetcher
	outbox             Outbox
	workerOwnedParsers bool

	tenants               map[string]domain.Tenant
	organizations         map[string]domain.Organization
	users                 map[string]domain.HumanUser
	roleBindings          map[string]domain.RoleBinding
	ssoProviders          map[string]domain.SSOProvider
	identityLinks         map[string]domain.UserIdentityLink
	ssoSessions           map[string]domain.SSOSession
	apiKeys               map[string]domain.APIKey
	collectors            map[string]domain.Collector
	collectorReleases     map[string]domain.CollectorRelease
	products              map[string]domain.Product
	projects              map[string]domain.Project
	releases              map[string]domain.Release
	artifacts             map[string]domain.Artifact
	buildRuns             map[string]domain.BuildRun
	attestations          map[string]domain.BuildAttestation
	evidence              map[string]domain.EvidenceItem
	lifecycle             map[string]domain.EvidenceLifecycleEvent
	candidates            map[string]domain.ReleaseCandidate
	images                map[string]domain.ContainerImage
	artifactSigs          map[string]domain.ArtifactSignature
	repositories          map[string]domain.SourceRepository
	commits               map[string]domain.SourceCommit
	branches              map[string]domain.SourceBranch
	pullRequests          map[string]domain.PullRequest
	environments          map[string]domain.DeploymentEnvironment
	deployments           map[string]domain.DeploymentEvent
	incidents             map[string]domain.Incident
	timeline              map[string]domain.IncidentTimelineEvent
	webhookReceivers      map[string]domain.IncidentWebhookReceiver
	webhookEvents         map[string]domain.IncidentWebhookEvent
	tasks                 map[string]domain.RemediationTask
	securityScans         map[string]domain.SecurityScan
	manualDocs            map[string]domain.ManualSecurityDocument
	sbomDiffs             map[string]domain.SBOMDiff
	depChanges            map[string]domain.DependencyChange
	vulnWorkflow          map[string]domain.VulnerabilityWorkflowRecord
	contractDiffs         map[string]domain.ContractDiff
	customPolicies        map[string]domain.CustomPolicy
	customPolicyEvals     map[string]domain.CustomPolicyEvaluation
	waivers               map[string]domain.Waiver
	approvals             map[string]domain.ApprovalRecord
	redactions            map[string]domain.RedactionProfile
	customerPackages      map[string]domain.CustomerSecurityPackage
	htmlReports           map[string]domain.HTMLReportPackage
	reportTemplates       map[string]domain.CustomReportTemplate
	renderedReports       map[string]domain.RenderedCustomReport
	evidenceBundles       map[string]domain.EvidenceBundle
	bundleImports         map[string]domain.EvidenceBundleImport
	dsseTrustRoots        map[string]domain.DSSETrustRoot
	cosignVerifs          map[string]domain.CosignVerification
	signingProviders      map[string]domain.SigningProvider
	merkleBatches         map[string]domain.MerkleBatch
	transparency          map[string]domain.TransparencyCheckpoint
	retentionPolicies     map[string]domain.ObjectRetentionPolicy
	backupManifests       map[string]domain.BackupManifest
	legalHolds            map[string]domain.LegalHold
	retentionOverrides    map[string]domain.RetentionOverride
	portalAccess          map[string]domain.CustomerPortalAccess
	questionTemplates     map[string]domain.QuestionnaireTemplate
	questionPackages      map[string]domain.QuestionnairePackage
	commercialCollectors  map[string]domain.CommercialCollectorDefinition
	evidenceSummaries     map[string]domain.EvidenceSummary
	questionDrafts        map[string]domain.QuestionnaireDraft
	graphSnapshots        map[string]domain.EvidenceGraphSnapshot
	saasProfiles          map[string]domain.SaaSEditionProfile
	publicLogs            map[string]domain.PublicTransparencyLog
	publicLogEntries      map[string]domain.PublicTransparencyLogEntry
	marketplaceCollectors map[string]domain.MarketplaceCollector
	pdfReports            map[string]domain.PDFReportPackage
	anomalyReports        map[string]domain.AnomalyReport
	providerVerifications map[string]domain.ProviderVerification
	signingOperations     map[string]domain.SigningOperation
	frameworks            map[string]domain.ControlFramework
	controls              map[string]domain.SecurityControl
	controlLinks          map[string]domain.ControlEvidence
	sboms                 map[string]domain.SBOM
	scans                 map[string]domain.VulnerabilityScan
	vexDocuments          map[string]domain.VEXDocument
	decisions             map[string]domain.VulnerabilityDecision
	contracts             map[string]domain.OpenAPIContract
	policies              map[string]domain.PolicyEvaluation
	exceptions            map[string]domain.Exception
	bundles               map[string]domain.ReleaseBundle
	signingKeys           map[string]domain.SigningKey
	signatures            map[string]domain.Signature
	verifications         map[string]domain.VerificationResult
	chain                 map[string][]domain.AuditChainEntry
	idempotency           map[string]IdempotencyRecord
}

func NewLedger(cfg Config) *Ledger {
	ledger, err := NewLedgerWithError(cfg)
	if err != nil {
		panic(err)
	}
	return ledger
}

func NewLedgerWithError(cfg Config) (*Ledger, error) {
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	pepper := strings.TrimSpace(cfg.APIKeyPepper)
	if pepper == "" {
		pepper = "local-dev-pepper-change-me"
	}
	retention := cfg.Retention
	if retention == nil && cfg.ObjectStore != nil {
		if verifier, ok := cfg.ObjectStore.(ObjectRetentionVerifier); ok {
			retention = verifier
		}
	}
	ledger := &Ledger{
		pepper:                []byte(pepper),
		now:                   now,
		store:                 cfg.Store,
		objects:               cfg.ObjectStore,
		retention:             retention,
		signer:                cfg.Signer,
		oidc:                  cfg.OIDC,
		transparencyProofs:    cfg.Transparency,
		outbox:                cfg.Outbox,
		workerOwnedParsers:    cfg.WorkerOwnedParserSideEffects,
		tenants:               map[string]domain.Tenant{},
		organizations:         map[string]domain.Organization{},
		users:                 map[string]domain.HumanUser{},
		roleBindings:          map[string]domain.RoleBinding{},
		ssoProviders:          map[string]domain.SSOProvider{},
		identityLinks:         map[string]domain.UserIdentityLink{},
		ssoSessions:           map[string]domain.SSOSession{},
		apiKeys:               map[string]domain.APIKey{},
		collectors:            map[string]domain.Collector{},
		collectorReleases:     map[string]domain.CollectorRelease{},
		products:              map[string]domain.Product{},
		projects:              map[string]domain.Project{},
		releases:              map[string]domain.Release{},
		artifacts:             map[string]domain.Artifact{},
		buildRuns:             map[string]domain.BuildRun{},
		attestations:          map[string]domain.BuildAttestation{},
		evidence:              map[string]domain.EvidenceItem{},
		lifecycle:             map[string]domain.EvidenceLifecycleEvent{},
		candidates:            map[string]domain.ReleaseCandidate{},
		images:                map[string]domain.ContainerImage{},
		artifactSigs:          map[string]domain.ArtifactSignature{},
		repositories:          map[string]domain.SourceRepository{},
		commits:               map[string]domain.SourceCommit{},
		branches:              map[string]domain.SourceBranch{},
		pullRequests:          map[string]domain.PullRequest{},
		environments:          map[string]domain.DeploymentEnvironment{},
		deployments:           map[string]domain.DeploymentEvent{},
		incidents:             map[string]domain.Incident{},
		timeline:              map[string]domain.IncidentTimelineEvent{},
		webhookReceivers:      map[string]domain.IncidentWebhookReceiver{},
		webhookEvents:         map[string]domain.IncidentWebhookEvent{},
		tasks:                 map[string]domain.RemediationTask{},
		securityScans:         map[string]domain.SecurityScan{},
		manualDocs:            map[string]domain.ManualSecurityDocument{},
		sbomDiffs:             map[string]domain.SBOMDiff{},
		depChanges:            map[string]domain.DependencyChange{},
		vulnWorkflow:          map[string]domain.VulnerabilityWorkflowRecord{},
		contractDiffs:         map[string]domain.ContractDiff{},
		customPolicies:        map[string]domain.CustomPolicy{},
		customPolicyEvals:     map[string]domain.CustomPolicyEvaluation{},
		waivers:               map[string]domain.Waiver{},
		approvals:             map[string]domain.ApprovalRecord{},
		redactions:            map[string]domain.RedactionProfile{},
		customerPackages:      map[string]domain.CustomerSecurityPackage{},
		htmlReports:           map[string]domain.HTMLReportPackage{},
		reportTemplates:       map[string]domain.CustomReportTemplate{},
		renderedReports:       map[string]domain.RenderedCustomReport{},
		evidenceBundles:       map[string]domain.EvidenceBundle{},
		bundleImports:         map[string]domain.EvidenceBundleImport{},
		dsseTrustRoots:        map[string]domain.DSSETrustRoot{},
		cosignVerifs:          map[string]domain.CosignVerification{},
		signingProviders:      map[string]domain.SigningProvider{},
		merkleBatches:         map[string]domain.MerkleBatch{},
		transparency:          map[string]domain.TransparencyCheckpoint{},
		retentionPolicies:     map[string]domain.ObjectRetentionPolicy{},
		backupManifests:       map[string]domain.BackupManifest{},
		legalHolds:            map[string]domain.LegalHold{},
		retentionOverrides:    map[string]domain.RetentionOverride{},
		portalAccess:          map[string]domain.CustomerPortalAccess{},
		questionTemplates:     map[string]domain.QuestionnaireTemplate{},
		questionPackages:      map[string]domain.QuestionnairePackage{},
		commercialCollectors:  map[string]domain.CommercialCollectorDefinition{},
		evidenceSummaries:     map[string]domain.EvidenceSummary{},
		questionDrafts:        map[string]domain.QuestionnaireDraft{},
		graphSnapshots:        map[string]domain.EvidenceGraphSnapshot{},
		saasProfiles:          map[string]domain.SaaSEditionProfile{},
		publicLogs:            map[string]domain.PublicTransparencyLog{},
		publicLogEntries:      map[string]domain.PublicTransparencyLogEntry{},
		marketplaceCollectors: map[string]domain.MarketplaceCollector{},
		pdfReports:            map[string]domain.PDFReportPackage{},
		anomalyReports:        map[string]domain.AnomalyReport{},
		providerVerifications: map[string]domain.ProviderVerification{},
		signingOperations:     map[string]domain.SigningOperation{},
		frameworks:            map[string]domain.ControlFramework{},
		controls:              map[string]domain.SecurityControl{},
		controlLinks:          map[string]domain.ControlEvidence{},
		sboms:                 map[string]domain.SBOM{},
		scans:                 map[string]domain.VulnerabilityScan{},
		vexDocuments:          map[string]domain.VEXDocument{},
		decisions:             map[string]domain.VulnerabilityDecision{},
		contracts:             map[string]domain.OpenAPIContract{},
		policies:              map[string]domain.PolicyEvaluation{},
		exceptions:            map[string]domain.Exception{},
		bundles:               map[string]domain.ReleaseBundle{},
		signingKeys:           map[string]domain.SigningKey{},
		signatures:            map[string]domain.Signature{},
		verifications:         map[string]domain.VerificationResult{},
		chain:                 map[string][]domain.AuditChainEntry{},
		idempotency:           map[string]IdempotencyRecord{},
	}
	if ledger.outbox == nil {
		ledger.outbox = nopOutbox{}
	}
	if cfg.Store != nil {
		state, ok, err := cfg.Store.LoadState(context.Background())
		if err != nil {
			return nil, err
		}
		if ok {
			ledger.applyState(state)
		}
	}
	return ledger, nil
}

func (l *Ledger) HasTenants() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.tenants) > 0
}

func (l *Ledger) BootstrapTenant(ctx context.Context, name, keyName string, scopes []string) (domain.Tenant, domain.APIKey, string, error) {
	if err := ctx.Err(); err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", err
	}
	name = strings.TrimSpace(name)
	keyName = strings.TrimSpace(keyName)
	if name == "" || keyName == "" {
		return domain.Tenant{}, domain.APIKey{}, "", ErrValidation
	}
	if len(scopes) == 0 {
		scopes = []string{"*"}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	tenant := domain.Tenant{ID: newID("ten"), Name: name, CreatedAt: now}
	l.tenants[tenant.ID] = tenant
	key, secret, err := l.createAPIKeyLocked(tenant.ID, keyName, scopes, nil)
	if err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", err
	}
	if _, err := l.rotateSigningKeyLocked(tenant.ID, "bootstrap"); err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", err
	}
	_, _ = l.appendChainLocked(tenant.ID, "tenant.created", "tenant", tenant.ID, "system", "bootstrap", "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.Tenant{}, domain.APIKey{}, "", err
	}
	return tenant, key, secret, nil
}

func (l *Ledger) Authenticate(ctx context.Context, secret string) (domain.Actor, error) {
	if err := ctx.Err(); err != nil {
		return domain.Actor{}, err
	}
	secret = strings.TrimSpace(strings.TrimPrefix(secret, "Bearer "))
	if secret == "" {
		return domain.Actor{}, ErrUnauthorized
	}
	prefix := secretPrefix(secret)
	hash := l.hashSecret(secret)
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, key := range l.apiKeys {
		if key.Prefix != prefix || !secretHashEqual(key.Hash, hash) || key.RevokedAt != nil {
			continue
		}
		if key.ExpiresAt != nil && !key.ExpiresAt.After(l.now()) {
			return domain.Actor{}, ErrUnauthorized
		}
		now := l.now()
		key.LastUsedAt = &now
		l.apiKeys[id] = key
		collectorID := ""
		for collectorMapID, collector := range l.collectors {
			if collector.TenantID == key.TenantID && collector.APIKeyID == key.ID {
				collectorID = collector.ID
				collector.LastSeenAt = &now
				l.collectors[collectorMapID] = collector
				break
			}
		}
		_ = l.persistLocked(ctx)
		return domain.Actor{TenantID: key.TenantID, KeyID: key.ID, Name: key.Name, Scopes: append([]string(nil), key.Scopes...), CollectorID: collectorID}, nil
	}
	for id, session := range l.ssoSessions {
		if session.Prefix != prefix || !secretHashEqual(session.Hash, hash) || session.RevokedAt != nil || !session.ExpiresAt.After(l.now()) {
			continue
		}
		user, ok := l.users[session.UserID]
		if !ok || user.TenantID != session.TenantID || user.Status != "active" {
			return domain.Actor{}, ErrUnauthorized
		}
		grants := append(l.resourceGrantsForUserLocked(user.ID), l.resourceGrantsForSSOSessionLocked(session)...)
		scopes := scopesFromResourceGrants(grants)
		if len(scopes) == 0 {
			return domain.Actor{}, ErrForbidden
		}
		l.ssoSessions[id] = session
		_ = l.persistLocked(ctx)
		return domain.Actor{TenantID: user.TenantID, UserID: user.ID, SessionID: session.ID, Name: user.Email, Scopes: scopes, ResourceGrants: grants}, nil
	}
	return domain.Actor{}, ErrUnauthorized
}

func (l *Ledger) CreateAPIKey(ctx context.Context, actor domain.Actor, name string, scopes []string, expiresAt *time.Time) (domain.APIKey, string, error) {
	if err := ctx.Err(); err != nil {
		return domain.APIKey{}, "", err
	}
	if err := require(actor, ScopeAdmin); err != nil {
		return domain.APIKey{}, "", err
	}
	if strings.TrimSpace(name) == "" || len(scopes) == 0 {
		return domain.APIKey{}, "", ErrValidation
	}
	if err := requireGrantableScopes(actor, scopes); err != nil {
		return domain.APIKey{}, "", err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key, secret, err := l.createAPIKeyLocked(actor.TenantID, name, scopes, expiresAt)
	if err != nil {
		return domain.APIKey{}, "", err
	}
	_, _ = l.appendChainLocked(actor.TenantID, "api_key.created", "api_key", key.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.APIKey{}, "", err
	}
	return key, secret, nil
}

func (l *Ledger) ListAPIKeys(ctx context.Context, actor domain.Actor) ([]domain.APIKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeAdmin); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []domain.APIKey{}
	for _, key := range l.apiKeys {
		if key.TenantID == actor.TenantID {
			key.Hash = ""
			out = append(out, key)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (l *Ledger) CreateProduct(ctx context.Context, actor domain.Actor, name, slug string) (domain.Product, error) {
	if err := ctx.Err(); err != nil {
		return domain.Product{}, err
	}
	if err := require(actor, ScopeProductWrite); err != nil {
		return domain.Product{}, err
	}
	name, slug = strings.TrimSpace(name), strings.TrimSpace(slug)
	if name == "" || slug == "" {
		return domain.Product{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.authorizeResourceLocked(actor, ScopeProductWrite, resourceRefs{}); err != nil {
		return domain.Product{}, err
	}
	for _, existing := range l.products {
		if existing.TenantID == actor.TenantID && existing.Slug == slug {
			return domain.Product{}, ErrConflict
		}
	}
	product := domain.Product{ID: newID("prod"), TenantID: actor.TenantID, Name: name, Slug: slug, CreatedAt: l.now()}
	l.products[product.ID] = product
	_, _ = l.appendChainLocked(actor.TenantID, "product.created", "product", product.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.Product{}, err
	}
	return product, nil
}

func (l *Ledger) ListProducts(ctx context.Context, actor domain.Actor) ([]domain.Product, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeProductRead); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []domain.Product{}
	for _, product := range l.products {
		if product.TenantID == actor.TenantID && l.resourceAllowedLocked(actor, ScopeProductRead, resourceRefs{ProductID: product.ID}) {
			out = append(out, product)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (l *Ledger) CreateProject(ctx context.Context, actor domain.Actor, productID, name string) (domain.Project, error) {
	if err := ctx.Err(); err != nil {
		return domain.Project{}, err
	}
	if err := require(actor, ScopeProjectWrite); err != nil {
		return domain.Project{}, err
	}
	productID, name = strings.TrimSpace(productID), strings.TrimSpace(name)
	if productID == "" || name == "" {
		return domain.Project{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	product, ok := l.products[productID]
	if !ok || product.TenantID != actor.TenantID {
		return domain.Project{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeProjectWrite, resourceRefs{ProductID: product.ID}); err != nil {
		return domain.Project{}, err
	}
	project := domain.Project{ID: newID("proj"), TenantID: actor.TenantID, ProductID: productID, Name: name, CreatedAt: l.now()}
	l.projects[project.ID] = project
	_, _ = l.appendChainLocked(actor.TenantID, "project.created", "project", project.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.Project{}, err
	}
	return project, nil
}

func (l *Ledger) CreateRelease(ctx context.Context, actor domain.Actor, productID, version string) (domain.Release, error) {
	if err := ctx.Err(); err != nil {
		return domain.Release{}, err
	}
	if err := require(actor, ScopeReleaseWrite); err != nil {
		return domain.Release{}, err
	}
	productID, version = strings.TrimSpace(productID), strings.TrimSpace(version)
	if productID == "" || version == "" {
		return domain.Release{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	product, ok := l.products[productID]
	if !ok || product.TenantID != actor.TenantID {
		return domain.Release{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeReleaseWrite, resourceRefs{ProductID: product.ID}); err != nil {
		return domain.Release{}, err
	}
	for _, existing := range l.releases {
		if existing.TenantID == actor.TenantID && existing.ProductID == productID && existing.Version == version {
			return domain.Release{}, ErrConflict
		}
	}
	release := domain.Release{ID: newID("rel"), TenantID: actor.TenantID, ProductID: productID, Version: version, State: "draft", CreatedAt: l.now()}
	l.releases[release.ID] = release
	_, _ = l.appendChainLocked(actor.TenantID, "release.created", "release", release.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.Release{}, err
	}
	return release, nil
}

func (l *Ledger) GetRelease(ctx context.Context, actor domain.Actor, releaseID string) (domain.Release, error) {
	if err := ctx.Err(); err != nil {
		return domain.Release{}, err
	}
	if err := require(actor, ScopeReleaseRead); err != nil {
		return domain.Release{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	release, ok := l.releases[strings.TrimSpace(releaseID)]
	if !ok || release.TenantID != actor.TenantID {
		return domain.Release{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeReleaseRead, resourceRefs{ReleaseID: release.ID}); err != nil {
		return domain.Release{}, err
	}
	return release, nil
}

func (l *Ledger) FreezeRelease(ctx context.Context, actor domain.Actor, releaseID string) (domain.Release, error) {
	if err := ctx.Err(); err != nil {
		return domain.Release{}, err
	}
	if err := require(actor, ScopeReleaseWrite); err != nil {
		return domain.Release{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	release, ok := l.releases[strings.TrimSpace(releaseID)]
	if !ok || release.TenantID != actor.TenantID {
		return domain.Release{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeReleaseWrite, resourceRefs{ReleaseID: release.ID}); err != nil {
		return domain.Release{}, err
	}
	if release.State != "draft" {
		return domain.Release{}, ErrConflict
	}
	now := l.now()
	release.State = "frozen"
	release.FrozenAt = &now
	l.releases[release.ID] = release
	_, _ = l.appendChainLocked(actor.TenantID, "release.frozen", "release", release.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.Release{}, err
	}
	return release, nil
}

func (l *Ledger) ApproveRelease(ctx context.Context, actor domain.Actor, releaseID string) (domain.Release, error) {
	if err := ctx.Err(); err != nil {
		return domain.Release{}, err
	}
	if err := require(actor, ScopeReleaseWrite); err != nil {
		return domain.Release{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	release, ok := l.releases[strings.TrimSpace(releaseID)]
	if !ok || release.TenantID != actor.TenantID {
		return domain.Release{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeReleaseWrite, resourceRefs{ReleaseID: release.ID}); err != nil {
		return domain.Release{}, err
	}
	if release.State != "frozen" {
		return domain.Release{}, ErrConflict
	}
	now := l.now()
	release.State = "approved"
	release.ApprovedAt = &now
	l.releases[release.ID] = release
	_, _ = l.appendChainLocked(actor.TenantID, "release.approved", "release", release.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.Release{}, err
	}
	return release, nil
}

func (l *Ledger) RegisterArtifact(ctx context.Context, actor domain.Actor, name, mediaType, digest string, size int64) (domain.Artifact, error) {
	if err := ctx.Err(); err != nil {
		return domain.Artifact{}, err
	}
	if err := require(actor, ScopeEvidenceWrite); err != nil {
		return domain.Artifact{}, err
	}
	name, digest = strings.TrimSpace(name), strings.TrimSpace(digest)
	if name == "" || !validDigest(digest) || size < 0 {
		return domain.Artifact{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, existing := range l.artifacts {
		if existing.TenantID == actor.TenantID && existing.Digest == digest {
			return existing, nil
		}
	}
	artifact := domain.Artifact{ID: newID("art"), TenantID: actor.TenantID, Name: name, MediaType: mediaType, Size: size, Digest: digest, CreatedAt: l.now()}
	l.artifacts[artifact.ID] = artifact
	_, _ = l.appendChainLocked(actor.TenantID, "artifact.created", "artifact", artifact.ID, "api_key", actor.KeyID, digest, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.Artifact{}, err
	}
	return artifact, nil
}

type CreateEvidenceInput struct {
	ProductID        string
	ProjectID        string
	ReleaseID        string
	BuildID          string
	DeploymentID     string
	Type             string
	Subtype          string
	Title            string
	SourceSystem     string
	SourceIdentity   map[string]any
	CollectorID      string
	ObservedAt       time.Time
	PayloadRef       string
	PayloadHash      string
	PayloadMediaType string
	PayloadSize      int64
	SubjectRefs      []domain.SubjectRef
	Metadata         map[string]any
	Tags             []string
	Limitations      []string
}

func (l *Ledger) CreateEvidence(ctx context.Context, actor domain.Actor, in CreateEvidenceInput) (domain.EvidenceItem, error) {
	if err := ctx.Err(); err != nil {
		return domain.EvidenceItem{}, err
	}
	if err := require(actor, ScopeEvidenceWrite); err != nil {
		return domain.EvidenceItem{}, err
	}
	in.Type = strings.TrimSpace(in.Type)
	in.Title = strings.TrimSpace(in.Title)
	in.PayloadHash = strings.TrimSpace(in.PayloadHash)
	if in.Type == "" || in.Title == "" || !validDigest(in.PayloadHash) {
		return domain.EvidenceItem{}, ErrValidation
	}
	if in.ObservedAt.IsZero() {
		in.ObservedAt = l.now()
	}
	if actor.CollectorID != "" {
		in.CollectorID = actor.CollectorID
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ensureScopeLocked(actor.TenantID, in.ProductID, in.ProjectID, in.ReleaseID); err != nil {
		return domain.EvidenceItem{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceWrite, resourceRefs{ProductID: in.ProductID, ProjectID: in.ProjectID, ReleaseID: in.ReleaseID}); err != nil {
		return domain.EvidenceItem{}, err
	}
	now := l.now()
	item := domain.EvidenceItem{
		ID:                  newID("ev"),
		TenantID:            actor.TenantID,
		ProductID:           in.ProductID,
		ProjectID:           in.ProjectID,
		ReleaseID:           in.ReleaseID,
		BuildID:             in.BuildID,
		DeploymentID:        in.DeploymentID,
		Type:                in.Type,
		Subtype:             strings.TrimSpace(in.Subtype),
		Title:               in.Title,
		SourceSystem:        nonEmpty(in.SourceSystem, "api"),
		SourceIdentity:      cloneMap(in.SourceIdentity),
		CollectorID:         strings.TrimSpace(in.CollectorID),
		UploadedBy:          actor.KeyID,
		ObservedAt:          in.ObservedAt.UTC(),
		EvidenceVersion:     1,
		SchemaVersion:       domain.EvidenceItemSchemaVersion,
		PayloadRef:          strings.TrimSpace(in.PayloadRef),
		PayloadHash:         in.PayloadHash,
		PayloadMediaType:    strings.TrimSpace(in.PayloadMediaType),
		PayloadSize:         in.PayloadSize,
		Canonicalization:    domain.CanonicalizationProfileVersion,
		SubjectRefs:         append([]domain.SubjectRef(nil), in.SubjectRefs...),
		TrustLevel:          "L2",
		VerificationStatus:  "pending",
		Tags:                sortedStrings(in.Tags),
		Metadata:            cloneMap(in.Metadata),
		Limitations:         append([]string(nil), in.Limitations...),
		CreatedAt:           now,
		RelatedEvidenceRefs: nil,
	}
	hash, err := canonicalHash(item)
	if err != nil {
		return domain.EvidenceItem{}, err
	}
	item.CanonicalHash = hash
	entry, err := l.appendChainLocked(actor.TenantID, "evidence.created", "evidence_item", item.ID, "api_key", actor.KeyID, item.PayloadHash, "")
	if err != nil {
		return domain.EvidenceItem{}, err
	}
	item.ChainEntryID = entry.ID
	l.evidence[item.ID] = item
	if err := l.persistLocked(ctx); err != nil {
		return domain.EvidenceItem{}, err
	}
	return item, nil
}

func (l *Ledger) GetEvidence(ctx context.Context, actor domain.Actor, id string) (domain.EvidenceItem, error) {
	if err := ctx.Err(); err != nil {
		return domain.EvidenceItem{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return domain.EvidenceItem{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	item, ok := l.evidence[strings.TrimSpace(id)]
	if !ok || item.TenantID != actor.TenantID {
		return domain.EvidenceItem{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, refsForEvidence(item)); err != nil {
		return domain.EvidenceItem{}, err
	}
	return item, nil
}

func (l *Ledger) ListEvidence(ctx context.Context, actor domain.Actor, releaseID, typ string) ([]domain.EvidenceItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []domain.EvidenceItem{}
	for _, item := range l.evidence {
		if item.TenantID != actor.TenantID {
			continue
		}
		if releaseID != "" && item.ReleaseID != releaseID {
			continue
		}
		if typ != "" && item.Type != typ {
			continue
		}
		if !l.resourceAllowedLocked(actor, ScopeEvidenceRead, refsForEvidence(item)) {
			continue
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (l *Ledger) SupersedeEvidence(ctx context.Context, actor domain.Actor, id, replacementID, reason string) (domain.EvidenceItem, error) {
	if err := ctx.Err(); err != nil {
		return domain.EvidenceItem{}, err
	}
	if err := require(actor, ScopeEvidenceWrite); err != nil {
		return domain.EvidenceItem{}, err
	}
	if strings.TrimSpace(reason) == "" {
		return domain.EvidenceItem{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	item, ok := l.evidence[strings.TrimSpace(id)]
	replacement, rok := l.evidence[strings.TrimSpace(replacementID)]
	if !ok || !rok || item.TenantID != actor.TenantID || replacement.TenantID != actor.TenantID {
		return domain.EvidenceItem{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceWrite, refsForEvidence(item)); err != nil {
		return domain.EvidenceItem{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceWrite, refsForEvidence(replacement)); err != nil {
		return domain.EvidenceItem{}, err
	}
	if item.SupersededBy != "" {
		return domain.EvidenceItem{}, ErrConflict
	}
	item.SupersededBy = replacement.ID
	replacement.Supersedes = item.ID
	l.evidence[item.ID] = item
	l.evidence[replacement.ID] = replacement
	_, _ = l.appendChainLocked(actor.TenantID, "evidence.superseded", "evidence_item", item.ID, "api_key", actor.KeyID, item.PayloadHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.EvidenceItem{}, err
	}
	return item, nil
}

func (l *Ledger) LinkEvidence(ctx context.Context, actor domain.Actor, id, targetType, targetID string) (domain.EvidenceItem, error) {
	if err := ctx.Err(); err != nil {
		return domain.EvidenceItem{}, err
	}
	if err := require(actor, ScopeEvidenceWrite); err != nil {
		return domain.EvidenceItem{}, err
	}
	targetType, targetID = strings.TrimSpace(targetType), strings.TrimSpace(targetID)
	if targetType == "" || targetID == "" {
		return domain.EvidenceItem{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	item, ok := l.evidence[strings.TrimSpace(id)]
	if !ok || item.TenantID != actor.TenantID {
		return domain.EvidenceItem{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceWrite, refsForEvidence(item)); err != nil {
		return domain.EvidenceItem{}, err
	}
	switch targetType {
	case "release":
		rel, ok := l.releases[targetID]
		if !ok || rel.TenantID != actor.TenantID {
			return domain.EvidenceItem{}, ErrNotFound
		}
		if err := l.authorizeResourceLocked(actor, ScopeEvidenceWrite, resourceRefs{ReleaseID: rel.ID}); err != nil {
			return domain.EvidenceItem{}, err
		}
		item.ReleaseID = targetID
	case "product":
		prod, ok := l.products[targetID]
		if !ok || prod.TenantID != actor.TenantID {
			return domain.EvidenceItem{}, ErrNotFound
		}
		if err := l.authorizeResourceLocked(actor, ScopeEvidenceWrite, resourceRefs{ProductID: prod.ID}); err != nil {
			return domain.EvidenceItem{}, err
		}
		item.ProductID = targetID
	default:
		return domain.EvidenceItem{}, ErrValidation
	}
	item.RelatedEvidenceRefs = append(item.RelatedEvidenceRefs, domain.EvidenceRef{Type: targetType, ID: targetID, Relationship: "linked_to"})
	l.evidence[item.ID] = item
	_, _ = l.appendChainLocked(actor.TenantID, "evidence.linked", "evidence_item", item.ID, "api_key", actor.KeyID, item.PayloadHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.EvidenceItem{}, err
	}
	return item, nil
}

func (l *Ledger) UploadSBOM(ctx context.Context, actor domain.Actor, releaseID, artifactID string, raw []byte) (domain.SBOM, error) {
	if err := ctx.Err(); err != nil {
		return domain.SBOM{}, err
	}
	if err := require(actor, ScopeEvidenceWrite); err != nil {
		return domain.SBOM{}, err
	}
	if len(raw) == 0 || len(raw) > 20<<20 {
		return domain.SBOM{}, ErrValidation
	}
	var doc struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Components  []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"components"`
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil || strings.ToLower(doc.BOMFormat) != "cyclonedx" {
		return domain.SBOM{}, ErrValidation
	}
	components := make([]domain.SBOMComponent, 0, len(doc.Components))
	for _, component := range doc.Components {
		if strings.TrimSpace(component.Name) == "" {
			return domain.SBOM{}, ErrValidation
		}
		components = append(components, domain.SBOMComponent{Name: component.Name, Version: component.Version, PURL: component.PURL})
	}
	l.mu.Lock()
	if err := l.ensureScopeLocked(actor.TenantID, "", "", strings.TrimSpace(releaseID)); err != nil {
		l.mu.Unlock()
		return domain.SBOM{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceWrite, resourceRefs{ReleaseID: strings.TrimSpace(releaseID)}); err != nil {
		l.mu.Unlock()
		return domain.SBOM{}, err
	}
	l.mu.Unlock()
	payloadHash := hashBytes(raw)
	payloadRef, err := l.storePayload(ctx, actor.TenantID, "sbom", "application/vnd.cyclonedx+json", payloadHash, raw)
	if err != nil {
		return domain.SBOM{}, err
	}
	item, err := l.CreateEvidence(ctx, actor, CreateEvidenceInput{
		ReleaseID:        releaseID,
		Type:             "sbom",
		Subtype:          "cyclonedx",
		Title:            "CycloneDX SBOM",
		SourceSystem:     "api",
		ObservedAt:       l.now(),
		PayloadRef:       payloadRef,
		PayloadHash:      payloadHash,
		PayloadMediaType: "application/vnd.cyclonedx+json",
		PayloadSize:      int64(len(raw)),
		SubjectRefs:      subjectForArtifact(artifactID),
		Metadata: map[string]any{
			"sbom_format":       "cyclonedx",
			"sbom_spec_version": doc.SpecVersion,
			"component_count":   len(components),
		},
	})
	if err != nil {
		return domain.SBOM{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	sbom := domain.SBOM{ID: newID("sbom"), TenantID: actor.TenantID, EvidenceID: item.ID, ReleaseID: releaseID, ArtifactID: artifactID, Format: "cyclonedx", SpecVersion: doc.SpecVersion, ComponentCount: len(components), Components: components, CreatedAt: l.now()}
	persistedSBOM := sbom
	chainAction := "sbom.parsed"
	if l.workerOwnedParsers {
		persistedSBOM.SpecVersion = ""
		persistedSBOM.ComponentCount = 0
		persistedSBOM.Components = nil
		chainAction = "sbom.accepted"
	}
	l.sboms[sbom.ID] = persistedSBOM
	_, _ = l.appendChainLocked(actor.TenantID, chainAction, "sbom", sbom.ID, "api_key", actor.KeyID, payloadHash, "")
	if err := l.enqueue(ctx, actor.TenantID, "parse_sbom", "sbom", sbom.ID, map[string]any{"payload_ref": payloadRef, "payload_hash": payloadHash, "parser_version": ParserVersionCycloneDXJSON}); err != nil {
		return domain.SBOM{}, err
	}
	if err := l.persistLocked(ctx); err != nil {
		return domain.SBOM{}, err
	}
	return sbom, nil
}

func (l *Ledger) UploadVulnerabilityScan(ctx context.Context, actor domain.Actor, raw []byte) (domain.VulnerabilityScan, error) {
	if err := ctx.Err(); err != nil {
		return domain.VulnerabilityScan{}, err
	}
	if err := require(actor, ScopeEvidenceWrite); err != nil {
		return domain.VulnerabilityScan{}, err
	}
	if len(raw) == 0 || len(raw) > 20<<20 {
		return domain.VulnerabilityScan{}, ErrValidation
	}
	var doc struct {
		Scanner   string `json:"scanner"`
		TargetRef string `json:"target_ref"`
		Findings  []struct {
			Vulnerability string `json:"vulnerability"`
			Component     string `json:"component"`
			Severity      string `json:"severity"`
			State         string `json:"state"`
		} `json:"findings"`
		ReleaseID string `json:"release_id"`
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil || strings.TrimSpace(doc.Scanner) == "" || strings.TrimSpace(doc.TargetRef) == "" {
		return domain.VulnerabilityScan{}, ErrValidation
	}
	if doc.ReleaseID == "" {
		return domain.VulnerabilityScan{}, ErrValidation
	}
	l.mu.Lock()
	release, ok := l.releases[strings.TrimSpace(doc.ReleaseID)]
	if !ok || release.TenantID != actor.TenantID {
		l.mu.Unlock()
		return domain.VulnerabilityScan{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceWrite, resourceRefs{ProductID: release.ProductID, ReleaseID: release.ID}); err != nil {
		l.mu.Unlock()
		return domain.VulnerabilityScan{}, err
	}
	l.mu.Unlock()
	payloadHash := hashBytes(raw)
	payloadRef, err := l.storePayload(ctx, actor.TenantID, "vulnerability-scan", "application/json", payloadHash, raw)
	if err != nil {
		return domain.VulnerabilityScan{}, err
	}
	item, err := l.CreateEvidence(ctx, actor, CreateEvidenceInput{
		ReleaseID:        doc.ReleaseID,
		Type:             "vulnerability_scan",
		Subtype:          "generic",
		Title:            "Generic vulnerability scan",
		SourceSystem:     doc.Scanner,
		ObservedAt:       l.now(),
		PayloadRef:       payloadRef,
		PayloadHash:      payloadHash,
		PayloadMediaType: "application/json",
		PayloadSize:      int64(len(raw)),
		Metadata:         map[string]any{"scanner": doc.Scanner, "target_ref": doc.TargetRef},
	})
	if err != nil {
		return domain.VulnerabilityScan{}, err
	}
	summary := map[string]int{}
	findings := make([]domain.VulnerabilityFinding, 0, len(doc.Findings))
	for _, finding := range doc.Findings {
		if finding.Vulnerability == "" || finding.Severity == "" {
			return domain.VulnerabilityScan{}, ErrValidation
		}
		severity := strings.ToLower(finding.Severity)
		summary[severity]++
		state := nonEmpty(finding.State, "open")
		findings = append(findings, domain.VulnerabilityFinding{ID: newID("vf"), Vulnerability: finding.Vulnerability, Component: finding.Component, Severity: severity, State: state})
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	scan := domain.VulnerabilityScan{ID: newID("scan"), TenantID: actor.TenantID, EvidenceID: item.ID, ReleaseID: doc.ReleaseID, Scanner: doc.Scanner, TargetRef: doc.TargetRef, Summary: summary, Findings: findings, CreatedAt: l.now()}
	l.scans[scan.ID] = scan
	_, _ = l.appendChainLocked(actor.TenantID, "vulnerability_scan.parsed", "vulnerability_scan", scan.ID, "api_key", actor.KeyID, payloadHash, "")
	if err := l.enqueue(ctx, actor.TenantID, "parse_vulnerability_scan", "vulnerability_scan", scan.ID, map[string]any{"payload_ref": payloadRef, "payload_hash": payloadHash, "parser_version": ParserVersionGenericVulnerabilityJSON}); err != nil {
		return domain.VulnerabilityScan{}, err
	}
	if err := l.persistLocked(ctx); err != nil {
		return domain.VulnerabilityScan{}, err
	}
	return scan, nil
}

func (l *Ledger) UploadOpenAPIContract(ctx context.Context, actor domain.Actor, productID, releaseID, version string, raw []byte) (domain.OpenAPIContract, error) {
	if err := ctx.Err(); err != nil {
		return domain.OpenAPIContract{}, err
	}
	if err := require(actor, ScopeEvidenceWrite); err != nil {
		return domain.OpenAPIContract{}, err
	}
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(raw)
	if err != nil {
		return domain.OpenAPIContract{}, ErrValidation
	}
	if err := doc.Validate(ctx); err != nil {
		return domain.OpenAPIContract{}, ErrValidation
	}
	operations := extractOpenAPIOperations(doc)
	l.mu.Lock()
	if err := l.ensureScopeLocked(actor.TenantID, strings.TrimSpace(productID), "", strings.TrimSpace(releaseID)); err != nil {
		l.mu.Unlock()
		return domain.OpenAPIContract{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceWrite, resourceRefs{ProductID: strings.TrimSpace(productID), ReleaseID: strings.TrimSpace(releaseID)}); err != nil {
		l.mu.Unlock()
		return domain.OpenAPIContract{}, err
	}
	l.mu.Unlock()
	payloadHash := hashBytes(raw)
	payloadRef, err := l.storePayload(ctx, actor.TenantID, "openapi-contract", "application/vnd.oai.openapi+json", payloadHash, raw)
	if err != nil {
		return domain.OpenAPIContract{}, err
	}
	item, err := l.CreateEvidence(ctx, actor, CreateEvidenceInput{
		ProductID:        productID,
		ReleaseID:        releaseID,
		Type:             "openapi_contract",
		Subtype:          "openapi",
		Title:            "OpenAPI contract",
		SourceSystem:     "api",
		ObservedAt:       l.now(),
		PayloadRef:       payloadRef,
		PayloadHash:      payloadHash,
		PayloadMediaType: "application/vnd.oai.openapi+json",
		PayloadSize:      int64(len(raw)),
		Metadata:         map[string]any{"version": version, "path_count": len(doc.Paths.Map())},
	})
	if err != nil {
		return domain.OpenAPIContract{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	contract := domain.OpenAPIContract{ID: newID("oas"), TenantID: actor.TenantID, ProductID: productID, ReleaseID: releaseID, Version: version, Hash: payloadHash, PathCount: len(doc.Paths.Map()), Operations: operations, EvidenceID: item.ID, CreatedAt: l.now()}
	l.contracts[contract.ID] = contract
	_, _ = l.appendChainLocked(actor.TenantID, "openapi_contract.parsed", "openapi_contract", contract.ID, "api_key", actor.KeyID, contract.Hash, "")
	if err := l.enqueue(ctx, actor.TenantID, "parse_openapi_contract", "openapi_contract", contract.ID, map[string]any{"payload_ref": payloadRef, "payload_hash": payloadHash, "parser_version": ParserVersionOpenAPIJSON}); err != nil {
		return domain.OpenAPIContract{}, err
	}
	if err := l.persistLocked(ctx); err != nil {
		return domain.OpenAPIContract{}, err
	}
	return contract, nil
}

func extractOpenAPIOperations(doc *openapi3.T) []domain.OpenAPIOperation {
	if doc == nil || doc.Paths == nil {
		return nil
	}
	paths := doc.Paths.Map()
	pathNames := make([]string, 0, len(paths))
	for path := range paths {
		pathNames = append(pathNames, path)
	}
	sort.Strings(pathNames)
	out := make([]domain.OpenAPIOperation, 0)
	for _, path := range pathNames {
		item := paths[path]
		for _, methodOperation := range openAPIMethodOperations(item) {
			operation := methodOperation.operation
			if operation == nil {
				continue
			}
			out = append(out, domain.OpenAPIOperation{
				Path:                  path,
				Method:                strings.ToUpper(methodOperation.method),
				OperationID:           operation.OperationID,
				Deprecated:            operation.Deprecated,
				RequestBodyRequired:   openAPIRequestBodyRequired(operation),
				RequiredRequestFields: openAPIRequiredRequestFields(operation),
				ResponseStatuses:      openAPIResponseStatuses(operation),
			})
		}
	}
	return out
}

type openAPIMethodOperation struct {
	method    string
	operation *openapi3.Operation
}

func openAPIMethodOperations(item *openapi3.PathItem) []openAPIMethodOperation {
	if item == nil {
		return nil
	}
	return []openAPIMethodOperation{
		{method: "connect", operation: item.Connect},
		{method: "delete", operation: item.Delete},
		{method: "get", operation: item.Get},
		{method: "head", operation: item.Head},
		{method: "options", operation: item.Options},
		{method: "patch", operation: item.Patch},
		{method: "post", operation: item.Post},
		{method: "put", operation: item.Put},
		{method: "trace", operation: item.Trace},
	}
}

func openAPIRequestBodyRequired(operation *openapi3.Operation) bool {
	return operation != nil && operation.RequestBody != nil && operation.RequestBody.Value != nil && operation.RequestBody.Value.Required
}

func openAPIRequiredRequestFields(operation *openapi3.Operation) []string {
	if operation == nil || operation.RequestBody == nil || operation.RequestBody.Value == nil {
		return nil
	}
	fields := map[string]struct{}{}
	for _, media := range operation.RequestBody.Value.Content {
		if media == nil || media.Schema == nil || media.Schema.Value == nil {
			continue
		}
		for _, field := range media.Schema.Value.Required {
			if strings.TrimSpace(field) != "" {
				fields[strings.TrimSpace(field)] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(fields))
	for field := range fields {
		out = append(out, field)
	}
	sort.Strings(out)
	return out
}

func openAPIResponseStatuses(operation *openapi3.Operation) []string {
	if operation == nil || operation.Responses == nil {
		return nil
	}
	statuses := make([]string, 0, len(operation.Responses.Map()))
	for status := range operation.Responses.Map() {
		statuses = append(statuses, status)
	}
	sort.Strings(statuses)
	return statuses
}

func (l *Ledger) EvaluateRelease(ctx context.Context, actor domain.Actor, releaseID string) (domain.PolicyEvaluation, error) {
	if err := ctx.Err(); err != nil {
		return domain.PolicyEvaluation{}, err
	}
	if err := require(actor, ScopeVerifyRead); err != nil {
		return domain.PolicyEvaluation{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	release, ok := l.releases[strings.TrimSpace(releaseID)]
	if !ok || release.TenantID != actor.TenantID {
		return domain.PolicyEvaluation{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeVerifyRead, resourceRefs{ReleaseID: release.ID}); err != nil {
		return domain.PolicyEvaluation{}, err
	}
	checks := []domain.PolicyCheck{
		l.checkReleaseHasEvidenceLocked(actor.TenantID, release.ID, "sbom", "release_requires_sbom", "high"),
		l.checkReleaseHasEvidenceLocked(actor.TenantID, release.ID, "vulnerability_scan", "release_requires_vulnerability_scan", "high"),
		l.checkReleaseHasArtifactDigestLocked(actor.TenantID, release.ID),
		l.checkReleaseHasSignedBundleLocked(actor.TenantID, release.ID),
		l.checkReleaseHasPassedBuildLocked(actor.TenantID, release.ID),
		l.checkReleaseHasBuildAttestationLocked(actor.TenantID, release.ID),
		l.checkNoOpenCriticalLocked(actor.TenantID, release.ID),
	}
	result := "passed"
	for _, check := range checks {
		if check.Result == "failed" {
			result = "failed"
			break
		}
	}
	eval := domain.PolicyEvaluation{ID: newID("pe"), TenantID: actor.TenantID, ReleaseID: release.ID, Result: result, PolicySet: domain.PolicySetVersion, Checks: checks, CreatedAt: l.now()}
	l.policies[eval.ID] = eval
	_, _ = l.appendChainLocked(actor.TenantID, "policy.evaluated", "policy_evaluation", eval.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.PolicyEvaluation{}, err
	}
	return eval, nil
}

func (l *Ledger) CreateReleaseBundle(ctx context.Context, actor domain.Actor, releaseID string) (domain.ReleaseBundle, error) {
	if err := ctx.Err(); err != nil {
		return domain.ReleaseBundle{}, err
	}
	if err := require(actor, ScopeBundleWrite); err != nil {
		return domain.ReleaseBundle{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	release, ok := l.releases[strings.TrimSpace(releaseID)]
	if !ok || release.TenantID != actor.TenantID {
		return domain.ReleaseBundle{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeBundleWrite, resourceRefs{ReleaseID: release.ID}); err != nil {
		return domain.ReleaseBundle{}, err
	}
	evidenceIDs := []string{}
	for _, item := range l.evidence {
		if item.TenantID == actor.TenantID && item.ReleaseID == release.ID {
			evidenceIDs = append(evidenceIDs, item.ID)
		}
	}
	sort.Strings(evidenceIDs)
	head := ""
	entries := l.chain[actor.TenantID]
	if len(entries) > 0 {
		head = entries[len(entries)-1].EntryHash
	}
	bundleID := newID("rb")
	manifest := map[string]any{
		"manifest_version": domain.ReleaseBundleSchemaVersion,
		"bundle_id":        bundleID,
		"tenant_id":        actor.TenantID,
		"release": map[string]any{
			"id":      release.ID,
			"version": release.Version,
			"state":   release.State,
		},
		"evidence_ids": evidenceIDs,
		"chain_checkpoint": map[string]any{
			"sequence":  len(entries),
			"head_hash": head,
		},
		"generated_at": l.now().UTC().Format(time.RFC3339Nano),
		"generator": map[string]any{
			"name":    "evydence",
			"version": "dev",
		},
	}
	manifestHash, err := canonicalAnyHash(manifest)
	if err != nil {
		return domain.ReleaseBundle{}, err
	}
	sig, err := l.signLocked(actor.TenantID, "release_bundle", bundleID, []byte(manifestHash))
	if err != nil {
		return domain.ReleaseBundle{}, err
	}
	bundle := domain.ReleaseBundle{ID: bundleID, TenantID: actor.TenantID, ReleaseID: release.ID, State: "generated", Manifest: manifest, ManifestHash: manifestHash, SignatureRefs: []string{sig.ID}, CreatedAt: l.now()}
	l.bundles[bundle.ID] = bundle
	_, _ = l.appendChainLocked(actor.TenantID, "bundle.generated", "release_bundle", bundle.ID, "api_key", actor.KeyID, manifestHash, sig.ID)
	if err := l.enqueue(ctx, actor.TenantID, "sign_bundle", "release_bundle", bundle.ID, map[string]any{"manifest_hash": manifestHash}); err != nil {
		return domain.ReleaseBundle{}, err
	}
	if err := l.persistLocked(ctx); err != nil {
		return domain.ReleaseBundle{}, err
	}
	return bundle, nil
}

func (l *Ledger) GetReleaseBundle(ctx context.Context, actor domain.Actor, id string) (domain.ReleaseBundle, error) {
	if err := ctx.Err(); err != nil {
		return domain.ReleaseBundle{}, err
	}
	if err := require(actor, ScopeBundleRead); err != nil {
		return domain.ReleaseBundle{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	bundle, ok := l.bundles[strings.TrimSpace(id)]
	if !ok || bundle.TenantID != actor.TenantID {
		return domain.ReleaseBundle{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeBundleRead, resourceRefs{ReleaseID: bundle.ReleaseID}); err != nil {
		return domain.ReleaseBundle{}, err
	}
	return bundle, nil
}

func (l *Ledger) GetSBOM(ctx context.Context, actor domain.Actor, id string) (domain.SBOM, error) {
	if err := ctx.Err(); err != nil {
		return domain.SBOM{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return domain.SBOM{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	sbom, ok := l.sboms[strings.TrimSpace(id)]
	if !ok || sbom.TenantID != actor.TenantID {
		return domain.SBOM{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ReleaseID: sbom.ReleaseID}); err != nil {
		return domain.SBOM{}, err
	}
	return sbom, nil
}

type ListSBOMComponentsInput struct {
	SBOMID     string
	ReleaseID  string
	ArtifactID string
	Query      string
	PURL       string
	Limit      int
}

func (l *Ledger) ListSBOMComponents(ctx context.Context, actor domain.Actor, in ListSBOMComponentsInput) ([]domain.SBOMComponentRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return nil, err
	}
	in.SBOMID = strings.TrimSpace(in.SBOMID)
	in.ReleaseID = strings.TrimSpace(in.ReleaseID)
	in.ArtifactID = strings.TrimSpace(in.ArtifactID)
	in.Query = strings.ToLower(strings.TrimSpace(in.Query))
	in.PURL = strings.TrimSpace(in.PURL)
	if in.Limit < 0 || in.Limit > 500 {
		return nil, ErrValidation
	}
	if in.Limit == 0 {
		in.Limit = 100
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if in.SBOMID != "" {
		sbom, ok := l.sboms[in.SBOMID]
		if !ok || sbom.TenantID != actor.TenantID {
			return nil, ErrNotFound
		}
	}
	ids := make([]string, 0, len(l.sboms))
	for id := range l.sboms {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]domain.SBOMComponentRecord, 0)
	for _, id := range ids {
		sbom := l.sboms[id]
		if sbom.TenantID != actor.TenantID {
			continue
		}
		if in.SBOMID != "" && sbom.ID != in.SBOMID {
			continue
		}
		if in.ReleaseID != "" && sbom.ReleaseID != in.ReleaseID {
			continue
		}
		if in.ArtifactID != "" && sbom.ArtifactID != in.ArtifactID {
			continue
		}
		if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ReleaseID: sbom.ReleaseID, ArtifactID: sbom.ArtifactID}); err != nil {
			return nil, err
		}
		for _, component := range sbom.Components {
			if !sbomComponentMatches(component, in.Query, in.PURL) {
				continue
			}
			out = append(out, domain.SBOMComponentRecord{SBOMID: sbom.ID, ReleaseID: sbom.ReleaseID, ArtifactID: sbom.ArtifactID, Format: sbom.Format, SpecVersion: sbom.SpecVersion, Component: component})
			if len(out) >= in.Limit {
				return out, nil
			}
		}
	}
	return out, nil
}

func sbomComponentMatches(component domain.SBOMComponent, query, purl string) bool {
	if purl != "" && component.PURL != purl {
		return false
	}
	if query == "" {
		return true
	}
	haystack := strings.ToLower(component.Name + "\n" + component.Version + "\n" + component.PURL)
	return strings.Contains(haystack, query)
}

func (l *Ledger) GetVulnerabilityScan(ctx context.Context, actor domain.Actor, id string) (domain.VulnerabilityScan, error) {
	if err := ctx.Err(); err != nil {
		return domain.VulnerabilityScan{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return domain.VulnerabilityScan{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	scan, ok := l.scans[strings.TrimSpace(id)]
	if !ok || scan.TenantID != actor.TenantID {
		return domain.VulnerabilityScan{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ReleaseID: scan.ReleaseID}); err != nil {
		return domain.VulnerabilityScan{}, err
	}
	return scan, nil
}

func (l *Ledger) GetOpenAPIContract(ctx context.Context, actor domain.Actor, id string) (domain.OpenAPIContract, error) {
	if err := ctx.Err(); err != nil {
		return domain.OpenAPIContract{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return domain.OpenAPIContract{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	contract, ok := l.contracts[strings.TrimSpace(id)]
	if !ok || contract.TenantID != actor.TenantID {
		return domain.OpenAPIContract{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ProductID: contract.ProductID, ReleaseID: contract.ReleaseID}); err != nil {
		return domain.OpenAPIContract{}, err
	}
	return contract, nil
}

func (l *Ledger) VerifySubject(ctx context.Context, actor domain.Actor, subjectType, subjectID string) (domain.VerificationResult, error) {
	if err := ctx.Err(); err != nil {
		return domain.VerificationResult{}, err
	}
	if err := require(actor, ScopeVerifyRead); err != nil {
		return domain.VerificationResult{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	checks := []domain.VerifyCheck{}
	result := "passed"
	switch strings.TrimSpace(subjectType) {
	case "audit_chain":
		if err := l.authorizeResourceLocked(actor, ScopeVerifyRead, resourceRefs{}); err != nil {
			return domain.VerificationResult{}, err
		}
		checks = l.verifyChainLocked(actor.TenantID)
	case "evidence_item":
		item, ok := l.evidence[strings.TrimSpace(subjectID)]
		if !ok || item.TenantID != actor.TenantID {
			return domain.VerificationResult{}, ErrNotFound
		}
		if err := l.authorizeResourceLocked(actor, ScopeVerifyRead, refsForEvidence(item)); err != nil {
			return domain.VerificationResult{}, err
		}
		hash, err := canonicalHash(item)
		if err != nil || hash != item.CanonicalHash {
			result = "failed"
			checks = append(checks, domain.VerifyCheck{Name: "canonical_hash", Result: "failed"})
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "canonical_hash", Result: "passed"})
		}
	case "release_bundle":
		bundle, ok := l.bundles[strings.TrimSpace(subjectID)]
		if !ok || bundle.TenantID != actor.TenantID {
			return domain.VerificationResult{}, ErrNotFound
		}
		if err := l.authorizeResourceLocked(actor, ScopeVerifyRead, resourceRefs{ReleaseID: bundle.ReleaseID}); err != nil {
			return domain.VerificationResult{}, err
		}
		hash, err := canonicalAnyHash(bundle.Manifest)
		if err != nil || hash != bundle.ManifestHash {
			result = "failed"
			checks = append(checks, domain.VerifyCheck{Name: "manifest_hash", Result: "failed"})
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "manifest_hash", Result: "passed"})
		}
		if !l.verifySignatureLocked(bundle.TenantID, bundle.SignatureRefs, []byte(bundle.ManifestHash)) {
			result = "failed"
			checks = append(checks, domain.VerifyCheck{Name: "bundle_signature", Result: "failed"})
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "bundle_signature", Result: "passed"})
		}
	case "artifact_signature":
		sig, ok := l.artifactSigs[strings.TrimSpace(subjectID)]
		if !ok || sig.TenantID != actor.TenantID {
			return domain.VerificationResult{}, ErrNotFound
		}
		if err := l.authorizeResourceLocked(actor, ScopeVerifyRead, resourceRefs{ArtifactID: sig.ArtifactID}); err != nil {
			return domain.VerificationResult{}, err
		}
		artifact, ok := l.artifacts[sig.ArtifactID]
		if !ok || artifact.TenantID != actor.TenantID {
			return domain.VerificationResult{}, ErrNotFound
		}
		if artifact.Digest != sig.SubjectDigest {
			result = "failed"
			checks = append(checks, domain.VerifyCheck{Name: "subject_digest", Result: "failed"})
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "subject_digest", Result: "passed"})
		}
		if sig.Algorithm == "" || sig.Signature == "" {
			result = "failed"
			checks = append(checks, domain.VerifyCheck{Name: "signature_present", Result: "failed"})
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "signature_present", Result: "passed", Detail: "signature recorded; cryptographic trust-root verification is deferred"})
		}
	default:
		return domain.VerificationResult{}, ErrValidation
	}
	for _, check := range checks {
		if check.Result != "passed" {
			result = "failed"
		}
	}
	vr := domain.VerificationResult{ID: newID("vr"), TenantID: actor.TenantID, SubjectType: subjectType, SubjectID: subjectID, Result: result, Checks: checks, VerifiedAt: l.now()}
	l.verifications[vr.ID] = vr
	if err := l.enqueue(ctx, actor.TenantID, "verify_subject", subjectType, subjectID, map[string]any{"result_id": vr.ID}); err != nil {
		return domain.VerificationResult{}, err
	}
	if err := l.persistLocked(ctx); err != nil {
		return domain.VerificationResult{}, err
	}
	if result != "passed" {
		return vr, ErrVerificationFailed
	}
	return vr, nil
}

func (l *Ledger) RotateSigningKey(ctx context.Context, actor domain.Actor, reason string) (domain.SigningKey, error) {
	if err := ctx.Err(); err != nil {
		return domain.SigningKey{}, err
	}
	if err := require(actor, ScopeKeysAdmin); err != nil {
		return domain.SigningKey{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key, err := l.rotateSigningKeyLocked(actor.TenantID, reason)
	if err != nil {
		return domain.SigningKey{}, err
	}
	_, _ = l.appendChainLocked(actor.TenantID, "signing_key.rotated", "signing_key", key.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.SigningKey{}, err
	}
	return key, nil
}

func (l *Ledger) ListSigningKeys(ctx context.Context, actor domain.Actor) ([]domain.SigningKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeVerifyRead); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []domain.SigningKey{}
	for _, key := range l.signingKeys {
		if key.TenantID == actor.TenantID {
			key.Private = nil
			out = append(out, key)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (l *Ledger) MissingEvidenceReport(ctx context.Context, actor domain.Actor, releaseID string) (map[string]any, error) {
	eval, err := l.EvaluateRelease(ctx, actor, releaseID)
	if err != nil && !errors.Is(err, ErrVerificationFailed) {
		return nil, err
	}
	missing := []string{}
	for _, check := range eval.Checks {
		missing = append(missing, check.Missing...)
	}
	sort.Strings(missing)
	return map[string]any{
		"report_type":      "missing_evidence",
		"template_version": "missing-evidence.v1.0.0",
		"release_id":       releaseID,
		"result":           eval.Result,
		"missing":          missing,
		"assumptions":      []string{"This report supports compliance readiness and is not a legal compliance conclusion."},
		"limitations":      []string{"Missing evidence is based only on evidence recorded in this Evydence instance."},
	}, nil
}

func (l *Ledger) WithIdempotency(ctx context.Context, actor domain.Actor, method, path, key string, body []byte, run func() (int, any, error)) (int, any, error) {
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return 0, nil, ErrValidation
	}
	requestHash := hashBytes(append([]byte(method+"\n"+path+"\n"), body...))
	storeKey := NewIdempotencyRecordKey(actor.TenantID, idempotencyActorID(actor), method, path, key)
	l.mu.Lock()
	record, ok := l.idempotency[storeKey]
	l.mu.Unlock()
	if ok {
		if record.RequestHash != requestHash {
			return 0, nil, ErrIdempotencyConflict
		}
		return record.Status, record.Response, nil
	}
	status, response, err := run()
	if err != nil {
		return status, response, err
	}
	l.mu.Lock()
	l.idempotency[storeKey] = IdempotencyRecord{RequestHash: requestHash, Status: status, Response: response, CreatedAt: l.now()}
	if err := l.persistLocked(ctx); err != nil {
		l.mu.Unlock()
		return 0, nil, err
	}
	l.mu.Unlock()
	return status, response, nil
}

func idempotencyActorID(actor domain.Actor) string {
	switch {
	case strings.TrimSpace(actor.KeyID) != "":
		return "api_key:" + strings.TrimSpace(actor.KeyID)
	case strings.TrimSpace(actor.UserID) != "":
		return "user:" + strings.TrimSpace(actor.UserID)
	case strings.TrimSpace(actor.CollectorID) != "":
		return "collector:" + strings.TrimSpace(actor.CollectorID)
	default:
		return "anonymous"
	}
}

func NewIdempotencyRecordKey(tenantID, actorID, method, path, key string) string {
	parts := []string{tenantID, actorID, method, path, key}
	encoded := make([]string, 0, len(parts))
	for _, part := range parts {
		encoded = append(encoded, base64.RawURLEncoding.EncodeToString([]byte(part)))
	}
	return "v2:" + strings.Join(encoded, ".")
}

func ParseIdempotencyRecordKey(value string) (IdempotencyRecordKey, bool) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "v2:") {
		parts := strings.Split(strings.TrimPrefix(value, "v2:"), ".")
		if len(parts) != 5 {
			return IdempotencyRecordKey{}, false
		}
		decoded := make([]string, 0, len(parts))
		for _, part := range parts {
			raw, err := base64.RawURLEncoding.DecodeString(part)
			if err != nil {
				return IdempotencyRecordKey{}, false
			}
			decoded = append(decoded, string(raw))
		}
		return idempotencyRecordKeyFromParts(decoded)
	}
	return idempotencyRecordKeyFromParts(strings.Split(value, "\x00"))
}

func idempotencyRecordKeyFromParts(parts []string) (IdempotencyRecordKey, bool) {
	if len(parts) != 5 || parts[0] == "" || parts[1] == "" || parts[4] == "" {
		return IdempotencyRecordKey{}, false
	}
	return IdempotencyRecordKey{
		TenantID:       parts[0],
		ActorID:        parts[1],
		Method:         parts[2],
		Path:           parts[3],
		IdempotencyKey: parts[4],
	}, true
}

func (l *Ledger) createAPIKeyLocked(tenantID, name string, scopes []string, expiresAt *time.Time) (domain.APIKey, string, error) {
	secret := "evy_" + randomToken(32)
	key := domain.APIKey{ID: newID("key"), TenantID: tenantID, Name: name, Prefix: secretPrefix(secret), Scopes: sortedStrings(scopes), CreatedAt: l.now(), ExpiresAt: expiresAt, Hash: l.hashSecret(secret)}
	l.apiKeys[key.ID] = key
	public := key
	public.Hash = ""
	return public, secret, nil
}

func (l *Ledger) hashSecret(secret string) string {
	mac := hmac.New(sha256.New, l.pepper)
	_, _ = mac.Write([]byte(secret))
	return hex.EncodeToString(mac.Sum(nil))
}

func secretHashEqual(stored, candidate string) bool {
	if len(stored) != sha256.Size*2 || len(candidate) != sha256.Size*2 {
		return false
	}
	return hmac.Equal([]byte(stored), []byte(candidate))
}

func (l *Ledger) ensureScopeLocked(tenantID, productID, projectID, releaseID string) error {
	if productID != "" {
		product, ok := l.products[productID]
		if !ok || product.TenantID != tenantID {
			return ErrNotFound
		}
	}
	if projectID != "" {
		project, ok := l.projects[projectID]
		if !ok || project.TenantID != tenantID {
			return ErrNotFound
		}
	}
	if releaseID != "" {
		release, ok := l.releases[releaseID]
		if !ok || release.TenantID != tenantID {
			return ErrNotFound
		}
	}
	return nil
}

func (l *Ledger) appendChainLocked(tenantID, entryType, subjectType, subjectID, actorType, actorID, payloadHash, signatureRef string) (domain.AuditChainEntry, error) {
	entries := l.chain[tenantID]
	previous := ""
	if len(entries) > 0 {
		previous = entries[len(entries)-1].EntryHash
	}
	entry := domain.AuditChainEntry{
		ID:                newID("ace"),
		TenantID:          tenantID,
		Sequence:          int64(len(entries) + 1),
		EntryType:         entryType,
		SubjectType:       subjectType,
		SubjectID:         subjectID,
		ActorType:         actorType,
		ActorID:           actorID,
		OccurredAt:        l.now(),
		PayloadHash:       payloadHash,
		PreviousEntryHash: previous,
		SignatureRef:      signatureRef,
		SchemaVersion:     domain.AuditChainEntrySchemaVersion,
	}
	canonical, err := canonicalAnyHash(map[string]any{
		"tenant_id":           entry.TenantID,
		"sequence":            entry.Sequence,
		"entry_type":          entry.EntryType,
		"subject_type":        entry.SubjectType,
		"subject_id":          entry.SubjectID,
		"actor_type":          entry.ActorType,
		"actor_id":            entry.ActorID,
		"occurred_at":         entry.OccurredAt.UTC().Format(time.RFC3339Nano),
		"payload_hash":        entry.PayloadHash,
		"previous_entry_hash": entry.PreviousEntryHash,
		"signature_ref":       entry.SignatureRef,
		"schema_version":      entry.SchemaVersion,
	})
	if err != nil {
		return domain.AuditChainEntry{}, err
	}
	entry.CanonicalEntryHash = canonical
	entry.EntryHash = hashBytes([]byte(previous + "\n" + canonical))
	l.chain[tenantID] = append(entries, entry)
	return entry, nil
}

func (l *Ledger) verifyChainLocked(tenantID string) []domain.VerifyCheck {
	entries := l.chain[tenantID]
	checks := []domain.VerifyCheck{}
	previous := ""
	for i, entry := range entries {
		if entry.Sequence != int64(i+1) {
			checks = append(checks, domain.VerifyCheck{Name: "sequence", Result: "failed", Detail: entry.ID})
			return checks
		}
		if entry.PreviousEntryHash != previous {
			checks = append(checks, domain.VerifyCheck{Name: "previous_hash", Result: "failed", Detail: entry.ID})
			return checks
		}
		if hashBytes([]byte(previous+"\n"+entry.CanonicalEntryHash)) != entry.EntryHash {
			checks = append(checks, domain.VerifyCheck{Name: "entry_hash", Result: "failed", Detail: entry.ID})
			return checks
		}
		previous = entry.EntryHash
	}
	checks = append(checks, domain.VerifyCheck{Name: "audit_chain", Result: "passed"})
	return checks
}

func (l *Ledger) rotateSigningKeyLocked(tenantID, _ string) (domain.SigningKey, error) {
	for id, key := range l.signingKeys {
		if key.TenantID == tenantID && key.Status == "active" {
			key.Status = "retiring"
			l.signingKeys[id] = key
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return domain.SigningKey{}, err
	}
	key := domain.SigningKey{ID: newID("sk"), TenantID: tenantID, KID: time.Now().UTC().Format("20060102T150405Z"), Algorithm: "Ed25519", Status: "active", PublicKey: base64.RawStdEncoding.EncodeToString(pub), Private: priv, CreatedAt: l.now()}
	l.signingKeys[key.ID] = key
	public := key
	public.Private = nil
	return public, nil
}

func (l *Ledger) signLocked(tenantID, subjectType, subjectID string, payload []byte) (domain.Signature, error) {
	var active domain.SigningKey
	for _, key := range l.signingKeys {
		if key.TenantID == tenantID && key.Status == "active" {
			active = key
			break
		}
	}
	if active.ID == "" {
		if _, err := l.rotateSigningKeyLocked(tenantID, "auto"); err != nil {
			return domain.Signature{}, err
		}
		for _, key := range l.signingKeys {
			if key.TenantID == tenantID && key.Status == "active" {
				active = key
				break
			}
		}
	}
	sigBytes := ed25519.Sign(ed25519.PrivateKey(active.Private), payload)
	sig := domain.Signature{ID: newID("sig"), TenantID: tenantID, SubjectType: subjectType, SubjectID: subjectID, KeyID: active.ID, Algorithm: "Ed25519", Value: base64.RawStdEncoding.EncodeToString(sigBytes), CreatedAt: l.now()}
	l.signatures[sig.ID] = sig
	return sig, nil
}

func (l *Ledger) verifySignatureLocked(tenantID string, signatureRefs []string, payload []byte) bool {
	for _, ref := range signatureRefs {
		sig, ok := l.signatures[ref]
		if !ok || sig.TenantID != tenantID {
			continue
		}
		key, ok := l.signingKeys[sig.KeyID]
		if !ok || key.TenantID != tenantID {
			continue
		}
		if key.Status == "revoked" && (key.RevokedAt == nil || sig.CreatedAt.After(*key.RevokedAt)) {
			continue
		}
		pub, err := base64.RawStdEncoding.DecodeString(key.PublicKey)
		if err != nil {
			continue
		}
		value, err := base64.RawStdEncoding.DecodeString(sig.Value)
		if err != nil {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(pub), payload, value) {
			return true
		}
	}
	return false
}

func (l *Ledger) checkReleaseHasEvidenceLocked(tenantID, releaseID, typ, name, severity string) domain.PolicyCheck {
	for _, item := range l.evidence {
		if item.TenantID == tenantID && item.ReleaseID == releaseID && item.Type == typ {
			return domain.PolicyCheck{Name: name, Result: "passed", Severity: severity, Explanation: typ + " evidence exists"}
		}
	}
	return domain.PolicyCheck{Name: name, Result: "failed", Severity: severity, Missing: []string{typ}, Explanation: typ + " evidence is missing"}
}

func (l *Ledger) checkNoOpenCriticalLocked(tenantID, releaseID string) domain.PolicyCheck {
	blocking := l.unhandledCriticalFindingsLocked(tenantID, releaseID)
	if len(blocking) > 0 {
		return domain.PolicyCheck{Name: "critical_exploitable_blocks_release", Result: "failed", Severity: "critical", Missing: []string{"vulnerability_decision"}, Explanation: "open critical finding requires remediation, a valid VEX decision, or an approved unexpired exception"}
	}
	return domain.PolicyCheck{Name: "critical_exploitable_blocks_release", Result: "passed", Severity: "critical", Explanation: "no open critical findings recorded"}
}

func require(actor domain.Actor, scope string) error {
	if actor.TenantID == "" || (actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "") {
		return ErrUnauthorized
	}
	if requiresExplicitScope(scope) {
		if actorHasExactScope(actor, scope) {
			return nil
		}
		return ErrForbidden
	}
	if actor.HasScope(scope) || actor.HasScope(ScopeAdmin) {
		return nil
	}
	return ErrForbidden
}

func requireGrantableScopes(actor domain.Actor, scopes []string) error {
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if requiresExplicitScope(scope) && !actorHasExactScope(actor, scope) {
			return ErrForbidden
		}
	}
	return nil
}

func requiresExplicitScope(scope string) bool {
	return scope == ScopeInstanceAdmin
}

func actorHasExactScope(actor domain.Actor, scope string) bool {
	for _, got := range actor.Scopes {
		if got == scope {
			return true
		}
	}
	return false
}

func canonicalHash(item domain.EvidenceItem) (string, error) {
	item.CanonicalHash = ""
	item.ChainEntryID = ""
	item.SignatureRefs = nil
	return canonicalAnyHash(item)
}

func canonicalAnyHash(v any) (string, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	var normalized any
	if err := json.Unmarshal(body, &normalized); err != nil {
		return "", err
	}
	body, err = json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	return hashBytes(body), nil
}

func hashBytes(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(strings.TrimPrefix(value, "sha256:")) == 64
}

func newID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}

func randomToken(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func secretPrefix(secret string) string {
	if len(secret) <= 12 {
		return secret
	}
	return secret[:12]
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	for i := range out {
		out[i] = strings.TrimSpace(out[i])
	}
	sort.Strings(out)
	return out
}

func cloneMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func nonEmpty(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func subjectForArtifact(artifactID string) []domain.SubjectRef {
	if strings.TrimSpace(artifactID) == "" {
		return nil
	}
	return []domain.SubjectRef{{Type: "artifact", ID: artifactID}}
}

func IsValidation(err error) bool {
	return errors.Is(err, ErrValidation)
}

func ProblemCode(err error) string {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return "UNAUTHORIZED"
	case errors.Is(err, ErrForbidden):
		return "FORBIDDEN"
	case errors.Is(err, ErrNotFound):
		return "NOT_FOUND"
	case errors.Is(err, ErrConflict):
		return "CONFLICT"
	case errors.Is(err, ErrImmutable):
		return "EVIDENCE_IMMUTABLE"
	case errors.Is(err, ErrIdempotencyConflict):
		return "IDEMPOTENCY_KEY_REUSED"
	case errors.Is(err, ErrVerificationFailed):
		return "VERIFICATION_FAILED"
	case errors.Is(err, ErrRateLimited):
		return "RATE_LIMITED"
	case errors.Is(err, ErrValidation):
		return "VALIDATION_FAILED"
	default:
		return "INTERNAL_ERROR"
	}
}

func StatusCode(err error) int {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return 401
	case errors.Is(err, ErrForbidden):
		return 403
	case errors.Is(err, ErrNotFound):
		return 404
	case errors.Is(err, ErrConflict), errors.Is(err, ErrImmutable), errors.Is(err, ErrIdempotencyConflict):
		return 409
	case errors.Is(err, ErrValidation):
		return 400
	case errors.Is(err, ErrVerificationFailed):
		return 422
	case errors.Is(err, ErrRateLimited):
		return 429
	default:
		return 500
	}
}

func SafeErrorDetail(err error) string {
	switch StatusCode(err) {
	case 500:
		return "internal server error"
	default:
		return fmt.Sprintf("%s", err)
	}
}
