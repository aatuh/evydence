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
	APIKeyPepper    string
	Now             func() time.Time
	Store           Store
	UnitOfWork      UnitOfWorkFactory
	ObjectStore     ObjectStore
	Retention       ObjectRetentionVerifier
	Signer          SigningExecutor
	OIDC            OIDCDiscoveryClient
	ProviderAPI     ProviderIdentityValidator
	Transparency    TransparencyProofFetcher
	Outbox          Outbox
	ReadinessChecks []ReadinessCheck
	// WorkerOwnedParserSideEffects stores accepted parser records first and
	// lets outbox workers populate parser-derived fields from raw payloads.
	WorkerOwnedParserSideEffects bool
}

type Ledger struct {
	mu sync.Mutex

	pepper             []byte
	now                func() time.Time
	store              Store
	unitOfWork         UnitOfWorkFactory
	objects            ObjectStore
	retention          ObjectRetentionVerifier
	signer             SigningExecutor
	oidc               OIDCDiscoveryClient
	providerAPI        ProviderIdentityValidator
	transparencyProofs TransparencyProofFetcher
	outbox             Outbox
	readinessChecks    []ReadinessCheck
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
	answerLibrary         map[string]domain.QuestionnaireAnswerLibraryEntry
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
	vexImportReports      map[string]domain.VEXImportReport
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

// NewLedger creates an in-memory ledger. Durable state loading can fail, so
// callers configuring Config.Store must use NewLedgerWithContext.
func NewLedger(cfg Config) *Ledger {
	if cfg.Store != nil {
		panic("NewLedger does not load durable state; use NewLedgerWithContext")
	}
	ledger, err := NewLedgerWithContext(context.Background(), cfg)
	if err != nil {
		panic("unexpected in-memory ledger initialization failure: " + err.Error())
	}
	return ledger
}

// NewLedgerWithContext creates a ledger and honors cancellation while loading
// configured durable state.
func NewLedgerWithContext(ctx context.Context, cfg Config) (*Ledger, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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
	unitOfWork := cfg.UnitOfWork
	if unitOfWork == nil {
		if factory, ok := cfg.Store.(UnitOfWorkFactory); ok {
			unitOfWork = factory
		}
	}
	ledger := &Ledger{
		pepper:                []byte(pepper),
		now:                   now,
		store:                 cfg.Store,
		unitOfWork:            unitOfWork,
		objects:               cfg.ObjectStore,
		retention:             retention,
		signer:                cfg.Signer,
		oidc:                  cfg.OIDC,
		providerAPI:           cfg.ProviderAPI,
		transparencyProofs:    cfg.Transparency,
		outbox:                cfg.Outbox,
		readinessChecks:       normalizedReadinessChecks(cfg.ReadinessChecks),
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
		answerLibrary:         map[string]domain.QuestionnaireAnswerLibraryEntry{},
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
		vexImportReports:      map[string]domain.VEXImportReport{},
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
		state, ok, err := cfg.Store.LoadState(ctx)
		if err != nil {
			return nil, err
		}
		if ok {
			if err := ledger.applyState(state); err != nil {
				return nil, err
			}
		}
	}
	return ledger, nil
}

func (l *Ledger) HasTenants() bool {
	return l.identityService().HasTenants()
}

func (l *Ledger) BootstrapTenant(ctx context.Context, name, keyName string, scopes []string) (domain.Tenant, domain.APIKey, string, error) {
	return l.identityService().BootstrapTenant(ctx, name, keyName, scopes)
}

func (l *Ledger) Authenticate(ctx context.Context, secret string) (domain.Actor, error) {
	return l.identityService().Authenticate(ctx, secret)
}

func (l *Ledger) CreateAPIKey(ctx context.Context, actor domain.Actor, name string, scopes []string, expiresAt *time.Time) (domain.APIKey, string, error) {
	return l.identityService().CreateAPIKey(ctx, actor, name, scopes, expiresAt)
}

func (l *Ledger) ListAPIKeys(ctx context.Context, actor domain.Actor) ([]domain.APIKey, error) {
	return l.identityService().ListAPIKeys(ctx, actor)
}

func (s releaseEvidenceService) CreateProduct(ctx context.Context, actor domain.Actor, name, slug string) (domain.Product, error) {
	l := s.ledger
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
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.ReleaseCatalog.InsertProduct(ctx, product); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(product.CreatedAt, actor.TenantID, "product.created", "product", product.ID, "api_key", actor.KeyID, "", ""))
			return err
		}); err != nil {
			return domain.Product{}, err
		}
		l.products[product.ID] = product
		l.publishCommittedAuditEntryLocked(entry)
		return product, nil
	}
	l.products[product.ID] = product
	_, _ = l.appendChainLocked(actor.TenantID, "product.created", "product", product.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistReleaseLedgerStateLocked(ctx); err != nil {
		return domain.Product{}, err
	}
	return product, nil
}

func (s releaseEvidenceService) ListProducts(ctx context.Context, actor domain.Actor) ([]domain.Product, error) {
	l := s.ledger
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

func (s releaseEvidenceService) GetProduct(ctx context.Context, actor domain.Actor, id string) (domain.Product, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.Product{}, err
	}
	if err := require(actor, ScopeProductRead); err != nil {
		return domain.Product{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	product, ok := l.products[strings.TrimSpace(id)]
	if !ok || product.TenantID != actor.TenantID {
		return domain.Product{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeProductRead, resourceRefs{ProductID: product.ID}); err != nil {
		return domain.Product{}, err
	}
	return product, nil
}

func (s releaseEvidenceService) CreateProject(ctx context.Context, actor domain.Actor, productID, name string) (domain.Project, error) {
	l := s.ledger
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
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.ReleaseCatalog.InsertProject(ctx, project); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(project.CreatedAt, actor.TenantID, "project.created", "project", project.ID, "api_key", actor.KeyID, "", ""))
			return err
		}); err != nil {
			return domain.Project{}, err
		}
		l.projects[project.ID] = project
		l.publishCommittedAuditEntryLocked(entry)
		return project, nil
	}
	l.projects[project.ID] = project
	_, _ = l.appendChainLocked(actor.TenantID, "project.created", "project", project.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistReleaseLedgerStateLocked(ctx); err != nil {
		return domain.Project{}, err
	}
	return project, nil
}

func (s releaseEvidenceService) GetProject(ctx context.Context, actor domain.Actor, id string) (domain.Project, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.Project{}, err
	}
	if err := require(actor, ScopeProjectRead); err != nil {
		return domain.Project{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	project, ok := l.projects[strings.TrimSpace(id)]
	if !ok || project.TenantID != actor.TenantID {
		return domain.Project{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeProjectRead, resourceRefs{ProductID: project.ProductID, ProjectID: project.ID}); err != nil {
		return domain.Project{}, err
	}
	return project, nil
}

func (s releaseEvidenceService) CreateRelease(ctx context.Context, actor domain.Actor, productID, version string) (domain.Release, error) {
	l := s.ledger
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
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.ReleaseCatalog.InsertRelease(ctx, release); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(release.CreatedAt, actor.TenantID, "release.created", "release", release.ID, "api_key", actor.KeyID, "", ""))
			return err
		}); err != nil {
			return domain.Release{}, err
		}
		l.releases[release.ID] = release
		l.publishCommittedAuditEntryLocked(entry)
		return release, nil
	}
	l.releases[release.ID] = release
	_, _ = l.appendChainLocked(actor.TenantID, "release.created", "release", release.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistReleaseLedgerStateLocked(ctx); err != nil {
		return domain.Release{}, err
	}
	return release, nil
}

func (s releaseEvidenceService) GetRelease(ctx context.Context, actor domain.Actor, releaseID string) (domain.Release, error) {
	l := s.ledger
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

func (s releaseEvidenceService) FreezeRelease(ctx context.Context, actor domain.Actor, releaseID string) (domain.Release, error) {
	l := s.ledger
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
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.ReleaseCatalog.UpdateReleaseState(ctx, release, "draft"); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(now, actor.TenantID, "release.frozen", "release", release.ID, "api_key", actor.KeyID, "", ""))
			return err
		}); err != nil {
			return domain.Release{}, err
		}
		l.releases[release.ID] = release
		l.publishCommittedAuditEntryLocked(entry)
		return release, nil
	}
	l.releases[release.ID] = release
	_, _ = l.appendChainLocked(actor.TenantID, "release.frozen", "release", release.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistReleaseLedgerStateLocked(ctx); err != nil {
		return domain.Release{}, err
	}
	return release, nil
}

func (s releaseEvidenceService) ApproveRelease(ctx context.Context, actor domain.Actor, releaseID string) (domain.Release, error) {
	l := s.ledger
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
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.ReleaseCatalog.UpdateReleaseState(ctx, release, "frozen"); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(now, actor.TenantID, "release.approved", "release", release.ID, "api_key", actor.KeyID, "", ""))
			return err
		}); err != nil {
			return domain.Release{}, err
		}
		l.releases[release.ID] = release
		l.publishCommittedAuditEntryLocked(entry)
		return release, nil
	}
	l.releases[release.ID] = release
	_, _ = l.appendChainLocked(actor.TenantID, "release.approved", "release", release.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistReleaseLedgerStateLocked(ctx); err != nil {
		return domain.Release{}, err
	}
	return release, nil
}

func (s releaseEvidenceService) RegisterArtifact(ctx context.Context, actor domain.Actor, name, mediaType, digest string, size int64) (domain.Artifact, error) {
	l := s.ledger
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
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.ReleaseCatalog.InsertArtifact(ctx, artifact); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(artifact.CreatedAt, actor.TenantID, "artifact.created", "artifact", artifact.ID, "api_key", actor.KeyID, artifact.Digest, ""))
			return err
		}); err != nil {
			return domain.Artifact{}, err
		}
		l.artifacts[artifact.ID] = artifact
		l.publishCommittedAuditEntryLocked(entry)
		return artifact, nil
	}
	l.artifacts[artifact.ID] = artifact
	_, _ = l.appendChainLocked(actor.TenantID, "artifact.created", "artifact", artifact.ID, "api_key", actor.KeyID, digest, "")
	if err := l.persistReleaseLedgerStateLocked(ctx); err != nil {
		return domain.Artifact{}, err
	}
	return artifact, nil
}

func (s releaseEvidenceService) GetArtifact(ctx context.Context, actor domain.Actor, id string) (domain.Artifact, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.Artifact{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return domain.Artifact{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	artifact, ok := l.artifacts[strings.TrimSpace(id)]
	if !ok || artifact.TenantID != actor.TenantID {
		return domain.Artifact{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ArtifactID: artifact.ID}); err != nil {
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

// newEvidenceItemLocked validates tenant-scoped references and constructs an
// immutable evidence value without publishing it to the local read model.
// Callers can therefore include the evidence row, its audit entry, and any
// derived parser record in one transaction before updating process state.
func (s releaseEvidenceService) newEvidenceItemLocked(actor domain.Actor, in CreateEvidenceInput) (domain.EvidenceItem, error) {
	l := s.ledger
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
	return item, nil
}

func (s releaseEvidenceService) CreateEvidence(ctx context.Context, actor domain.Actor, in CreateEvidenceInput) (domain.EvidenceItem, error) {
	l := s.ledger
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
	item, err := s.newEvidenceItemLocked(actor, in)
	if err != nil {
		return domain.EvidenceItem{}, err
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(item.CreatedAt, actor.TenantID, "evidence.created", "evidence_item", item.ID, "api_key", actor.KeyID, item.PayloadHash, ""))
			if err != nil {
				return err
			}
			item.ChainEntryID = entry.ID
			return repos.Evidence.InsertEvidence(ctx, item)
		}); err != nil {
			return domain.EvidenceItem{}, err
		}
		l.evidence[item.ID] = item
		l.publishCommittedAuditEntryLocked(entry)
		return item, nil
	}
	entry, err := l.appendChainLocked(actor.TenantID, "evidence.created", "evidence_item", item.ID, "api_key", actor.KeyID, item.PayloadHash, "")
	if err != nil {
		return domain.EvidenceItem{}, err
	}
	item.ChainEntryID = entry.ID
	l.evidence[item.ID] = item
	if err := l.persistReleaseLedgerStateLocked(ctx); err != nil {
		return domain.EvidenceItem{}, err
	}
	return item, nil
}

func (s releaseEvidenceService) GetEvidence(ctx context.Context, actor domain.Actor, id string) (domain.EvidenceItem, error) {
	l := s.ledger
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

func (s releaseEvidenceService) ListEvidence(ctx context.Context, actor domain.Actor, releaseID, typ string) ([]domain.EvidenceItem, error) {
	l := s.ledger
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

func (s releaseEvidenceService) SupersedeEvidence(ctx context.Context, actor domain.Actor, id, replacementID, reason string) (domain.EvidenceItem, error) {
	l := s.ledger
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
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		now := l.now()
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Evidence.RecordSupersession(ctx, item, replacement); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(now, actor.TenantID, "evidence.superseded", "evidence_item", item.ID, "api_key", actor.KeyID, item.PayloadHash, ""))
			return err
		}); err != nil {
			return domain.EvidenceItem{}, err
		}
		l.evidence[item.ID] = item
		l.evidence[replacement.ID] = replacement
		l.publishCommittedAuditEntryLocked(entry)
		return item, nil
	}
	l.evidence[item.ID] = item
	l.evidence[replacement.ID] = replacement
	_, _ = l.appendChainLocked(actor.TenantID, "evidence.superseded", "evidence_item", item.ID, "api_key", actor.KeyID, item.PayloadHash, "")
	if err := l.persistReleaseLedgerStateLocked(ctx); err != nil {
		return domain.EvidenceItem{}, err
	}
	return item, nil
}

func (s releaseEvidenceService) LinkEvidence(ctx context.Context, actor domain.Actor, id, targetType, targetID string) (domain.EvidenceItem, error) {
	l := s.ledger
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
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		now := l.now()
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Evidence.UpdateEvidenceLinks(ctx, item); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(now, actor.TenantID, "evidence.linked", "evidence_item", item.ID, "api_key", actor.KeyID, item.PayloadHash, ""))
			return err
		}); err != nil {
			return domain.EvidenceItem{}, err
		}
		l.evidence[item.ID] = item
		l.publishCommittedAuditEntryLocked(entry)
		return item, nil
	}
	l.evidence[item.ID] = item
	_, _ = l.appendChainLocked(actor.TenantID, "evidence.linked", "evidence_item", item.ID, "api_key", actor.KeyID, item.PayloadHash, "")
	if err := l.persistReleaseLedgerStateLocked(ctx); err != nil {
		return domain.EvidenceItem{}, err
	}
	return item, nil
}

func (s releaseEvidenceService) UploadSBOM(ctx context.Context, actor domain.Actor, releaseID, artifactID string, raw []byte) (domain.SBOM, error) {
	l := s.ledger
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
			Type    string `json:"type"`
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
	evidenceInput := CreateEvidenceInput{
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
	}
	if l.unitOfWork != nil {
		l.mu.Lock()
		defer l.mu.Unlock()
		item, err := s.newEvidenceItemLocked(actor, evidenceInput)
		if err != nil {
			return domain.SBOM{}, err
		}
		sbom := domain.SBOM{ID: newID("sbom"), TenantID: actor.TenantID, EvidenceID: item.ID, ReleaseID: releaseID, ArtifactID: artifactID, Format: "cyclonedx", SpecVersion: doc.SpecVersion, ComponentCount: len(components), Components: components, CreatedAt: l.now()}
		persistedSBOM := sbom
		chainAction := "sbom.parsed"
		if l.workerOwnedParsers {
			persistedSBOM.SpecVersion = ""
			persistedSBOM.ComponentCount = 0
			persistedSBOM.Components = nil
			chainAction = "sbom.accepted"
		}
		job := l.newOutboxJob(actor.TenantID, "parse_sbom", "sbom", sbom.ID, map[string]any{"payload_ref": payloadRef, "payload_hash": payloadHash, "parser_version": ParserVersionCycloneDXJSON})
		var evidenceEntry, sbomEntry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			var err error
			evidenceEntry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(item.CreatedAt, actor.TenantID, "evidence.created", "evidence_item", item.ID, "api_key", actor.KeyID, item.PayloadHash, ""))
			if err != nil {
				return err
			}
			item.ChainEntryID = evidenceEntry.ID
			if err := repos.Evidence.InsertEvidence(ctx, item); err != nil {
				return err
			}
			sbomEntry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(sbom.CreatedAt, actor.TenantID, chainAction, "sbom", sbom.ID, "api_key", actor.KeyID, payloadHash, ""))
			if err != nil {
				return err
			}
			if err := repos.Evidence.InsertSBOM(ctx, persistedSBOM); err != nil {
				return err
			}
			return repos.Outbox.Enqueue(ctx, job)
		}); err != nil {
			return domain.SBOM{}, err
		}
		l.evidence[item.ID] = item
		l.sboms[sbom.ID] = persistedSBOM
		l.publishCommittedAuditEntryLocked(evidenceEntry)
		l.publishCommittedAuditEntryLocked(sbomEntry)
		return sbom, nil
	}
	item, err := l.CreateEvidence(ctx, actor, evidenceInput)
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
	job := l.newOutboxJob(actor.TenantID, "parse_sbom", "sbom", sbom.ID, map[string]any{"payload_ref": payloadRef, "payload_hash": payloadHash, "parser_version": ParserVersionCycloneDXJSON})
	if err := l.persistReleaseLedgerWithOutboxLocked(ctx, job); err != nil {
		return domain.SBOM{}, err
	}
	return sbom, nil
}

func (s releaseEvidenceService) UploadVulnerabilityScan(ctx context.Context, actor domain.Actor, raw []byte) (domain.VulnerabilityScan, error) {
	l := s.ledger
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
	scanID := newID("scan")
	summary := map[string]int{}
	findings := make([]domain.VulnerabilityFinding, 0, len(doc.Findings))
	for i, finding := range doc.Findings {
		if finding.Vulnerability == "" || finding.Severity == "" {
			return domain.VulnerabilityScan{}, ErrValidation
		}
		severity := strings.ToLower(finding.Severity)
		summary[severity]++
		state := nonEmpty(finding.State, "open")
		findings = append(findings, domain.VulnerabilityFinding{ID: fmt.Sprintf("%s:finding:%d", scanID, i+1), Vulnerability: finding.Vulnerability, Component: finding.Component, Severity: severity, State: state})
	}
	payloadHash := hashBytes(raw)
	payloadRef, err := l.storePayload(ctx, actor.TenantID, "vulnerability-scan", "application/json", payloadHash, raw)
	if err != nil {
		return domain.VulnerabilityScan{}, err
	}
	evidenceInput := CreateEvidenceInput{
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
	}
	if l.unitOfWork != nil {
		l.mu.Lock()
		defer l.mu.Unlock()
		item, err := s.newEvidenceItemLocked(actor, evidenceInput)
		if err != nil {
			return domain.VulnerabilityScan{}, err
		}
		scan := domain.VulnerabilityScan{ID: scanID, TenantID: actor.TenantID, EvidenceID: item.ID, ReleaseID: doc.ReleaseID, Scanner: doc.Scanner, TargetRef: doc.TargetRef, Summary: summary, Findings: findings, CreatedAt: l.now()}
		persistedScan := scan
		chainAction := "vulnerability_scan.parsed"
		if l.workerOwnedParsers {
			persistedScan.Scanner = ""
			persistedScan.TargetRef = ""
			persistedScan.Summary = nil
			persistedScan.Findings = nil
			chainAction = "vulnerability_scan.accepted"
		}
		job := l.newOutboxJob(actor.TenantID, "parse_vulnerability_scan", "vulnerability_scan", scan.ID, map[string]any{"payload_ref": payloadRef, "payload_hash": payloadHash, "parser_version": ParserVersionGenericVulnerabilityJSON})
		var evidenceEntry, scanEntry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			var err error
			evidenceEntry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(item.CreatedAt, actor.TenantID, "evidence.created", "evidence_item", item.ID, "api_key", actor.KeyID, item.PayloadHash, ""))
			if err != nil {
				return err
			}
			item.ChainEntryID = evidenceEntry.ID
			if err := repos.Evidence.InsertEvidence(ctx, item); err != nil {
				return err
			}
			scanEntry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(scan.CreatedAt, actor.TenantID, chainAction, "vulnerability_scan", scan.ID, "api_key", actor.KeyID, payloadHash, ""))
			if err != nil {
				return err
			}
			if err := repos.Evidence.InsertVulnerabilityScan(ctx, persistedScan); err != nil {
				return err
			}
			return repos.Outbox.Enqueue(ctx, job)
		}); err != nil {
			return domain.VulnerabilityScan{}, err
		}
		l.evidence[item.ID] = item
		l.scans[scan.ID] = persistedScan
		l.publishCommittedAuditEntryLocked(evidenceEntry)
		l.publishCommittedAuditEntryLocked(scanEntry)
		return scan, nil
	}
	item, err := l.CreateEvidence(ctx, actor, evidenceInput)
	if err != nil {
		return domain.VulnerabilityScan{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	scan := domain.VulnerabilityScan{ID: scanID, TenantID: actor.TenantID, EvidenceID: item.ID, ReleaseID: doc.ReleaseID, Scanner: doc.Scanner, TargetRef: doc.TargetRef, Summary: summary, Findings: findings, CreatedAt: l.now()}
	persistedScan := scan
	chainAction := "vulnerability_scan.parsed"
	if l.workerOwnedParsers {
		persistedScan.Scanner = ""
		persistedScan.TargetRef = ""
		persistedScan.Summary = nil
		persistedScan.Findings = nil
		chainAction = "vulnerability_scan.accepted"
	}
	l.scans[scan.ID] = persistedScan
	_, _ = l.appendChainLocked(actor.TenantID, chainAction, "vulnerability_scan", scan.ID, "api_key", actor.KeyID, payloadHash, "")
	job := l.newOutboxJob(actor.TenantID, "parse_vulnerability_scan", "vulnerability_scan", scan.ID, map[string]any{"payload_ref": payloadRef, "payload_hash": payloadHash, "parser_version": ParserVersionGenericVulnerabilityJSON})
	if err := l.persistReleaseLedgerWithOutboxLocked(ctx, job); err != nil {
		return domain.VulnerabilityScan{}, err
	}
	return scan, nil
}

func (s releaseEvidenceService) UploadOpenAPIContract(ctx context.Context, actor domain.Actor, productID, releaseID, version string, raw []byte) (domain.OpenAPIContract, error) {
	l := s.ledger
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
	evidenceInput := CreateEvidenceInput{
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
	}
	if l.unitOfWork != nil {
		l.mu.Lock()
		defer l.mu.Unlock()
		item, err := s.newEvidenceItemLocked(actor, evidenceInput)
		if err != nil {
			return domain.OpenAPIContract{}, err
		}
		contract := domain.OpenAPIContract{ID: newID("oas"), TenantID: actor.TenantID, ProductID: productID, ReleaseID: releaseID, Version: version, Hash: payloadHash, PathCount: len(doc.Paths.Map()), Operations: operations, EvidenceID: item.ID, CreatedAt: l.now()}
		persistedContract := contract
		chainAction := "openapi_contract.parsed"
		if l.workerOwnedParsers {
			persistedContract.PathCount = 0
			persistedContract.Operations = nil
			chainAction = "openapi_contract.accepted"
		}
		job := l.newOutboxJob(actor.TenantID, "parse_openapi_contract", "openapi_contract", contract.ID, map[string]any{"payload_ref": payloadRef, "payload_hash": payloadHash, "parser_version": ParserVersionOpenAPIJSON})
		var evidenceEntry, contractEntry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			var err error
			evidenceEntry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(item.CreatedAt, actor.TenantID, "evidence.created", "evidence_item", item.ID, "api_key", actor.KeyID, item.PayloadHash, ""))
			if err != nil {
				return err
			}
			item.ChainEntryID = evidenceEntry.ID
			if err := repos.Evidence.InsertEvidence(ctx, item); err != nil {
				return err
			}
			contractEntry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(contract.CreatedAt, actor.TenantID, chainAction, "openapi_contract", contract.ID, "api_key", actor.KeyID, contract.Hash, ""))
			if err != nil {
				return err
			}
			if err := repos.Evidence.InsertOpenAPIContract(ctx, persistedContract); err != nil {
				return err
			}
			return repos.Outbox.Enqueue(ctx, job)
		}); err != nil {
			return domain.OpenAPIContract{}, err
		}
		l.evidence[item.ID] = item
		l.contracts[contract.ID] = persistedContract
		l.publishCommittedAuditEntryLocked(evidenceEntry)
		l.publishCommittedAuditEntryLocked(contractEntry)
		return contract, nil
	}
	item, err := l.CreateEvidence(ctx, actor, evidenceInput)
	if err != nil {
		return domain.OpenAPIContract{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	contract := domain.OpenAPIContract{ID: newID("oas"), TenantID: actor.TenantID, ProductID: productID, ReleaseID: releaseID, Version: version, Hash: payloadHash, PathCount: len(doc.Paths.Map()), Operations: operations, EvidenceID: item.ID, CreatedAt: l.now()}
	persistedContract := contract
	chainAction := "openapi_contract.parsed"
	if l.workerOwnedParsers {
		persistedContract.PathCount = 0
		persistedContract.Operations = nil
		chainAction = "openapi_contract.accepted"
	}
	l.contracts[contract.ID] = persistedContract
	_, _ = l.appendChainLocked(actor.TenantID, chainAction, "openapi_contract", contract.ID, "api_key", actor.KeyID, contract.Hash, "")
	job := l.newOutboxJob(actor.TenantID, "parse_openapi_contract", "openapi_contract", contract.ID, map[string]any{"payload_ref": payloadRef, "payload_hash": payloadHash, "parser_version": ParserVersionOpenAPIJSON})
	if err := l.persistReleaseLedgerWithOutboxLocked(ctx, job); err != nil {
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
	checks := l.releasePolicyChecksLocked(actor.TenantID, release.ID)
	result := releasePolicyResult(checks)
	eval := domain.PolicyEvaluation{ID: newID("pe"), TenantID: actor.TenantID, ReleaseID: release.ID, Result: result, PolicySet: domain.PolicySetVersion, Checks: checks, CreatedAt: l.now()}
	l.policies[eval.ID] = eval
	_, _ = l.appendChainLocked(actor.TenantID, "policy.evaluated", "policy_evaluation", eval.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.PolicyEvaluation{}, err
	}
	return eval, nil
}

func (l *Ledger) releasePolicyChecksLocked(tenantID, releaseID string) []domain.PolicyCheck {
	return []domain.PolicyCheck{
		l.checkReleaseHasArtifactLocked(tenantID, releaseID),
		l.checkReleaseHasEvidenceLocked(tenantID, releaseID, "sbom", "release_requires_sbom", "high"),
		l.checkReleaseHasEvidenceLocked(tenantID, releaseID, "vulnerability_scan", "release_requires_vulnerability_scan", "high"),
		l.checkReleaseHasArtifactDigestLocked(tenantID, releaseID),
		l.checkReleaseHasSignedBundleLocked(tenantID, releaseID),
		l.checkReleaseHasPassedBuildLocked(tenantID, releaseID),
		l.checkReleaseHasBuildAttestationLocked(tenantID, releaseID),
		l.checkNoOpenCriticalLocked(tenantID, releaseID),
		l.checkNoOpenHighLocked(tenantID, releaseID),
		l.checkCustomerVisibleDecisionsHaveStatementsLocked(tenantID, releaseID),
		l.checkNotAffectedDecisionsHaveJustificationLocked(tenantID, releaseID),
		l.checkExceptionsCompleteLocked(tenantID, releaseID),
		l.checkPackageRedactionProfilesValidLocked(tenantID, releaseID),
	}
}

func releasePolicyResult(checks []domain.PolicyCheck) string {
	for _, check := range checks {
		if check.Result == "failed" {
			return "failed"
		}
	}
	return "passed"
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
		"object_lock_proofs": l.packageObjectLockProofsLocked(actor.TenantID),
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
	job := l.newOutboxJob(actor.TenantID, "sign_bundle", "release_bundle", bundle.ID, map[string]any{"manifest_hash": manifestHash})
	mutation, err := l.criticalMutationLocked()
	if err != nil {
		return domain.ReleaseBundle{}, err
	}
	mutation.OutboxJobs = append(mutation.OutboxJobs, job)
	if _, ok := l.store.(CriticalMutationStore); !ok {
		if err := l.enqueueJob(ctx, job); err != nil {
			return domain.ReleaseBundle{}, err
		}
	}
	if err := l.persistCriticalLocked(ctx, mutation); err != nil {
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

func (s releaseEvidenceService) GetSBOM(ctx context.Context, actor domain.Actor, id string) (domain.SBOM, error) {
	l := s.ledger
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

func (s releaseEvidenceService) ListSBOMComponents(ctx context.Context, actor domain.Actor, in ListSBOMComponentsInput) ([]domain.SBOMComponentRecord, error) {
	l := s.ledger
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

func (s releaseEvidenceService) GetVulnerabilityScan(ctx context.Context, actor domain.Actor, id string) (domain.VulnerabilityScan, error) {
	l := s.ledger
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

func (s releaseEvidenceService) GetOpenAPIContract(ctx context.Context, actor domain.Actor, id string) (domain.OpenAPIContract, error) {
	l := s.ledger
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
	var profile domain.VerificationProfile
	switch strings.TrimSpace(subjectType) {
	case "audit_chain":
		if err := l.authorizeResourceLocked(actor, ScopeVerifyRead, resourceRefs{}); err != nil {
			return domain.VerificationResult{}, err
		}
		checks = l.verifyChainLocked(actor.TenantID)
		profile = assuranceProfile("audit-chain-integrity.v1", requiredCheckNames(checks), []string{"Evydence audit-chain canonical hashes"}, "tenant-scoped verification authorization", "not_evaluated", "tenant audit-chain entries", "", []string{"Audit-chain verification does not prove external anchoring or third-party log inclusion."})
	case "audit_chain_checkpoint":
		if err := l.authorizeResourceLocked(actor, ScopeVerifyRead, resourceRefs{}); err != nil {
			return domain.VerificationResult{}, err
		}
		var found bool
		checks, found = l.verifyMerkleAuditChainCheckpointLocked(actor.TenantID, strings.TrimSpace(subjectID))
		if !found {
			return domain.VerificationResult{}, ErrNotFound
		}
		profile = assuranceProfile("audit-chain-merkle-checkpoint.v1", requiredCheckNames(checks), []string{"Evydence audit-chain hashes", "tenant signing keys"}, "tenant-scoped verification authorization", "not_evaluated", "tenant audit-chain range and signed Merkle root", "", []string{"This signed checkpoint detects truncation or rewrites within its covered sequence range, but does not prove external publication or third-party log inclusion."})
	case "audit_chain_release_manifest":
		bundle, ok := l.bundles[strings.TrimSpace(subjectID)]
		if !ok || bundle.TenantID != actor.TenantID {
			return domain.VerificationResult{}, ErrNotFound
		}
		if err := l.authorizeResourceLocked(actor, ScopeVerifyRead, resourceRefs{ReleaseID: bundle.ReleaseID}); err != nil {
			return domain.VerificationResult{}, err
		}
		var found bool
		checks, found = l.verifyReleaseManifestAuditChainCheckpointLocked(actor.TenantID, bundle.ID)
		if !found {
			return domain.VerificationResult{}, ErrNotFound
		}
		profile = assuranceProfile("audit-chain-release-manifest-checkpoint.v1", requiredCheckNames(checks), []string{"release bundle manifest", "tenant signing keys"}, "tenant-scoped verification authorization", "not_evaluated", "signed release manifest audit-chain checkpoint", bundle.ManifestHash, []string{"This signed checkpoint detects truncation or rewrites within its covered sequence range, but does not prove external publication or third-party log inclusion."})
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
			checks = append(checks, domain.VerifyCheck{Name: "canonical_hash", Result: "failed"})
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "canonical_hash", Result: "passed"})
		}
		profile = assuranceProfile("evidence-canonical-hash.v1", []string{"canonical_hash"}, []string{domain.CanonicalizationProfileVersion}, "tenant-scoped verification authorization", "not_evaluated", "canonical evidence fields", item.CanonicalHash, []string{"Canonical evidence hashing does not validate the origin or completeness of the uploaded payload."})
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
			checks = append(checks, domain.VerifyCheck{Name: "manifest_hash", Result: "failed"})
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "manifest_hash", Result: "passed"})
		}
		if !l.verifySignatureLocked(bundle.TenantID, bundle.SignatureRefs, []byte(bundle.ManifestHash)) {
			checks = append(checks, domain.VerifyCheck{Name: "bundle_signature", Result: "failed"})
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "bundle_signature", Result: "passed"})
		}
		profile = assuranceProfile("release-bundle-signature.v1", []string{"manifest_hash", "bundle_signature"}, []string{"active or historically valid tenant signing keys"}, "tenant-scoped verification authorization", "not_evaluated", "release bundle manifest canonical JSON", bundle.ManifestHash, []string{"Bundle verification does not establish external publication, registry provenance, or legal sufficiency."})
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
			checks = append(checks, domain.VerifyCheck{Name: "digest_binding_assessed", Result: "failed"})
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "digest_binding_assessed", Result: "passed"})
		}
		if sig.Algorithm == "" || sig.Signature == "" {
			checks = append(checks, domain.VerifyCheck{Name: "signature_material_present", Result: "failed"})
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "signature_material_present", Result: "passed", Detail: "signature recorded; cryptographic trust-root verification is deferred"})
		}
		profile = assuranceProfile("artifact-signature-metadata.v1", []string{"digest_binding_assessed", "signature_material_present", "cryptographic_signature_verified", "certificate_identity_policy", "transparency_inclusion_proof"}, []string{"recorded artifact signature metadata"}, "no certificate identity policy evaluated", "not_evaluated", "artifact digest and detached signature metadata", sig.SubjectDigest, []string{"This profile is metadata-only and cannot verify cryptographic signature validity, certificate identity, trust roots, or transparency inclusion."})
	default:
		return domain.VerificationResult{}, ErrValidation
	}
	vr := verificationResult(newID("vr"), actor.TenantID, subjectType, subjectID, checks, profile, l.now())
	l.verifications[vr.ID] = vr
	job := l.newOutboxJob(actor.TenantID, "verify_subject", subjectType, subjectID, map[string]any{"result_id": vr.ID})
	mutation, err := l.criticalMutationLocked()
	if err != nil {
		return domain.VerificationResult{}, err
	}
	mutation.OutboxJobs = append(mutation.OutboxJobs, job)
	if _, ok := l.store.(CriticalMutationStore); !ok {
		if err := l.enqueueJob(ctx, job); err != nil {
			return domain.VerificationResult{}, err
		}
	}
	if err := l.persistCriticalLocked(ctx, mutation); err != nil {
		return domain.VerificationResult{}, err
	}
	if verificationReturnsFailure(vr.Result) {
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

func (s packageReportService) MissingEvidenceReport(ctx context.Context, actor domain.Actor, releaseID string) (map[string]any, error) {
	l := s.ledger
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
	if err := l.persistCriticalStateLocked(ctx); err != nil {
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
	if err := RehashAuditChainEntry(&entry); err != nil {
		return domain.AuditChainEntry{}, err
	}
	l.chain[tenantID] = append(entries, entry)
	return entry, nil
}

func (l *Ledger) verifyChainLocked(tenantID string) []domain.VerifyCheck {
	entries := l.chain[tenantID]
	checks := []domain.VerifyCheck{}
	previous := ""
	passed := true
	for i, entry := range entries {
		if entry.TenantID != tenantID {
			checks = append(checks, domain.VerifyCheck{Name: "tenant_id", Result: "failed", Detail: entry.ID})
			passed = false
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "tenant_id", Result: "passed", Detail: entry.ID})
		}
		if entry.SchemaVersion != auditChainEntryLegacySchemaVersion && entry.SchemaVersion != domain.AuditChainEntrySchemaVersion {
			checks = append(checks, domain.VerifyCheck{Name: "schema_version", Result: "failed", Detail: entry.ID})
			passed = false
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "schema_version", Result: "passed", Detail: entry.ID})
		}
		if entry.Sequence != int64(i+1) {
			checks = append(checks, domain.VerifyCheck{Name: "sequence", Result: "failed", Detail: entry.ID})
			passed = false
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "sequence", Result: "passed", Detail: entry.ID})
		}
		if entry.PreviousEntryHash != previous {
			checks = append(checks, domain.VerifyCheck{Name: "previous_hash", Result: "failed", Detail: entry.ID})
			passed = false
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "previous_hash", Result: "passed", Detail: entry.ID})
		}
		canonical, canonicalMatches, err := verifiedAuditChainCanonicalHash(entry)
		if err != nil || !canonicalMatches {
			checks = append(checks, domain.VerifyCheck{Name: "canonical_entry_hash", Result: "failed", Detail: entry.ID})
			passed = false
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "canonical_entry_hash", Result: "passed", Detail: entry.ID})
		}
		if err != nil || hashBytes([]byte(previous+"\n"+canonical)) != entry.EntryHash {
			checks = append(checks, domain.VerifyCheck{Name: "entry_hash", Result: "failed", Detail: entry.ID})
			passed = false
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "entry_hash", Result: "passed", Detail: entry.ID})
		}
		signatureCheck := l.verifyAuditEntrySignatureLocked(entry)
		checks = append(checks, signatureCheck)
		if signatureCheck.Result != "passed" {
			passed = false
		}
		previous = entry.EntryHash
	}
	if passed {
		checks = append(checks, domain.VerifyCheck{Name: "audit_chain", Result: "passed"})
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "audit_chain", Result: "failed"})
	}
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

func (l *Ledger) checkReleaseHasArtifactLocked(tenantID, releaseID string) domain.PolicyCheck {
	for _, item := range l.evidence {
		if item.TenantID != tenantID || item.ReleaseID != releaseID {
			continue
		}
		for _, ref := range item.SubjectRefs {
			if ref.Type == "artifact" && ref.ID != "" {
				return domain.PolicyCheck{Name: "release_has_artifact", Result: "passed", Severity: "high", Explanation: "artifact evidence is linked to the release"}
			}
		}
	}
	return domain.PolicyCheck{Name: "release_has_artifact", Result: "failed", Severity: "high", Missing: []string{"artifact"}, Explanation: "release artifact evidence is missing", Remediation: "Register an artifact digest and link it to release evidence such as SBOM, scan, build output, or artifact digest evidence."}
}

func (l *Ledger) checkReleaseHasEvidenceLocked(tenantID, releaseID, typ, name, severity string) domain.PolicyCheck {
	for _, item := range l.evidence {
		if item.TenantID == tenantID && item.ReleaseID == releaseID && item.Type == typ {
			return domain.PolicyCheck{Name: name, Result: "passed", Severity: severity, Explanation: typ + " evidence exists"}
		}
	}
	return domain.PolicyCheck{Name: name, Result: "failed", Severity: severity, Missing: []string{typ}, Explanation: typ + " evidence is missing", Remediation: "Upload " + typ + " evidence for this release."}
}

func (l *Ledger) checkNoOpenCriticalLocked(tenantID, releaseID string) domain.PolicyCheck {
	blocking := l.unhandledCriticalFindingsLocked(tenantID, releaseID)
	if len(blocking) > 0 {
		return domain.PolicyCheck{Name: "critical_exploitable_blocks_release", Result: "failed", Severity: "critical", Missing: []string{"vulnerability_decision"}, Explanation: "open critical finding requires remediation, a valid VEX decision, or an approved unexpired exception", Remediation: "Record a fixed or not_affected vulnerability decision, upload VEX evidence, remediate the finding, or approve an unexpired scoped exception."}
	}
	return domain.PolicyCheck{Name: "critical_exploitable_blocks_release", Result: "passed", Severity: "critical", Explanation: "no open critical findings recorded"}
}

func (l *Ledger) checkNoOpenHighLocked(tenantID, releaseID string) domain.PolicyCheck {
	blocking := l.unhandledFindingsBySeverityLocked(tenantID, releaseID, "high")
	if len(blocking) > 0 {
		return domain.PolicyCheck{Name: "high_findings_require_triage", Result: "failed", Severity: "high", Missing: []string{"vulnerability_decision"}, Explanation: "open high finding requires a valid decision, remediation, or an approved unexpired exception", Remediation: "Record a fixed or not_affected vulnerability decision, upload VEX evidence, remediate the finding, or approve an unexpired scoped exception."}
	}
	return domain.PolicyCheck{Name: "high_findings_require_triage", Result: "passed", Severity: "high", Explanation: "no unhandled open high findings recorded"}
}
