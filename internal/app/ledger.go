package app

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
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
	BuildAttestationParser releaseapp.BuildAttestationParser
	DSSEPolicyVerifier     verificationapp.DSSEPolicyVerifier
	APIKeyPepper           string
	Now                    func() time.Time
	Store                  Store
	UnitOfWork             UnitOfWorkFactory
	ObjectStore            ObjectStore
	Retention              ObjectRetentionVerifier
	Signer                 SigningExecutor
	OIDC                   OIDCDiscoveryClient
	ProviderAPI            ProviderIdentityValidator
	Transparency           TransparencyProofFetcher
	Cosign                 CosignPolicyVerifier
	Outbox                 Outbox
	OutboxAdmin            OutboxAdmin
	ReconciliationMetrics  ObjectReconciliationMetricsStore
	ReadinessChecks        []ReadinessCheck
	// WorkerOwnedParserSideEffects stores accepted parser records first and
	// lets outbox workers populate parser-derived fields from raw payloads.
	WorkerOwnedParserSideEffects bool
}

// Ledger is the compatibility facade used while bounded-context services and
// query adapters migrate. Deprecated: new command behavior belongs in the
// owning context application package.
type Ledger struct {
	mu              sync.Mutex
	transactionGate sync.RWMutex

	pepper                 []byte
	now                    func() time.Time
	store                  Store
	evidencePages          EvidencePageStore
	workerProjections      WorkerProjectionStore
	unitOfWork             UnitOfWorkFactory
	objects                ObjectStore
	retention              ObjectRetentionVerifier
	signer                 SigningExecutor
	oidc                   OIDCDiscoveryClient
	providerAPI            ProviderIdentityValidator
	transparencyProofs     TransparencyProofFetcher
	cosign                 CosignPolicyVerifier
	outbox                 Outbox
	outboxAdmin            OutboxAdmin
	reconciliationMetrics  ObjectReconciliationMetricsStore
	readinessChecks        []ReadinessCheck
	workerOwnedParsers     bool
	buildAttestationParser releaseapp.BuildAttestationParser
	dssePolicyVerifier     verificationapp.DSSEPolicyVerifier
	releaseCommands        *releaseapp.Service
	evidenceCommands       *evidenceapp.Service
	identityCommands       *identityapp.Service
	riskCommands           *riskapp.Service
	packageCommands        *packageapp.Service
	verificationCommands   *verificationapp.Service

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
	// localVEXJobs is a compatibility-only, per-ledger handoff used when the
	// DB-less runtime has no durable outbox worker. The evidence transaction
	// adapter drains each job in a separate post-commit command.
	localVEXJobs map[string]OutboxJob
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
	if ctx == nil {
		return nil, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateLedgerDSSEPorts(cfg); err != nil {
		return nil, err
	}
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	pepper := strings.TrimSpace(cfg.APIKeyPepper)
	if pepper == "" {
		pepper = identityapp.LocalDevelopmentPepper
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
		pepper:                 []byte(pepper),
		now:                    now,
		store:                  cfg.Store,
		evidencePages:          evidencePageStore(cfg.Store),
		workerProjections:      workerProjectionStore(cfg.Store),
		unitOfWork:             unitOfWork,
		objects:                cfg.ObjectStore,
		retention:              retention,
		signer:                 cfg.Signer,
		oidc:                   cfg.OIDC,
		providerAPI:            cfg.ProviderAPI,
		transparencyProofs:     cfg.Transparency,
		cosign:                 cfg.Cosign,
		outbox:                 cfg.Outbox,
		outboxAdmin:            cfg.OutboxAdmin,
		reconciliationMetrics:  cfg.ReconciliationMetrics,
		readinessChecks:        normalizedReadinessChecks(cfg.ReadinessChecks),
		workerOwnedParsers:     cfg.WorkerOwnedParserSideEffects,
		buildAttestationParser: cfg.BuildAttestationParser,
		dssePolicyVerifier:     cfg.DSSEPolicyVerifier,
		tenants:                map[string]domain.Tenant{},
		organizations:          map[string]domain.Organization{},
		users:                  map[string]domain.HumanUser{},
		roleBindings:           map[string]domain.RoleBinding{},
		ssoProviders:           map[string]domain.SSOProvider{},
		identityLinks:          map[string]domain.UserIdentityLink{},
		ssoSessions:            map[string]domain.SSOSession{},
		apiKeys:                map[string]domain.APIKey{},
		collectors:             map[string]domain.Collector{},
		collectorReleases:      map[string]domain.CollectorRelease{},
		products:               map[string]domain.Product{},
		projects:               map[string]domain.Project{},
		releases:               map[string]domain.Release{},
		artifacts:              map[string]domain.Artifact{},
		buildRuns:              map[string]domain.BuildRun{},
		attestations:           map[string]domain.BuildAttestation{},
		evidence:               map[string]domain.EvidenceItem{},
		lifecycle:              map[string]domain.EvidenceLifecycleEvent{},
		candidates:             map[string]domain.ReleaseCandidate{},
		images:                 map[string]domain.ContainerImage{},
		artifactSigs:           map[string]domain.ArtifactSignature{},
		repositories:           map[string]domain.SourceRepository{},
		commits:                map[string]domain.SourceCommit{},
		branches:               map[string]domain.SourceBranch{},
		pullRequests:           map[string]domain.PullRequest{},
		environments:           map[string]domain.DeploymentEnvironment{},
		deployments:            map[string]domain.DeploymentEvent{},
		incidents:              map[string]domain.Incident{},
		timeline:               map[string]domain.IncidentTimelineEvent{},
		webhookReceivers:       map[string]domain.IncidentWebhookReceiver{},
		webhookEvents:          map[string]domain.IncidentWebhookEvent{},
		tasks:                  map[string]domain.RemediationTask{},
		securityScans:          map[string]domain.SecurityScan{},
		manualDocs:             map[string]domain.ManualSecurityDocument{},
		sbomDiffs:              map[string]domain.SBOMDiff{},
		depChanges:             map[string]domain.DependencyChange{},
		vulnWorkflow:           map[string]domain.VulnerabilityWorkflowRecord{},
		contractDiffs:          map[string]domain.ContractDiff{},
		customPolicies:         map[string]domain.CustomPolicy{},
		customPolicyEvals:      map[string]domain.CustomPolicyEvaluation{},
		waivers:                map[string]domain.Waiver{},
		approvals:              map[string]domain.ApprovalRecord{},
		redactions:             map[string]domain.RedactionProfile{},
		customerPackages:       map[string]domain.CustomerSecurityPackage{},
		htmlReports:            map[string]domain.HTMLReportPackage{},
		reportTemplates:        map[string]domain.CustomReportTemplate{},
		renderedReports:        map[string]domain.RenderedCustomReport{},
		evidenceBundles:        map[string]domain.EvidenceBundle{},
		bundleImports:          map[string]domain.EvidenceBundleImport{},
		dsseTrustRoots:         map[string]domain.DSSETrustRoot{},
		cosignVerifs:           map[string]domain.CosignVerification{},
		signingProviders:       map[string]domain.SigningProvider{},
		merkleBatches:          map[string]domain.MerkleBatch{},
		transparency:           map[string]domain.TransparencyCheckpoint{},
		retentionPolicies:      map[string]domain.ObjectRetentionPolicy{},
		backupManifests:        map[string]domain.BackupManifest{},
		legalHolds:             map[string]domain.LegalHold{},
		retentionOverrides:     map[string]domain.RetentionOverride{},
		portalAccess:           map[string]domain.CustomerPortalAccess{},
		questionTemplates:      map[string]domain.QuestionnaireTemplate{},
		questionPackages:       map[string]domain.QuestionnairePackage{},
		answerLibrary:          map[string]domain.QuestionnaireAnswerLibraryEntry{},
		commercialCollectors:   map[string]domain.CommercialCollectorDefinition{},
		evidenceSummaries:      map[string]domain.EvidenceSummary{},
		questionDrafts:         map[string]domain.QuestionnaireDraft{},
		graphSnapshots:         map[string]domain.EvidenceGraphSnapshot{},
		saasProfiles:           map[string]domain.SaaSEditionProfile{},
		publicLogs:             map[string]domain.PublicTransparencyLog{},
		publicLogEntries:       map[string]domain.PublicTransparencyLogEntry{},
		marketplaceCollectors:  map[string]domain.MarketplaceCollector{},
		pdfReports:             map[string]domain.PDFReportPackage{},
		anomalyReports:         map[string]domain.AnomalyReport{},
		providerVerifications:  map[string]domain.ProviderVerification{},
		signingOperations:      map[string]domain.SigningOperation{},
		frameworks:             map[string]domain.ControlFramework{},
		controls:               map[string]domain.SecurityControl{},
		controlLinks:           map[string]domain.ControlEvidence{},
		sboms:                  map[string]domain.SBOM{},
		scans:                  map[string]domain.VulnerabilityScan{},
		vexDocuments:           map[string]domain.VEXDocument{},
		vexImportReports:       map[string]domain.VEXImportReport{},
		decisions:              map[string]domain.VulnerabilityDecision{},
		contracts:              map[string]domain.OpenAPIContract{},
		policies:               map[string]domain.PolicyEvaluation{},
		exceptions:             map[string]domain.Exception{},
		bundles:                map[string]domain.ReleaseBundle{},
		signingKeys:            map[string]domain.SigningKey{},
		signatures:             map[string]domain.Signature{},
		verifications:          map[string]domain.VerificationResult{},
		chain:                  map[string][]domain.AuditChainEntry{},
		idempotency:            map[string]IdempotencyRecord{},
		localVEXJobs:           map[string]OutboxJob{},
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
	if err := ledger.configureReleaseCommands(); err != nil {
		return nil, err
	}
	if err := ledger.configureEvidenceCommands(); err != nil {
		return nil, err
	}
	if err := ledger.configureIdentityCommands(); err != nil {
		return nil, err
	}
	if err := ledger.configureRiskCommands(); err != nil {
		return nil, err
	}
	if err := ledger.configurePackageCommands(); err != nil {
		return nil, err
	}
	if err := ledger.configureVerificationCommands(); err != nil {
		return nil, err
	}
	return ledger, nil
}

func evidencePageStore(store Store) EvidencePageStore {
	pages, _ := store.(EvidencePageStore)
	return pages
}

func workerProjectionStore(store Store) WorkerProjectionStore {
	projections, _ := store.(WorkerProjectionStore)
	return projections
}

func (l *Ledger) HasTenants(ctx context.Context) bool {
	hasTenants, _ := l.identityCommands.HasTenants(ctx)
	return hasTenants
}

func (l *Ledger) BootstrapTenant(ctx context.Context, name, keyName string, scopes []string) (domain.Tenant, domain.APIKey, string, error) {
	return l.bootstrapTenant(ctx, identityapp.BootstrapTenantInput{
		TenantName: name, APIKeyName: keyName, Scopes: scopes,
	})
}

func (l *Ledger) Authenticate(ctx context.Context, secret string) (domain.Actor, error) {
	actor, err := l.identityCommands.Authenticate(ctx, secret)
	return actor, fromIdentityContextError(err)
}

func (l *Ledger) CreateAPIKey(ctx context.Context, actor domain.Actor, name string, scopes []string, expiresAt *time.Time) (domain.APIKey, string, error) {
	key, secret, err := l.identityCommands.CreateAPIKey(ctx, actor, identityapp.CreateAPIKeyInput{Name: name, Scopes: scopes, ExpiresAt: expiresAt})
	return apiKeyFromIdentityContext(key), secret, fromIdentityContextError(err)
}

func (l *Ledger) ListAPIKeys(ctx context.Context, actor domain.Actor) ([]domain.APIKey, error) {
	keys, err := l.identityCommands.ListAPIKeys(ctx, actor)
	if err != nil {
		return nil, fromIdentityContextError(err)
	}
	result := make([]domain.APIKey, 0, len(keys))
	for _, key := range keys {
		result = append(result, apiKeyFromIdentityContext(key))
	}
	return result, nil
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
	StagedPayload    ObjectPayload
	SubjectRefs      []domain.SubjectRef
	Metadata         map[string]any
	Tags             []string
	Limitations      []string
}

// newEvidenceItemForScopeLocked keeps composite command authorization explicit.
// The build-attestation and deployment compatibility bridges use their
// documented command scopes and must not introduce a hidden evidence:write
// requirement.
func (s releaseEvidenceService) newEvidenceItemForScopeLocked(actor domain.Actor, authorizationScope string, in CreateEvidenceInput) (domain.EvidenceItem, error) {
	if authorizationScope != ScopeEvidenceWrite && authorizationScope != ScopeBuildWrite && authorizationScope != ScopeDeploymentWrite {
		return domain.EvidenceItem{}, ErrValidation
	}
	deploymentEvent := strings.TrimSpace(in.Type) == "deployment" && strings.TrimSpace(in.Subtype) == "event" && strings.TrimSpace(in.DeploymentID) != ""
	if (authorizationScope == ScopeDeploymentWrite) != deploymentEvent {
		return domain.EvidenceItem{}, ErrValidation
	}
	l := s.ledger
	if err := l.ensureScopeLocked(actor.TenantID, in.ProductID, in.ProjectID, in.ReleaseID); err != nil {
		return domain.EvidenceItem{}, err
	}
	if err := l.authorizeResourceLocked(actor, authorizationScope, resourceRefs{ProductID: in.ProductID, ProjectID: in.ProjectID, ReleaseID: in.ReleaseID}); err != nil {
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
		Canonicalization:    evidencedomain.EvidenceCanonicalizationProfileVersion,
		SubjectRefs:         append([]domain.SubjectRef(nil), in.SubjectRefs...),
		TrustLevel:          "L2",
		VerificationStatus:  "pending",
		Tags:                sortedStrings(in.Tags),
		Metadata:            cloneMap(in.Metadata),
		Limitations:         append([]string(nil), in.Limitations...),
		CreatedAt:           now,
		RelatedEvidenceRefs: nil,
	}
	item = withEvidenceCanonicalOriginRefs(item)
	hash, err := canonicalHash(item)
	if err != nil {
		return domain.EvidenceItem{}, err
	}
	item.CanonicalHash = hash
	return item, nil
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
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return domain.SBOM{}, err
	}
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
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return nil, err
	}
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
		for index, component := range sbom.Components {
			if !sbomComponentMatches(component, in.Query, in.PURL) {
				continue
			}
			out = append(out, domain.SBOMComponentRecord{ID: sbom.ID + ":" + strconv.Itoa(index), SBOMID: sbom.ID, ReleaseID: sbom.ReleaseID, ArtifactID: sbom.ArtifactID, Format: sbom.Format, SpecVersion: sbom.SpecVersion, Component: component})
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
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return domain.VulnerabilityScan{}, err
	}
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
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return domain.OpenAPIContract{}, err
	}
	contract, ok := l.contracts[strings.TrimSpace(id)]
	if !ok || contract.TenantID != actor.TenantID {
		return domain.OpenAPIContract{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ProductID: contract.ProductID, ReleaseID: contract.ReleaseID}); err != nil {
		return domain.OpenAPIContract{}, err
	}
	return contract, nil
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

// IdempotencyCommand runs application writes using the isolated ledger view
// bound to the idempotency transaction. It must use the provided context and
// ledger rather than retaining either after it returns.
type IdempotencyCommand func(context.Context, *Ledger) (int, any, error)

func (l *Ledger) WithIdempotency(ctx context.Context, actor domain.Actor, method, path, key string, body []byte, run IdempotencyCommand) (int, any, error) {
	return l.withIdempotencyRequestHash(ctx, actor, method, path, key, hashBytes(append([]byte(method+"\n"+path+"\n"), body...)), run)
}

// WithIdempotencyRequestHash permits streaming transports to retain only a
// request digest. The supplied digest must cover the complete request body;
// the method and path remain part of the persisted idempotency fingerprint.
func (l *Ledger) WithIdempotencyRequestHash(ctx context.Context, actor domain.Actor, method, path, key, bodyDigest string, run IdempotencyCommand) (int, any, error) {
	if !validDigest(bodyDigest) {
		return 0, nil, ErrValidation
	}
	return l.withIdempotencyRequestHash(ctx, actor, method, path, key, hashBytes([]byte(method+"\n"+path+"\n"+bodyDigest)), run)
}

func (l *Ledger) withIdempotencyRequestHash(ctx context.Context, actor domain.Actor, method, path, key, requestHash string, run IdempotencyCommand) (int, any, error) {
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}
	key = strings.TrimSpace(key)
	if key == "" || run == nil || !validDigest(requestHash) {
		return 0, nil, ErrValidation
	}
	persistenceKey := IdempotencyRecordKey{TenantID: actor.TenantID, ActorID: idempotencyActorID(actor), Method: method, Path: path, IdempotencyKey: key}
	reservation, err := newIdempotencyReservation(persistenceKey, requestHash, l.now())
	if err != nil {
		return 0, nil, err
	}
	if l.unitOfWork != nil {
		return l.withDurableIdempotency(ctx, reservation, run)
	}
	return l.withInMemoryIdempotency(ctx, reservation, run)
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
	key, secret := l.newAPIKey(tenantID, name, scopes, expiresAt)
	l.apiKeys[key.ID] = key
	public := key
	public.Hash = ""
	return public, secret, nil
}

// newAPIKey derives a credential and its stored hash without publishing either
// value to the process read model. Transactional callers must persist key
// material before returning the bearer secret to the caller.
func (l *Ledger) newAPIKey(tenantID, name string, scopes []string, expiresAt *time.Time) (domain.APIKey, string) {
	secret := "evy_" + randomToken(32)
	key := domain.APIKey{ID: newID("key"), TenantID: tenantID, Name: name, Prefix: secretPrefix(secret), Scopes: sortedStrings(scopes), CreatedAt: l.now(), ExpiresAt: expiresAt, Hash: l.hashSecret(secret)}
	return key, secret
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

// newSigningKey creates private material without publishing it. Callers must
// write it transactionally and must never return Private to normal callers.
func (l *Ledger) newSigningKeyAt(tenantID, provider string, version int, now time.Time) (domain.SigningKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return domain.SigningKey{}, err
	}
	if provider == "" {
		provider = domain.SigningKeyDefaultProvider
	}
	if version < 1 {
		version = 1
	}
	now = now.UTC()
	fingerprint := sha256.Sum256(pub)
	return domain.SigningKey{ID: newID("sk"), TenantID: tenantID, KID: fmt.Sprintf("%s-v%d", now.Format("20060102T150405Z"), version), Version: version, Provider: provider, Algorithm: "Ed25519", Status: domain.SigningKeyStatusActive, PublicKey: base64.RawStdEncoding.EncodeToString(pub), PublicKeyFingerprint: "sha256:" + hex.EncodeToString(fingerprint[:]), Private: priv, ValidFrom: now, CreatedAt: now, HistoricalValidityPolicy: domain.SigningKeyHistoricalValidityPreserve}, nil
}

func (l *Ledger) verifySignatureLocked(tenantID string, signatureRefs []string, payload []byte) bool {
	return l.verifySignatureForSubjectLocked(tenantID, signatureRefs, "", "", payload)
}

// verifySignatureForSubjectLocked verifies both the cryptographic value and the
// immutable subject recorded with the signature. Callers that verify an
// identifiable ledger object must use this form so a valid signature for one
// object cannot be replayed for another object with identical bytes.
func (l *Ledger) verifySignatureForSubjectLocked(tenantID string, signatureRefs []string, subjectType, subjectID string, payload []byte) bool {
	for _, ref := range signatureRefs {
		sig, ok := l.signatures[ref]
		if !ok || sig.TenantID != tenantID {
			continue
		}
		if subjectType != "" && (sig.SubjectType != subjectType || sig.SubjectID != subjectID) {
			continue
		}
		key, ok := l.signingKeys[sig.KeyID]
		if !ok || key.TenantID != tenantID {
			continue
		}
		if key.HistoricalValidityAt(sig.CreatedAt, l.now().UTC()) != domain.SigningKeyHistoricalValidityValid {
			continue
		}
		if (ledgerVerificationPayloadVerifier{}).VerifyPayload(key.PublicKey, sig.Value, payload) {
			return true
		}
	}
	return false
}

// Compatibility-only crypto adapter for the explicit local Ledger profile.
// Durable commands receive their cryptographic adapter from platform wiring.
type ledgerVerificationPayloadVerifier struct{}

func (ledgerVerificationPayloadVerifier) VerifyPayload(publicKey, signature string, payload []byte) bool {
	if len(publicKey) > 128 || len(signature) > 128 {
		return false
	}
	public, err := base64.RawStdEncoding.DecodeString(publicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return false
	}
	value, err := base64.RawStdEncoding.DecodeString(signature)
	return err == nil && ed25519.Verify(ed25519.PublicKey(public), payload, value)
}
