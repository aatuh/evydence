package httpapi

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

// Authenticator is the transport's identity-verification boundary. Keeping it
// separate from the identity administration surface makes authentication an
// explicit dependency of every protected route.
type Authenticator interface {
	Authenticate(context.Context, string) (domain.Actor, error)
}

// ReadinessQuery probes process dependencies without consulting Ledger state.
// Operator details require explicit instance-wide authority in the service.
type ReadinessQuery interface {
	Public(context.Context) (map[string]any, error)
	Operator(context.Context, domain.Actor) (map[string]any, error)
}

// MetricsQuery returns tenant-safe counters and optional instance diagnostics
// without loading Ledger state or exposing evidence payloads.
type MetricsQuery interface {
	Snapshot(context.Context, domain.Actor) (map[string]any, error)
}

// RetentionQuery reads a tenant-wide report from a consistent durable
// projection; local memory retains its explicit Ledger-backed path.
type RetentionQuery interface {
	Report(context.Context, domain.Actor, string, string) (operationsdomain.RetentionReport, error)
}

// IncidentReportQuery assembles one tenant-owned incident report without
// loading other incidents or the compatibility Ledger.
type IncidentReportQuery interface {
	Report(context.Context, domain.Actor, string) (packagedomain.IncidentReport, error)
}

// SecurityUpdateEvidenceQuery assembles one tenant-owned release report from
// bounded, report-safe durable projections rather than Ledger maps.
type SecurityUpdateEvidenceQuery interface {
	Report(context.Context, domain.Actor, string, string) (packagedomain.SecurityUpdateEvidenceReport, error)
}

// CRAVulnerabilityQuery assembles one bounded release-scoped vulnerability
// handling report from report-safe durable projections.
type CRAVulnerabilityQuery interface {
	Report(context.Context, domain.Actor, string, string) (packagedomain.CRAVulnerabilityHandlingReport, error)
}

// MissingEvidenceQuery reads a committed release-readiness projection.
type MissingEvidenceQuery interface {
	Report(context.Context, domain.Actor, string) (map[string]any, error)
}

// ReleaseReadinessReportQuery renders a read-only bounded release snapshot.
type ReleaseReadinessReportQuery interface {
	Report(context.Context, domain.Actor, string) (packagedomain.ReleaseReadinessReport, error)
}

// CustomerPackageAccessCommands preserves atomic access counting and audit
// behavior while reading one durable package instead of Ledger maps.
type CustomerPackageAccessCommands interface {
	AccessCustomerSecurityPackage(context.Context, domain.Actor, string) (packagedomain.CustomerSecurityPackage, error)
	SecurityReviewPackageReport(context.Context, domain.Actor, string) (packagedomain.SecurityReviewPackageReport, error)
}

// HTMLReportCommands persists an escaped CRA report and its audit atomically.
type HTMLReportCommands interface {
	CRAReadinessHTMLPackage(context.Context, domain.Actor, string, string) (packagedomain.HTMLReportPackage, error)
}

type ReportTemplateCommands interface {
	CreateCustomReportTemplate(context.Context, domain.Actor, packageapp.CreateReportTemplateInput) (packagedomain.CustomReportTemplate, error)
	RenderCustomReport(context.Context, domain.Actor, packageapp.RenderReportInput) (packagedomain.RenderedCustomReport, error)
}

type BundleImportCommand interface {
	ImportEvidenceBundle(context.Context, domain.Actor, packagedomain.EvidenceBundle) (packagedomain.EvidenceBundleImport, error)
}

type ReleaseBundleCommands interface {
	CreateReleaseBundle(context.Context, identitydomain.Actor, string) (packagedomain.ReleaseBundle, error)
}

type EvidenceBundleCommands interface {
	ExportEvidenceBundle(context.Context, identitydomain.Actor, string, []string) (packagedomain.EvidenceBundle, error)
}

type SigningKeyCommands interface {
	RotateSigningKey(context.Context, identitydomain.Actor, string) (verificationdomain.SigningKey, error)
	RevokeSigningKey(context.Context, identitydomain.Actor, string, verificationapp.SigningKeyRevocationInput) (verificationdomain.SigningKey, error)
}

type RetentionCommands interface {
	CreateObjectRetentionPolicy(context.Context, identitydomain.Actor, verificationapp.CreateObjectRetentionPolicyInput) (verificationdomain.ObjectRetentionPolicy, error)
	VerifyObjectRetentionPolicy(context.Context, identitydomain.Actor, string) (verificationdomain.ObjectRetentionPolicy, error)
}

type ReleaseBundleVerification interface {
	VerifyReleaseBundle(context.Context, identitydomain.Actor, string) (verificationdomain.VerificationResult, error)
}

type EvidenceVerification interface {
	VerifyEvidence(context.Context, identitydomain.Actor, string) (verificationdomain.VerificationResult, error)
}

// SigningCustodyQuery assesses bounded durable provider and retention records.
type SigningCustodyQuery interface {
	Report(context.Context, identitydomain.Actor) (verificationdomain.SigningCustodyReviewReport, error)
}

// ReleaseSecuritySummaryQuery assembles one release's security overview from
// a bounded, tenant-scoped committed snapshot.
type ReleaseSecuritySummaryQuery interface {
	Summary(context.Context, domain.Actor, string) (riskdomain.ReleaseSecuritySummary, error)
}

// ControlCoverageQuery evaluates tenant-scoped control and CRA readiness
// reports from one bounded durable snapshot.
type ControlCoverageQuery interface {
	Coverage(context.Context, domain.Actor, packagequery.ControlCoverageFilter) (packagedomain.ControlCoverageReport, error)
	CRAReadiness(context.Context, domain.Actor, string, string) (packagedomain.CRAReadinessReport, error)
}

// InstanceAdminQuery returns aggregate operational counts only after the
// focused service verifies explicit instance-wide authority.
type InstanceAdminQuery interface {
	Snapshot(context.Context, domain.Actor) (operationsdomain.InstanceAdminSnapshot, error)
}

// OutboxReplayCommand owns the replay mutation and its idempotency record in
// one durable transaction. Local memory retains the Ledger-backed route.
type OutboxReplayCommand interface {
	ReplayIdempotent(context.Context, domain.Actor, string, string, string, []byte, string) (int, any, error)
}

// ProductQuery is a focused, authorized catalog read. Production bindings
// apply tenant/grant filters in PostgreSQL before returning records.
type ProductQuery interface {
	ListProductsPage(context.Context, domain.Actor, appquery.PageRequest, *appquery.SortKey) (appquery.Result[releasedomain.Product], error)
	GetProduct(context.Context, domain.Actor, string) (releasedomain.Product, error)
}

// CatalogPointQuery reads projects and releases from tenant-filtered durable
// storage while the local-memory profile retains compatibility readers.
type CatalogPointQuery interface {
	GetProject(context.Context, domain.Actor, string) (releasedomain.Project, error)
	GetRelease(context.Context, domain.Actor, string) (releasedomain.Release, error)
}

// EvidenceFlowQuery builds a tenant- and grant-scoped workflow snapshot from
// bounded database aggregates rather than the compatibility Ledger maps.
type EvidenceFlowQuery interface {
	Plan(context.Context, domain.Actor, string) (releasedomain.ReleaseEvidenceFlow, error)
}

// OutboxDiagnosticsQuery exposes payload-free queue health to explicitly
// authorized instance administrators without using Ledger state.
type OutboxDiagnosticsQuery interface {
	Diagnostics(context.Context, domain.Actor) (operationsquery.OutboxCounts, error)
}

// BuildPointQuery authorizes a build using one tenant-verified durable parent projection.
type BuildPointQuery interface {
	GetBuildRun(context.Context, domain.Actor, string) (releasedomain.BuildRun, error)
}

// ArtifactPointQuery checks current evidence/build associations for scoped
// human grants in a tenant-filtered PostgreSQL read.
type ArtifactPointQuery interface {
	GetArtifact(context.Context, domain.Actor, string) (releasedomain.Artifact, error)
}

// ReleaseCandidateQuery reads one tenant-verified candidate or a SQL-filtered
// page using current release and product ownership.
type ReleaseCandidateQuery interface {
	GetReleaseCandidate(context.Context, domain.Actor, string) (releasedomain.ReleaseCandidate, error)
	ListPage(context.Context, domain.Actor, string, appquery.PageRequest, *appquery.SortKey) (appquery.Result[releasedomain.ReleaseCandidate], error)
}

// DeploymentPointQuery authorizes a deployment against its current tenant-owned
// release and environment without consulting the Ledger projection.
type DeploymentPointQuery interface {
	GetDeployment(context.Context, domain.Actor, string) (operationsdomain.DeploymentEvent, error)
}

// DeploymentListQuery returns tenant/grant-filtered pages from PostgreSQL.
type DeploymentListQuery interface {
	ListEnvironmentsPage(context.Context, domain.Actor, string, appquery.PageRequest, *appquery.SortKey) (appquery.Result[operationsdomain.DeploymentEnvironment], error)
	ListDeploymentsPage(context.Context, domain.Actor, string, string, appquery.PageRequest, *appquery.SortKey) (appquery.Result[operationsdomain.DeploymentEvent], error)
}

// EvidencePointQuery reads authorized ordinary evidence from a bounded
// PostgreSQL snapshot. Worker-owned records retain the validated projection.
type EvidencePointQuery interface {
	GetEvidence(context.Context, domain.Actor, string) (evidencedomain.EvidenceItem, error)
}

// LifecycleEventsQuery pages ordinary evidence events from one tenant-bound
// database snapshot. Worker-owned evidence retains the provenance projection.
type LifecycleEventsQuery interface {
	ListPage(context.Context, domain.Actor, string, appquery.PageRequest, *appquery.SortKey) (appquery.Result[evidencedomain.EvidenceLifecycleEvent], error)
}

// OpenAPIContractPointQuery reads one parsed contract against current
// tenant-owned evidence, product, and release parents.
type OpenAPIContractPointQuery interface {
	GetOpenAPIContract(context.Context, domain.Actor, string) (evidencedomain.OpenAPIContract, error)
}

// SBOMPointQuery reads one parsed document against current tenant-owned
// evidence and release parents.
type SBOMPointQuery interface {
	GetSBOM(context.Context, domain.Actor, string) (evidencedomain.SBOM, error)
}

// VulnerabilityScanPointQuery resolves one parsed scan against current source
// evidence and tenant-owned release coordinates.
type VulnerabilityScanPointQuery interface {
	GetVulnerabilityScan(context.Context, domain.Actor, string) (evidencedomain.VulnerabilityScan, error)
}

// VEXPointQuery authorizes a document or its import report against the same
// current source evidence and tenant-owned parent coordinates.
type VEXPointQuery interface {
	GetVEXDocument(context.Context, domain.Actor, string) (evidencedomain.VEXDocument, error)
	GetVEXImportReport(context.Context, domain.Actor, string) (evidencedomain.VEXImportReport, error)
}

// SBOMComponentsQuery returns an authorized, bounded component page from
// current tenant-owned SBOM and artifact associations.
type SBOMComponentsQuery interface {
	ListPage(context.Context, domain.Actor, evidencequery.SBOMComponentFilter, appquery.PageRequest, *appquery.SortKey) (appquery.Result[evidencedomain.SBOMComponentRecord], error)
}

// SourceRepositoryQuery returns one tenant/grant-filtered durable page.
type SourceRepositoryQuery interface {
	ListPage(context.Context, domain.Actor, string, appquery.PageRequest, *appquery.SortKey) (appquery.Result[integrationdomain.SourceRepository], error)
}

// CollectorQuery pages tenant inventory without loading Ledger state or
// selecting credential secrets from PostgreSQL.
type CollectorQuery interface {
	ListPage(context.Context, domain.Actor, appquery.PageRequest, *appquery.SortKey) (appquery.Result[integrationdomain.Collector], error)
}

// CollectorHealthQuery reads one tenant-owned collector and its latest and
// pinned release from a consistent durable snapshot.
type CollectorHealthQuery interface {
	Report(context.Context, domain.Actor, string) (integrationdomain.CollectorHealthReport, error)
}

// CommercialCollectorQuery pages tenant-owned integration definitions.
type CommercialCollectorQuery interface {
	ListPage(context.Context, domain.Actor, appquery.PageRequest, *appquery.SortKey) (appquery.Result[integrationdomain.CommercialCollectorDefinition], error)
}

// MarketplaceCollectorQuery reads tenant-owned package metadata and current
// linked evidence through one bounded PostgreSQL read boundary.
type MarketplaceCollectorQuery interface {
	ListPage(context.Context, domain.Actor, appquery.PageRequest, *appquery.SortKey) (appquery.Result[experimentaldomain.MarketplaceCollector], error)
	Health(context.Context, domain.Actor, string) (experimentaldomain.MarketplaceCollectorHealthReport, error)
}

// VulnerabilityPostureQuery reads aggregate scan counts from one tenant-bound
// database snapshot; no raw findings cross this transport boundary.
type VulnerabilityPostureQuery interface {
	Report(context.Context, domain.Actor, string) (packagedomain.VulnerabilityPostureReport, error)
}

// ControlsQuery reads tenant-wide governance definitions from durable storage.
type ControlsQuery interface {
	ListFrameworksPage(context.Context, domain.Actor, appquery.PageRequest, *appquery.SortKey) (appquery.Result[riskdomain.ControlFramework], error)
	GetSecurityControl(context.Context, domain.Actor, string) (riskdomain.SecurityControl, error)
}

// ControlTemplateQuery lists static, risk-owned starter definitions without
// reaching the compatibility Ledger's tenant state.
type ControlTemplateQuery interface {
	ListTemplatePacks(context.Context, domain.Actor) ([]riskdomain.ControlFrameworkTemplatePack, error)
}

// ExceptionsQuery applies current verify grants before returning a bounded
// page of tenant-owned exception records.
type ExceptionsQuery interface {
	ListPage(context.Context, domain.Actor, string, appquery.PageRequest, *appquery.SortKey) (appquery.Result[riskdomain.Exception], error)
}

// VulnerabilityDecisionQuery returns a grant-filtered durable page without
// selecting tenant-internal notes or materializing all tenant decisions.
type VulnerabilityDecisionQuery interface {
	ListPage(context.Context, domain.Actor, riskquery.DecisionFilter, appquery.PageRequest, *appquery.SortKey) (appquery.Result[riskdomain.VulnerabilityDecision], error)
}

// VulnerabilityDecisionSummaryQuery reads one release's customer-safe active
// decision snapshot after applying the actor's report grant.
type VulnerabilityDecisionSummaryQuery interface {
	SummaryReport(context.Context, domain.Actor, string) (riskdomain.VulnerabilityDecisionSummaryReport, error)
}

// ControlEvidenceQuery pages current tenant-owned links after subject and
// resource-grant validation in the durable query boundary.
type ControlEvidenceQuery interface {
	ListPage(context.Context, domain.Actor, riskquery.ControlEvidenceFilter, appquery.PageRequest, *appquery.SortKey) (appquery.Result[riskdomain.ControlEvidence], error)
}

// ArtifactSignatureQuery reads one tenant-owned signature against its current
// artifact digest and the actor's current resource visibility.
type ArtifactSignatureQuery interface {
	GetArtifactSignature(context.Context, domain.Actor, string) (verificationdomain.ArtifactSignature, error)
}

// SigningKeyQuery pages public signing-key metadata without reading private material.
type SigningKeyQuery interface {
	ListPage(context.Context, domain.Actor, appquery.PageRequest, *appquery.SortKey) (appquery.Result[verificationdomain.SigningKey], error)
}

// ReleaseBundleQuery reads a bundle and its manifest from a current
// tenant-owned release after applying the actor's bundle-read grant.
type ReleaseBundleQuery interface {
	GetReleaseBundle(context.Context, domain.Actor, string) (packagedomain.ReleaseBundle, error)
}

// AnswerLibraryQuery pages tenant/grant-filtered reusable drafts without
// exposing private answer text from unrelated product or release scopes.
type AnswerLibraryQuery interface {
	ListPage(context.Context, domain.Actor, packagequery.AnswerLibraryFilter, appquery.PageRequest, *appquery.SortKey) (appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry], error)
}

// PortalAccessQuery pages only grant-visible customer package access metadata
// and never exposes the underlying portal token hash.
type PortalAccessQuery interface {
	ListPage(context.Context, domain.Actor, string, appquery.PageRequest, *appquery.SortKey) (appquery.Result[packagedomain.CustomerPortalAccess], error)
}

// AuditLogQuery pages current tenant audit entries without loading the Ledger.
type AuditLogQuery interface {
	ListPage(context.Context, domain.Actor, verificationquery.AuditFilter, appquery.PageRequest, *appquery.SortKey) (appquery.Result[verificationdomain.AuditChainEntry], error)
}

// APIKeyQuery returns only public key metadata from a bounded tenant page.
type APIKeyQuery interface {
	ListPage(context.Context, domain.Actor, appquery.PageRequest, *appquery.SortKey) (appquery.Result[identitydomain.APIKey], error)
}

// RoleBindingQuery returns one authorized tenant page of current bindings.
type RoleBindingQuery interface {
	ListPage(context.Context, domain.Actor, appquery.PageRequest, *appquery.SortKey) (appquery.Result[identitydomain.RoleBinding], error)
}

// commandScope binds transaction-local command services without exposing the
// compatibility Ledger type to HTTP command wrappers or context-owned
// handlers. The Ledger-backed implementation remains an adapter until the
// composition root is replaced by EVY-905.
type commandScope interface {
	bind(*Server)
}

type idempotencyExecutor interface {
	WithBody(context.Context, domain.Actor, string, string, string, []byte, func(context.Context, commandScope) (int, any, error)) (int, any, error)
	WithBodyDigest(context.Context, domain.Actor, string, string, string, string, func(context.Context, commandScope) (int, any, error)) (int, any, error)
}

type ledgerCommandScope struct {
	ledger *app.Ledger
}

func (scope ledgerCommandScope) bind(server *Server) {
	server.bindLedger(scope.ledger)
}

type ledgerIdempotencyExecutor struct {
	ledger *app.Ledger
}

func (executor ledgerIdempotencyExecutor) WithBody(ctx context.Context, actor domain.Actor, method, path, key string, body []byte, run func(context.Context, commandScope) (int, any, error)) (int, any, error) {
	if executor.ledger == nil || run == nil {
		return 0, nil, app.ErrValidation
	}
	return executor.ledger.WithIdempotency(ctx, actor, method, path, key, body, func(commandCtx context.Context, commandLedger *app.Ledger) (int, any, error) {
		return run(commandCtx, ledgerCommandScope{ledger: commandLedger})
	})
}

func (executor ledgerIdempotencyExecutor) WithBodyDigest(ctx context.Context, actor domain.Actor, method, path, key, bodyDigest string, run func(context.Context, commandScope) (int, any, error)) (int, any, error) {
	if executor.ledger == nil || run == nil {
		return 0, nil, app.ErrValidation
	}
	return executor.ledger.WithIdempotencyRequestHash(ctx, actor, method, path, key, bodyDigest, func(commandCtx context.Context, commandLedger *app.Ledger) (int, any, error) {
		return run(commandCtx, ledgerCommandScope{ledger: commandLedger})
	})
}

// identityAccessService is the HTTP-facing compatibility port for identity
// and access commands and queries. The legacy Ledger implements this port while
// callers migrate to the context-owned application service.
type identityAccessService interface {
	CreateAPIKey(context.Context, domain.Actor, string, []string, *time.Time) (domain.APIKey, string, error)
	ListAPIKeys(context.Context, domain.Actor) ([]domain.APIKey, error)
	CreateOrganization(context.Context, domain.Actor, app.CreateOrganizationInput) (domain.Organization, error)
	CreateUser(context.Context, domain.Actor, app.CreateUserInput) (domain.HumanUser, error)
	DeactivateUser(context.Context, domain.Actor, string) (domain.HumanUser, error)
	CreateRoleBinding(context.Context, domain.Actor, app.CreateRoleBindingInput) (domain.RoleBinding, error)
	ListRoleBindings(context.Context, domain.Actor) ([]domain.RoleBinding, error)
	CreateSSOProvider(context.Context, domain.Actor, app.CreateSSOProviderInput) (domain.SSOProvider, error)
	UpdateSSOProviderTrustMaterial(context.Context, domain.Actor, string, app.UpdateSSOProviderTrustMaterialInput) (domain.SSOProvider, error)
	RefreshSSOProviderOIDCTrustMaterial(context.Context, domain.Actor, string) (domain.SSOProvider, error)
	LinkSSOIdentity(context.Context, domain.Actor, app.LinkSSOIdentityInput) (domain.UserIdentityLink, error)
	CreateSSOSession(context.Context, domain.Actor, app.CreateSSOSessionInput) (domain.SSOSession, string, error)
	ExchangeSSOCredential(context.Context, app.ExchangeSSOCredentialInput) (domain.ProviderVerification, domain.SSOSession, string, error)
	RevokeSSOSession(context.Context, domain.Actor, string) (domain.SSOSession, error)
	RevokeCurrentSSOSession(context.Context, domain.Actor) (domain.SSOSession, error)
}

// releaseCatalogService contains only release-catalog operations owned by the
// release context. Verification, decision, package, and platform operations
// remain on their separate migration paths.
type releaseCatalogService interface {
	CreateProduct(context.Context, domain.Actor, string, string) (domain.Product, error)
	ListProducts(context.Context, domain.Actor) ([]domain.Product, error)
	GetProduct(context.Context, domain.Actor, string) (domain.Product, error)
	CreateProject(context.Context, domain.Actor, string, string) (domain.Project, error)
	GetProject(context.Context, domain.Actor, string) (domain.Project, error)
	CreateRelease(context.Context, domain.Actor, string, string) (domain.Release, error)
	GetRelease(context.Context, domain.Actor, string) (domain.Release, error)
	ReleaseEvidenceFlowPlan(context.Context, domain.Actor, string) (domain.ReleaseEvidenceFlow, error)
	FreezeRelease(context.Context, domain.Actor, string, int64) (domain.Release, error)
	ApproveRelease(context.Context, domain.Actor, string, int64) (domain.Release, error)
	CreateReleaseCandidate(context.Context, domain.Actor, app.CreateReleaseCandidateInput) (domain.ReleaseCandidate, error)
	ListReleaseCandidates(context.Context, domain.Actor, string) ([]domain.ReleaseCandidate, error)
	GetReleaseCandidate(context.Context, domain.Actor, string) (domain.ReleaseCandidate, error)
	UpdateReleaseCandidateState(context.Context, domain.Actor, string, string, string, int64) (domain.ReleaseCandidate, error)
	RegisterArtifact(context.Context, domain.Actor, string, string, string, int64) (domain.Artifact, error)
	GetArtifact(context.Context, domain.Actor, string) (domain.Artifact, error)
	RegisterContainerImage(context.Context, domain.Actor, app.RegisterContainerImageInput) (domain.ContainerImage, error)
	CreateBuildRun(context.Context, domain.Actor, app.CreateBuildRunInput) (domain.BuildRun, error)
	GetBuildRun(context.Context, domain.Actor, string) (domain.BuildRun, error)
	UploadBuildAttestation(context.Context, domain.Actor, string, []byte) (domain.BuildAttestation, error)
}

// evidenceIngestionService contains accepted-evidence, document-ingestion,
// normalization, and evidence-diff operations. Decision and report workflows
// intentionally remain outside this boundary.
type evidenceIngestionService interface {
	UploadSecurityScan(context.Context, domain.Actor, app.UploadSecurityScanInput) (domain.SecurityScan, error)
	UploadAPISecurityScan(context.Context, domain.Actor, app.UploadSecurityScanInput) (domain.SecurityScan, error)
	UploadManualSecurityDocument(context.Context, domain.Actor, app.UploadManualSecurityDocumentInput) (domain.ManualSecurityDocument, error)
	UploadSPDXSBOM(context.Context, domain.Actor, string, string, []byte) (domain.SBOM, error)
	UploadSPDXSBOMPayload(context.Context, domain.Actor, string, string, app.PayloadSource) (domain.SBOM, error)
	CreateSBOMDiff(context.Context, domain.Actor, app.CreateSBOMDiffInput) (domain.SBOMDiff, error)
	CreateEvidence(context.Context, domain.Actor, app.CreateEvidenceInput) (domain.EvidenceItem, error)
	ListEvidencePage(context.Context, domain.Actor, app.EvidencePageRequest) (appquery.Result[domain.EvidenceItem], error)
	SearchEvidencePage(context.Context, domain.Actor, app.EvidenceSearchPageRequest) (appquery.Result[domain.EvidenceItem], error)
	GetEvidence(context.Context, domain.Actor, string) (domain.EvidenceItem, error)
	SupersedeEvidence(context.Context, domain.Actor, string, string, string) (domain.EvidenceItem, error)
	LinkEvidence(context.Context, domain.Actor, string, string, string) (domain.EvidenceItem, error)
	RecordEvidenceLifecycleEvent(context.Context, domain.Actor, string, app.RecordEvidenceLifecycleInput) (domain.EvidenceLifecycleEvent, error)
	ListEvidenceLifecycleEvents(context.Context, domain.Actor, string) ([]domain.EvidenceLifecycleEvent, error)
	UploadSBOM(context.Context, domain.Actor, string, string, []byte) (domain.SBOM, error)
	UploadSBOMPayload(context.Context, domain.Actor, string, string, app.PayloadSource) (domain.SBOM, error)
	GetSBOM(context.Context, domain.Actor, string) (domain.SBOM, error)
	ListSBOMComponents(context.Context, domain.Actor, app.ListSBOMComponentsInput) ([]domain.SBOMComponentRecord, error)
	UploadVEX(context.Context, domain.Actor, string, string, []byte) (domain.VEXDocument, error)
	UploadVEXPayload(context.Context, domain.Actor, string, string, app.PayloadSource) (domain.VEXDocument, error)
	PreviewVEXImport(context.Context, domain.Actor, string, string, []byte) (domain.VEXImportPreview, error)
	GetVEXDocument(context.Context, domain.Actor, string) (domain.VEXDocument, error)
	GetVEXImportReport(context.Context, domain.Actor, string) (domain.VEXImportReport, error)
	UploadCycloneDXVEX(context.Context, domain.Actor, string, string, []byte) (domain.VEXDocument, error)
	PreviewCycloneDXVEXImport(context.Context, domain.Actor, string, string, []byte) (domain.VEXImportPreview, error)
	UploadVulnerabilityScanPayload(context.Context, domain.Actor, app.PayloadSource) (domain.VulnerabilityScan, error)
	GetVulnerabilityScan(context.Context, domain.Actor, string) (domain.VulnerabilityScan, error)
	UploadOpenAPIContract(context.Context, domain.Actor, string, string, string, []byte) (domain.OpenAPIContract, error)
	UploadOpenAPIContractPayload(context.Context, domain.Actor, string, string, string, app.PayloadSource) (domain.OpenAPIContract, error)
	GetOpenAPIContract(context.Context, domain.Actor, string) (domain.OpenAPIContract, error)
	CreateContractDiff(context.Context, domain.Actor, app.CreateContractDiffInput) (domain.ContractDiff, error)
}

// riskDecisionService is the transport boundary for append-only decisions,
// exceptions, waivers, approvals, and readiness evaluation.
type riskDecisionService interface {
	CreateWaiver(context.Context, domain.Actor, app.CreateWaiverInput) (domain.Waiver, error)
	ApproveWaiver(context.Context, domain.Actor, string) (domain.Waiver, error)
	CreateApprovalRecord(context.Context, domain.Actor, app.CreateApprovalInput) (domain.ApprovalRecord, error)
	CreateVulnerabilityDecision(context.Context, domain.Actor, string, app.CreateVulnerabilityDecisionInput) (domain.VulnerabilityDecision, error)
	ListVulnerabilityDecisions(context.Context, domain.Actor, app.ListVulnerabilityDecisionsInput) ([]domain.VulnerabilityDecision, error)
	VulnerabilityDecisionSummaryReport(context.Context, domain.Actor, string) (domain.VulnerabilityDecisionSummaryReport, error)
	EvaluateRelease(context.Context, domain.Actor, string) (domain.PolicyEvaluation, error)
	CreateException(context.Context, domain.Actor, app.CreateExceptionInput) (domain.Exception, error)
	ListExceptions(context.Context, domain.Actor, string) ([]domain.Exception, error)
	ApproveException(context.Context, domain.Actor, string) (domain.Exception, error)
}

// packageService contains the package generation, access, and read-only
// readiness-report operations migrated by EVY-904.
type packageService interface {
	CreateReleaseBundle(context.Context, domain.Actor, string) (domain.ReleaseBundle, error)
	CreateRedactionProfile(context.Context, domain.Actor, app.CreateRedactionProfileInput) (domain.RedactionProfile, error)
	CreateCustomerSecurityPackage(context.Context, domain.Actor, app.CreateCustomerPackageInput) (domain.CustomerSecurityPackage, error)
	AccessCustomerSecurityPackage(context.Context, domain.Actor, string) (domain.CustomerSecurityPackage, error)
	ExportEvidenceBundle(context.Context, domain.Actor, string, []string) (domain.EvidenceBundle, error)
	ImportEvidenceBundle(context.Context, domain.Actor, domain.EvidenceBundle) (domain.EvidenceBundleImport, error)
	CreateCustomReportTemplate(context.Context, domain.Actor, app.CreateReportTemplateInput) (domain.CustomReportTemplate, error)
	RenderCustomReport(context.Context, domain.Actor, app.RenderReportInput) (domain.RenderedCustomReport, error)
	CRAReadinessHTMLPackage(context.Context, domain.Actor, string, string) (domain.HTMLReportPackage, error)
	ReleaseReadinessReport(context.Context, domain.Actor, string) (domain.ReleaseReadinessReport, error)
}

// verificationService exposes provider-independent verification policy and
// signing-key administration without giving handlers unrelated Ledger methods.
type verificationService interface {
	VerifySubject(context.Context, domain.Actor, string, string) (domain.VerificationResult, error)
	VerifyCosignSignature(context.Context, domain.Actor, app.VerifyCosignInput) (domain.CosignVerification, error)
	VerifyDSSEAttestationSignature(context.Context, domain.Actor, string) (domain.VerificationResult, error)
	CreateDSSETrustRoot(context.Context, domain.Actor, app.CreateDSSETrustRootInput) (domain.DSSETrustRoot, error)
	CreateMerkleBatch(context.Context, domain.Actor, app.CreateMerkleBatchInput) (domain.MerkleBatch, error)
	VerifyMerkleBatch(context.Context, domain.Actor, string) (domain.VerificationResult, error)
	CreateTransparencyCheckpoint(context.Context, domain.Actor, app.CreateTransparencyCheckpointInput) (domain.TransparencyCheckpoint, error)
	CreateObjectRetentionPolicy(context.Context, domain.Actor, app.CreateObjectRetentionPolicyInput) (domain.ObjectRetentionPolicy, error)
	VerifyObjectRetentionPolicy(context.Context, domain.Actor, string) (domain.ObjectRetentionPolicy, error)
	SigningCustodyReviewReport(context.Context, domain.Actor) (domain.SigningCustodyReviewReport, error)
	GenerateBackupManifest(context.Context, domain.Actor) (domain.BackupManifest, error)
	VerifyBackupManifest(context.Context, domain.Actor, string) (domain.VerificationResult, error)
	ListSigningKeys(context.Context, domain.Actor) ([]domain.SigningKey, error)
	RotateSigningKey(context.Context, domain.Actor, string) (domain.SigningKey, error)
	RevokeSigningKeyWithPolicy(context.Context, domain.Actor, string, app.SigningKeyRevocationInput) (domain.SigningKey, error)
	CreateSigningProvider(context.Context, domain.Actor, app.CreateSigningProviderInput) (domain.SigningProvider, error)
}

var (
	_ Authenticator            = (*app.Ledger)(nil)
	_ idempotencyExecutor      = ledgerIdempotencyExecutor{}
	_ identityAccessService    = (*app.Ledger)(nil)
	_ releaseCatalogService    = (*app.Ledger)(nil)
	_ evidenceIngestionService = (*app.Ledger)(nil)
	_ riskDecisionService      = (*app.Ledger)(nil)
	_ packageService           = (*app.Ledger)(nil)
	_ verificationService      = (*app.Ledger)(nil)
)
