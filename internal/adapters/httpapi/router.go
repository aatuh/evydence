package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aatuh/api-toolkit/v3/httpx"
	"github.com/aatuh/api-toolkit/v3/idempotent"
	"github.com/aatuh/api-toolkit/v3/routecontracts"
	"github.com/aatuh/api-toolkit/v3/specs"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	application "github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identityquery "github.com/aatuh/evydence/internal/identity/query"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	"github.com/aatuh/evydence/internal/platform/jsonbounds"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasequery "github.com/aatuh/evydence/internal/release/query"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
	"github.com/aatuh/evydence/internal/runtimeinfo"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

type requestContext = context.Context

const requestIDHeader = "X-Request-ID"

type Server struct {
	ledger                            *app.Ledger
	authn                             Authenticator
	apiKeyCommands                    APIKeyCommands
	membershipCommands                MembershipCommands
	roleBindingCommands               RoleBindingCommands
	ssoProviderCommands               SSOProviderCommands
	ssoIdentityLinkCommands           SSOIdentityLinkCommands
	ssoSessionCommands                SSOSessionCommands
	ssoSessionRevocationCommands      SSOSessionRevocationCommands
	readinessQuery                    ReadinessQuery
	metricsQuery                      MetricsQuery
	retentionQuery                    RetentionQuery
	incidentReportQuery               IncidentReportQuery
	securityUpdateEvidenceQuery       SecurityUpdateEvidenceQuery
	craVulnerabilityQuery             CRAVulnerabilityQuery
	missingEvidenceQuery              MissingEvidenceQuery
	customerPackageAccessCommands     CustomerPackageAccessCommands
	customerPackageCreationCommands   CustomerPackageCreationCommands
	htmlReportCommands                HTMLReportCommands
	reportTemplateCommands            ReportTemplateCommands
	bundleImportCommand               BundleImportCommand
	releaseBundleCommands             ReleaseBundleCommands
	evidenceBundleCommands            EvidenceBundleCommands
	signingKeyCommands                SigningKeyCommands
	releaseBundleVerification         ReleaseBundleVerification
	evidenceVerification              EvidenceVerification
	dsseVerification                  DSSEVerification
	cosignVerification                CosignVerification
	artifactSignatureVerification     ArtifactSignatureVerification
	merkleVerification                MerkleVerification
	auditChainVerification            AuditChainVerification
	merkleCheckpointVerification      MerkleCheckpointVerification
	releaseManifestCheckpoint         ReleaseManifestCheckpoint
	backupVerification                BackupVerification
	backupGenerationCommands          BackupGenerationCommands
	artifactSignatureCommands         ArtifactSignatureCommands
	buildAttestationCommands          BuildAttestationCommands
	buildCommands                     BuildCommands
	containerImageCommands            ContainerImageCommands
	artifactCommands                  ArtifactCommands
	productCommands                   ProductCommands
	projectCommands                   ProjectCommands
	releaseCreationCommands           ReleaseCreationCommands
	releaseStateCommands              ReleaseStateCommands
	candidateStateCommands            CandidateStateCommands
	candidateCommands                 CandidateCommands
	controlCommands                   ControlCommands
	controlTemplateCommands           ControlTemplateCommands
	controlEvidenceCommands           ControlEvidenceCommands
	vulnerabilityDecisionCommands     VulnerabilityDecisionCommands
	approvalCommands                  ApprovalCommands
	waiverCommands                    WaiverCommands
	exceptionCommands                 ExceptionCommands
	vulnerabilityWorkflowCommands     VulnerabilityWorkflowCommands
	customPolicyCommands              CustomPolicyCommands
	policyEvaluationCommands          PolicyEvaluationCommands
	sbomDiffCommands                  SBOMDiffCommands
	contractDiffCommands              ContractDiffCommands
	durableCommandExecutor            DurableCommandExecutor
	evidenceCreationCommands          EvidenceCreationCommands
	openAPIIngestionCommands          OpenAPIIngestionCommands
	sbomIngestionCommands             SBOMIngestionCommands
	scanIngestionCommands             VulnerabilityScanIngestionCommands
	vexIngestionCommands              VEXIngestionCommands
	vexPreviewQuery                   VEXPreviewQuery
	securityDocumentCommands          SecurityDocumentCommands
	incidentCommands                  IncidentCommands
	incidentWebhookCommands           IncidentWebhookCommands
	collectorCommands                 CollectorCommands
	durableStreamedCommandExecutor    DurableStreamedCommandExecutor
	deploymentEnvironmentCommands     DeploymentEnvironmentCommands
	deploymentCommands                DeploymentCommands
	sourceRepositoryCommands          SourceRepositoryCommands
	sourceCommitCommands              SourceCommitCommands
	sourceBranchCommands              SourceBranchCommands
	pullRequestCommands               PullRequestCommands
	sourceSnapshotCommands            SourceSnapshotCommands
	subjectVerification               SubjectVerification
	transparencyCheckpointCommands    TransparencyCheckpointCommands
	merkleCreationCommands            MerkleCreationCommands
	signingCustodyQuery               SigningCustodyQuery
	retentionCommands                 RetentionCommands
	retentionMarkerCommands           RetentionMarkerCommands
	trustConfigurationCommands        TrustConfigurationCommands
	releaseReadinessReportQuery       ReleaseReadinessReportQuery
	releaseSecuritySummaryQuery       ReleaseSecuritySummaryQuery
	controlCoverageQuery              ControlCoverageQuery
	instanceAdminQuery                InstanceAdminQuery
	outboxDiagnosticsQuery            OutboxDiagnosticsQuery
	outboxReplayCommand               OutboxReplayCommand
	idempotency                       idempotencyExecutor
	identityAccess                    identityAccessService
	ssoExchangeCommands               SSOExchangeCommands
	providerVerificationCommands      ProviderVerificationCommands
	evidenceSummaryCommands           EvidenceSummaryCommands
	graphSnapshotCommands             GraphSnapshotCommands
	pdfReportCommands                 PDFReportCommands
	anomalyReportCommands             AnomalyReportCommands
	signingOperationCommands          SigningOperationCommands
	saasProfileCommands               SaaSProfileCommands
	marketplaceCollectorCommands      MarketplaceCollectorCommands
	publicTransparencyMetadata        PublicTransparencyMetadataCommands
	publicTransparencyProofs          PublicTransparencyProofCommands
	publicTransparencyFetch           PublicTransparencyFetchCommands
	questionnaireDraftCommands        QuestionnaireDraftCommands
	questionnairePackageCommands      QuestionnairePackageCommands
	portalAccessCommands              PortalAccessCommands
	portalTokenCommands               PortalTokenCommands
	questionnaireTemplateCommands     QuestionnaireTemplateCommands
	redactionProfileCommands          RedactionProfileCommands
	answerLibraryCommands             AnswerLibraryCommands
	releaseCatalog                    releaseCatalogService
	productQuery                      ProductQuery
	catalogPointQuery                 CatalogPointQuery
	evidenceFlowQuery                 EvidenceFlowQuery
	buildPointQuery                   BuildPointQuery
	artifactPointQuery                ArtifactPointQuery
	releaseCandidateQuery             ReleaseCandidateQuery
	deploymentPointQuery              DeploymentPointQuery
	deploymentListQuery               DeploymentListQuery
	evidencePointQuery                EvidencePointQuery
	lifecycleEventsQuery              LifecycleEventsQuery
	openAPIContractPointQuery         OpenAPIContractPointQuery
	sbomPointQuery                    SBOMPointQuery
	vulnerabilityScanPointQuery       VulnerabilityScanPointQuery
	vexPointQuery                     VEXPointQuery
	sbomComponentsQuery               SBOMComponentsQuery
	sourceRepositoryQuery             SourceRepositoryQuery
	collectorQuery                    CollectorQuery
	collectorHealthQuery              CollectorHealthQuery
	commercialCollectorQuery          CommercialCollectorQuery
	marketplaceCollectorQuery         MarketplaceCollectorQuery
	vulnerabilityPostureQuery         VulnerabilityPostureQuery
	controlsQuery                     ControlsQuery
	controlTemplateQuery              ControlTemplateQuery
	exceptionsQuery                   ExceptionsQuery
	vulnerabilityDecisionQuery        VulnerabilityDecisionQuery
	vulnerabilityDecisionSummaryQuery VulnerabilityDecisionSummaryQuery
	controlEvidenceQuery              ControlEvidenceQuery
	artifactSignatureQuery            ArtifactSignatureQuery
	signingKeyQuery                   SigningKeyQuery
	releaseBundleQuery                ReleaseBundleQuery
	answerLibraryQuery                AnswerLibraryQuery
	portalAccessQuery                 PortalAccessQuery
	auditLogQuery                     AuditLogQuery
	apiKeyQuery                       APIKeyQuery
	roleBindingQuery                  RoleBindingQuery
	evidenceIngestion                 evidenceIngestionService
	riskDecisions                     riskDecisionService
	packages                          packageService
	verification                      verificationService
	mux                               *http.ServeMux
	specs                             *specs.Registry
	routes                            *routecontracts.Registry
	ingress                           *ingressControl
	identity                          runtimeinfo.Identity
	cursors                           appquery.CursorCodec
}

type ServerOptions struct {
	// RateLimitRequestsPerMinute bounds unauthenticated and authenticated edge
	// traffic by client address. Forwarded addresses are used only when the
	// direct remote address belongs to TrustedProxyCIDRs.
	RateLimitRequestsPerMinute int
	// ExpensiveTenantRequestsPerMinute bounds storage, parsing, export, and
	// report-heavy POST operations per authenticated tenant and route.
	ExpensiveTenantRequestsPerMinute int
	RateLimitBucketCapacity          int
	TrustedProxyCIDRs                []string
	MaxURLBytes                      int
	MaxInboundRequestBytes           int64
	MaxInFlightRequests              int
	MaxConcurrentUploads             int
	BuildIdentity                    runtimeinfo.Identity
	// Authenticator overrides the local-memory Ledger authentication adapter.
	// Production binds it to current PostgreSQL credential and grant rows.
	Authenticator Authenticator
	// APIKeyCommands issues credentials without Ledger inventories or state.
	APIKeyCommands APIKeyCommands
	// MembershipCommands administers organizations/users without Ledger state.
	MembershipCommands MembershipCommands
	// RoleBindingCommands assigns current tenant-owned subjects/resources directly.
	RoleBindingCommands RoleBindingCommands
	// SSOProviderCommands registers providers without Ledger state or inventories.
	SSOProviderCommands SSOProviderCommands
	// SSOIdentityLinkCommands links current tenant-owned users/providers directly.
	SSOIdentityLinkCommands SSOIdentityLinkCommands
	// SSOSessionCommands issues admin-managed sessions without Ledger state.
	SSOSessionCommands SSOSessionCommands
	// SSOSessionRevocationCommands revokes/logout through locked durable metadata.
	SSOSessionRevocationCommands SSOSessionRevocationCommands
	// SSOExchangeCommands verifies public credentials and commits login directly.
	SSOExchangeCommands SSOExchangeCommands
	// ProviderVerificationCommands persists admin receipts without Ledger state.
	ProviderVerificationCommands ProviderVerificationCommands
	// EvidenceSummaryCommands creates bounded citation reports without Ledger state.
	EvidenceSummaryCommands EvidenceSummaryCommands
	// GraphSnapshotCommands materializes bounded committed adjacency without Ledger.
	GraphSnapshotCommands GraphSnapshotCommands
	// PDFReportCommands persists bounded PDF metadata without Ledger state.
	PDFReportCommands PDFReportCommands
	// AnomalyReportCommands persists bounded deterministic signals without Ledger.
	AnomalyReportCommands AnomalyReportCommands
	// SigningOperationCommands binds current provider receipts without Ledger.
	SigningOperationCommands SigningOperationCommands
	// SaaSProfileCommands records experimental deployment intent without Ledger.
	SaaSProfileCommands SaaSProfileCommands
	// MarketplaceCollectorCommands registers bounded metadata without Ledger.
	MarketplaceCollectorCommands MarketplaceCollectorCommands
	// PublicTransparencyMetadataCommands records log/publication metadata without Ledger.
	PublicTransparencyMetadataCommands PublicTransparencyMetadataCommands
	// PublicTransparencyProofCommands verifies operator-supplied proofs without Ledger.
	PublicTransparencyProofCommands PublicTransparencyProofCommands
	// PublicTransparencyFetchCommands fetches and verifies proofs without Ledger.
	PublicTransparencyFetchCommands PublicTransparencyFetchCommands
	// QuestionnaireDraftCommands selects authorized bounded answers without Ledger state.
	QuestionnaireDraftCommands QuestionnaireDraftCommands
	// QuestionnairePackageCommands generates bounded responses without Ledger state.
	QuestionnairePackageCommands QuestionnairePackageCommands
	// PortalAccessCommands issues and revokes scoped one-time tokens without Ledger.
	PortalAccessCommands PortalAccessCommands
	// PortalTokenCommands verifies and audits bounded package-token access.
	PortalTokenCommands PortalTokenCommands
	// QuestionnaireTemplateCommands creates bounded tenant definitions without Ledger.
	QuestionnaireTemplateCommands QuestionnaireTemplateCommands
	// RedactionProfileCommands creates tenant policy without Ledger state.
	RedactionProfileCommands RedactionProfileCommands
	// AnswerLibraryCommands creates scoped drafts without reading Ledger state.
	AnswerLibraryCommands AnswerLibraryCommands
	// ReadinessQuery probes production dependencies independently of Ledger state.
	ReadinessQuery ReadinessQuery
	// MetricsQuery supplies bounded tenant counters in the PostgreSQL profile.
	MetricsQuery MetricsQuery
	// RetentionQuery reads tenant-filtered legal holds and overrides from PostgreSQL.
	RetentionQuery RetentionQuery
	// IncidentReportQuery reads one tenant-owned incident and its scoped children.
	IncidentReportQuery IncidentReportQuery
	// SecurityUpdateEvidenceQuery reads bounded release-scoped report facts.
	SecurityUpdateEvidenceQuery SecurityUpdateEvidenceQuery
	// CRAVulnerabilityQuery reads report-safe vulnerability facts for one release.
	CRAVulnerabilityQuery CRAVulnerabilityQuery
	// MissingEvidenceQuery reads a committed release-readiness projection.
	MissingEvidenceQuery MissingEvidenceQuery
	// ReleaseReadinessReportQuery reads readiness and report facts in one view.
	ReleaseReadinessReportQuery ReleaseReadinessReportQuery
	// CustomerPackageAccessCommands reads and audits one durable package.
	CustomerPackageAccessCommands CustomerPackageAccessCommands
	// CustomerPackageCreationCommands freezes bounded durable public snapshots.
	CustomerPackageCreationCommands CustomerPackageCreationCommands
	// HTMLReportCommands uses bounded durable CRA facts and atomic report writes.
	HTMLReportCommands HTMLReportCommands
	// ReportTemplateCommands reads and persists templates and reports atomically.
	ReportTemplateCommands ReportTemplateCommands
	// BundleImportCommand atomically records validated manifest import receipts.
	BundleImportCommand BundleImportCommand
	// ReleaseBundleCommands generates signed bundles from committed durable facts.
	ReleaseBundleCommands ReleaseBundleCommands
	// EvidenceBundleCommands exports scoped references from committed durable facts.
	EvidenceBundleCommands EvidenceBundleCommands
	// SigningKeyCommands changes tenant-owned key lifecycle atomically.
	SigningKeyCommands SigningKeyCommands
	// ReleaseBundleVerification inspects durable bundle/public-key rows atomically.
	ReleaseBundleVerification ReleaseBundleVerification
	// EvidenceVerification hashes selected evidence in a durable transaction.
	EvidenceVerification EvidenceVerification
	// DSSEVerification inspects bounded finalized payloads and durable root policies.
	DSSEVerification DSSEVerification
	// CosignVerification binds durable artifact facts to offline configured trust.
	CosignVerification            CosignVerification
	ArtifactSignatureVerification ArtifactSignatureVerification
	MerkleVerification            MerkleVerification
	AuditChainVerification        AuditChainVerification
	MerkleCheckpointVerification  MerkleCheckpointVerification
	ReleaseManifestCheckpoint     ReleaseManifestCheckpoint
	BackupVerification            BackupVerification
	BackupGenerationCommands      BackupGenerationCommands
	ArtifactSignatureCommands     ArtifactSignatureCommands
	BuildAttestationCommands      BuildAttestationCommands
	BuildCommands                 BuildCommands
	ContainerImageCommands        ContainerImageCommands
	ArtifactCommands              ArtifactCommands
	ProductCommands               ProductCommands
	ProjectCommands               ProjectCommands
	ReleaseCreationCommands       ReleaseCreationCommands
	ReleaseStateCommands          ReleaseStateCommands
	CandidateStateCommands        CandidateStateCommands
	CandidateCommands             CandidateCommands
	ControlCommands               ControlCommands
	ControlTemplateCommands       ControlTemplateCommands
	ControlEvidenceCommands       ControlEvidenceCommands
	VulnerabilityDecisionCommands VulnerabilityDecisionCommands
	ApprovalCommands              ApprovalCommands
	WaiverCommands                WaiverCommands
	ExceptionCommands             ExceptionCommands
	VulnerabilityWorkflowCommands VulnerabilityWorkflowCommands
	CustomPolicyCommands          CustomPolicyCommands
	PolicyEvaluationCommands      PolicyEvaluationCommands
	SBOMDiffCommands              SBOMDiffCommands
	ContractDiffCommands          ContractDiffCommands
	DurableCommandExecutor        DurableCommandExecutor
	EvidenceCreationCommands      EvidenceCreationCommands
	OpenAPIIngestionCommands      OpenAPIIngestionCommands
	SBOMIngestionCommands         SBOMIngestionCommands
	ScanIngestionCommands         VulnerabilityScanIngestionCommands
	VEXIngestionCommands          VEXIngestionCommands
	VEXPreviewQuery               VEXPreviewQuery
	SecurityDocumentCommands      SecurityDocumentCommands
	IncidentCommands              IncidentCommands
	IncidentWebhookCommands       IncidentWebhookCommands
	CollectorCommands             CollectorCommands
	DeploymentEnvironmentCommands DeploymentEnvironmentCommands
	DeploymentCommands            DeploymentCommands
	SourceRepositoryCommands      SourceRepositoryCommands
	SourceCommitCommands          SourceCommitCommands
	SourceBranchCommands          SourceBranchCommands
	PullRequestCommands           PullRequestCommands
	SourceSnapshotCommands        SourceSnapshotCommands
	// SubjectVerification dispatches every generic subject without Ledger fallback.
	SubjectVerification            SubjectVerification
	TransparencyCheckpointCommands TransparencyCheckpointCommands
	MerkleCreationCommands         MerkleCreationCommands
	// SigningCustodyQuery assesses one bounded committed provider/policy inventory.
	SigningCustodyQuery SigningCustodyQuery
	// RetentionCommands atomically persists durable retention intent and observations.
	RetentionCommands RetentionCommands
	// RetentionMarkerCommands appends Operations-owned holds and extensions
	// through native durable replay, without a Ledger command clone.
	RetentionMarkerCommands RetentionMarkerCommands
	// TrustConfigurationCommands creates tenant-owned provider metadata and public
	// trust roots. It requires DurableCommandExecutor, never Ledger replay.
	TrustConfigurationCommands TrustConfigurationCommands
	// ReleaseSecuritySummaryQuery reads one committed report snapshot.
	ReleaseSecuritySummaryQuery ReleaseSecuritySummaryQuery
	// ControlCoverageQuery reads bounded tenant-owned control and CRA reports.
	ControlCoverageQuery ControlCoverageQuery
	// InstanceAdminQuery reads global operational counts without loading Ledger state.
	InstanceAdminQuery InstanceAdminQuery
	// OutboxDiagnosticsQuery reads global queue counts after instance-admin authorization.
	OutboxDiagnosticsQuery OutboxDiagnosticsQuery
	// OutboxReplayCommand atomically requeues terminal jobs and completes replay records.
	OutboxReplayCommand OutboxReplayCommand
	// PaginationSecret authenticates opaque cursor tokens. Production callers
	// should supply a stable, non-public secret so tokens survive restarts.
	PaginationSecret []byte
	// ProductQuery enables bounded PostgreSQL-backed catalog reads.
	// Local-memory servers retain the legacy in-process query path.
	ProductQuery ProductQuery
	// CatalogPointQuery enables tenant-filtered PostgreSQL project/release
	// reads. Local-memory servers use the compatibility service instead.
	CatalogPointQuery CatalogPointQuery
	// EvidenceFlowQuery reads one release's workflow counts from durable state.
	EvidenceFlowQuery EvidenceFlowQuery
	// BuildPointQuery reads current build and parent coordinates in PostgreSQL.
	BuildPointQuery BuildPointQuery
	// ArtifactPointQuery reads a tenant-owned artifact and current grant visibility.
	ArtifactPointQuery ArtifactPointQuery
	// ReleaseCandidateQuery reads candidate points and pages from PostgreSQL.
	ReleaseCandidateQuery ReleaseCandidateQuery
	// DeploymentPointQuery reads one tenant-owned deployment and parent projection.
	DeploymentPointQuery DeploymentPointQuery
	// DeploymentListQuery pages environments and events with SQL-side grants.
	DeploymentListQuery DeploymentListQuery
	// EvidencePointQuery reads ordinary evidence from tenant-scoped PostgreSQL.
	EvidencePointQuery EvidencePointQuery
	// LifecycleEventsQuery pages ordinary evidence events from PostgreSQL.
	LifecycleEventsQuery LifecycleEventsQuery
	// OpenAPIContractPointQuery reads current tenant-verified parsed contracts.
	OpenAPIContractPointQuery OpenAPIContractPointQuery
	// SBOMPointQuery reads one tenant-verified parsed SBOM.
	SBOMPointQuery SBOMPointQuery
	// VulnerabilityScanPointQuery reads one tenant-verified parsed scan.
	VulnerabilityScanPointQuery VulnerabilityScanPointQuery
	// VEXPointQuery reads one document or import report from current storage.
	VEXPointQuery VEXPointQuery
	// SBOMComponentsQuery pages components against current tenant and grants.
	SBOMComponentsQuery SBOMComponentsQuery
	// SourceRepositoryQuery pages current tenant-owned source repositories.
	SourceRepositoryQuery SourceRepositoryQuery
	// CollectorQuery pages durable collector inventory for the PostgreSQL profile.
	CollectorQuery CollectorQuery
	// CollectorHealthQuery reads a bounded durable health point.
	CollectorHealthQuery CollectorHealthQuery
	// CommercialCollectorQuery pages tenant-owned integration definitions.
	CommercialCollectorQuery CommercialCollectorQuery
	// MarketplaceCollectorQuery reads tenant-owned marketplace metadata and health.
	MarketplaceCollectorQuery MarketplaceCollectorQuery
	// VulnerabilityPostureQuery reports tenant/release-scoped scan aggregates.
	VulnerabilityPostureQuery VulnerabilityPostureQuery
	// ControlsQuery reads framework pages and tenant-owned control points.
	ControlsQuery ControlsQuery
	// ControlTemplateQuery reads static starter definitions from the risk context.
	ControlTemplateQuery ControlTemplateQuery
	// ExceptionsQuery pages current tenant-owned exceptions before HTTP encoding.
	ExceptionsQuery ExceptionsQuery
	// VulnerabilityDecisionQuery pages durable decisions after tenant and grant filtering.
	VulnerabilityDecisionQuery VulnerabilityDecisionQuery
	// VulnerabilityDecisionSummaryQuery reads a scoped customer-safe report.
	VulnerabilityDecisionSummaryQuery VulnerabilityDecisionSummaryQuery
	// ControlEvidenceQuery pages links from current subject ownership.
	ControlEvidenceQuery ControlEvidenceQuery
	// ArtifactSignatureQuery reads tenant-owned signature points from PostgreSQL.
	ArtifactSignatureQuery ArtifactSignatureQuery
	// SigningKeyQuery pages public lifecycle metadata from PostgreSQL.
	SigningKeyQuery SigningKeyQuery
	// ReleaseBundleQuery reads tenant-owned bundle points from PostgreSQL.
	ReleaseBundleQuery ReleaseBundleQuery
	// AnswerLibraryQuery pages authorized questionnaire drafts from PostgreSQL.
	AnswerLibraryQuery AnswerLibraryQuery
	// PortalAccessQuery pages grant-visible package access metadata.
	PortalAccessQuery PortalAccessQuery
	// AuditLogQuery pages tenant audit records in PostgreSQL for the durable profile.
	AuditLogQuery AuditLogQuery
	// APIKeyQuery pages public key metadata in PostgreSQL for the durable profile.
	APIKeyQuery APIKeyQuery
	// RoleBindingQuery pages current tenant bindings in PostgreSQL for the durable profile.
	RoleBindingQuery RoleBindingQuery
}

func NewServer(ledger *app.Ledger) (*Server, error) {
	return NewServerWithOptionsContext(context.Background(), ledger, ServerOptions{})
}

func NewServerWithOptions(ledger *app.Ledger, opts ServerOptions) (*Server, error) {
	return NewServerWithOptionsContext(context.Background(), ledger, opts)
}

func NewServerWithOptionsContext(ctx context.Context, ledger *app.Ledger, opts ServerOptions) (*Server, error) {
	if ctx == nil {
		return nil, errors.New("server context is required")
	}
	if opts.APIKeyCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused API keys require durable idempotency")
	}
	if opts.MembershipCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused membership requires durable idempotency")
	}
	if opts.RoleBindingCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused role bindings require durable idempotency")
	}
	if opts.SSOProviderCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused SSO providers require durable idempotency")
	}
	if opts.SSOIdentityLinkCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused SSO identity links require durable idempotency")
	}
	if opts.SSOSessionCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused SSO sessions require durable idempotency")
	}
	if opts.SSOSessionRevocationCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused SSO revocation requires durable idempotency")
	}
	if opts.ProviderVerificationCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused provider verification requires durable idempotency")
	}
	if opts.EvidenceSummaryCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused evidence summaries require durable idempotency")
	}
	if opts.GraphSnapshotCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused graph snapshots require durable idempotency")
	}
	if opts.PDFReportCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused PDF reports require durable idempotency")
	}
	if opts.AnomalyReportCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused anomaly reports require durable idempotency")
	}
	if opts.SigningOperationCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused signing operations require durable idempotency")
	}
	if opts.TrustConfigurationCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused trust configuration requires durable idempotency")
	}
	if opts.SigningKeyCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused signing keys require durable idempotency")
	}
	if opts.MerkleCreationCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused Merkle creation requires durable idempotency")
	}
	if opts.TransparencyCheckpointCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused checkpoints require durable idempotency")
	}
	if opts.BackupGenerationCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused backup generation requires durable idempotency")
	}
	if opts.CosignVerification != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused Cosign verification requires durable idempotency")
	}
	if opts.DSSEVerification != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused DSSE verification requires durable idempotency")
	}
	if opts.SubjectVerification != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused generic verification requires durable idempotency")
	}
	if opts.ArtifactSignatureCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused artifact signature creation requires durable idempotency")
	}
	if opts.ControlTemplateCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused control template installation requires durable idempotency")
	}
	if opts.ControlCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused control creation requires durable idempotency")
	}
	if opts.ControlEvidenceCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused control evidence linking requires durable idempotency")
	}
	if opts.SourceRepositoryCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused source repository creation requires durable idempotency")
	}
	if (opts.SourceCommitCommands != nil || opts.SourceBranchCommands != nil || opts.PullRequestCommands != nil) && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused source writes require durable idempotency")
	}
	if opts.SourceSnapshotCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused source snapshots require durable idempotency")
	}
	if opts.BuildCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused build creation requires durable idempotency")
	}
	if opts.RetentionCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused retention requires durable idempotency")
	}
	if opts.RetentionMarkerCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused retention markers require durable idempotency")
	}
	if opts.ReleaseBundleCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused release bundles require durable idempotency")
	}
	if opts.SaaSProfileCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused SaaS profiles require durable idempotency")
	}
	if opts.MarketplaceCollectorCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused marketplace collectors require durable idempotency")
	}
	if opts.PublicTransparencyMetadataCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused public transparency metadata requires durable idempotency")
	}
	if opts.PublicTransparencyProofCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused public transparency proofs require durable idempotency")
	}
	if opts.PublicTransparencyFetchCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused public transparency fetching requires durable idempotency")
	}
	if opts.QuestionnaireDraftCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused questionnaire drafts require durable idempotency")
	}
	if opts.QuestionnairePackageCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused questionnaire packages require durable idempotency")
	}
	if opts.PortalAccessCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused portal writes require durable idempotency")
	}
	if opts.QuestionnaireTemplateCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused questionnaire templates require durable idempotency")
	}
	if opts.RedactionProfileCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused redaction profiles require durable idempotency")
	}
	if opts.CustomerPackageCreationCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused customer packages require durable idempotency")
	}
	if opts.AnswerLibraryCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused answer library requires durable idempotency")
	}
	if opts.CollectorCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused collectors require durable idempotency")
	}
	if (opts.IncidentCommands != nil || opts.IncidentWebhookCommands != nil) && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused incidents require durable idempotency")
	}
	if opts.SecurityDocumentCommands != nil && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused security documents require durable idempotency")
	}
	if opts.OpenAPIIngestionCommands != nil || opts.SBOMIngestionCommands != nil || opts.ScanIngestionCommands != nil || opts.VEXIngestionCommands != nil {
		if _, ok := opts.DurableCommandExecutor.(DurableStreamedCommandExecutor); !ok {
			return nil, errors.New("focused document ingestion requires durable streamed idempotency")
		}
	}
	if (opts.VulnerabilityDecisionCommands != nil || opts.ApprovalCommands != nil || opts.WaiverCommands != nil || opts.ExceptionCommands != nil || opts.VulnerabilityWorkflowCommands != nil || opts.CustomPolicyCommands != nil || opts.PolicyEvaluationCommands != nil || opts.SBOMDiffCommands != nil || opts.ContractDiffCommands != nil) && opts.DurableCommandExecutor == nil {
		return nil, errors.New("focused commands require durable idempotency")
	}
	if ledger == nil {
		var err error
		ledger, err = app.NewLedgerWithContext(ctx, app.Config{})
		if err != nil {
			return nil, err
		}
	}
	mux := http.NewServeMux()
	specRegistry := NewSpecRegistry()
	router := &serveMuxRouter{mux: mux}
	routeRegistry := routecontracts.NewRegistry(router, specRegistry)
	identity := opts.BuildIdentity
	if identity.IsZero() {
		identity = runtimeinfo.Current()
	}
	paginationSecret := opts.PaginationSecret
	if len(paginationSecret) == 0 {
		paginationSecret = make([]byte, 32)
		if _, err := rand.Read(paginationSecret); err != nil {
			return nil, err
		}
	}
	cursors, err := appquery.NewCursorCodec(paginationSecret)
	if err != nil {
		return nil, err
	}
	ingress, err := newIngressControl(opts)
	if err != nil {
		return nil, err
	}
	server := &Server{mux: mux, specs: specRegistry, routes: routeRegistry, ingress: ingress, identity: identity, cursors: cursors, readinessQuery: opts.ReadinessQuery, metricsQuery: opts.MetricsQuery, retentionQuery: opts.RetentionQuery, incidentReportQuery: opts.IncidentReportQuery, securityUpdateEvidenceQuery: opts.SecurityUpdateEvidenceQuery, craVulnerabilityQuery: opts.CRAVulnerabilityQuery, controlCoverageQuery: opts.ControlCoverageQuery, instanceAdminQuery: opts.InstanceAdminQuery, outboxDiagnosticsQuery: opts.OutboxDiagnosticsQuery, outboxReplayCommand: opts.OutboxReplayCommand, productQuery: opts.ProductQuery, catalogPointQuery: opts.CatalogPointQuery, evidenceFlowQuery: opts.EvidenceFlowQuery, buildPointQuery: opts.BuildPointQuery, artifactPointQuery: opts.ArtifactPointQuery, releaseCandidateQuery: opts.ReleaseCandidateQuery, deploymentPointQuery: opts.DeploymentPointQuery, deploymentListQuery: opts.DeploymentListQuery, evidencePointQuery: opts.EvidencePointQuery, lifecycleEventsQuery: opts.LifecycleEventsQuery, openAPIContractPointQuery: opts.OpenAPIContractPointQuery, sbomPointQuery: opts.SBOMPointQuery, vulnerabilityScanPointQuery: opts.VulnerabilityScanPointQuery, vexPointQuery: opts.VEXPointQuery, sbomComponentsQuery: opts.SBOMComponentsQuery, sourceRepositoryQuery: opts.SourceRepositoryQuery, collectorQuery: opts.CollectorQuery, collectorHealthQuery: opts.CollectorHealthQuery, commercialCollectorQuery: opts.CommercialCollectorQuery, marketplaceCollectorQuery: opts.MarketplaceCollectorQuery, vulnerabilityPostureQuery: opts.VulnerabilityPostureQuery, controlsQuery: opts.ControlsQuery, controlTemplateQuery: opts.ControlTemplateQuery, exceptionsQuery: opts.ExceptionsQuery, vulnerabilityDecisionQuery: opts.VulnerabilityDecisionQuery, controlEvidenceQuery: opts.ControlEvidenceQuery, artifactSignatureQuery: opts.ArtifactSignatureQuery, signingKeyQuery: opts.SigningKeyQuery, releaseBundleQuery: opts.ReleaseBundleQuery, answerLibraryQuery: opts.AnswerLibraryQuery, portalAccessQuery: opts.PortalAccessQuery, auditLogQuery: opts.AuditLogQuery, apiKeyQuery: opts.APIKeyQuery, roleBindingQuery: opts.RoleBindingQuery}
	server.vulnerabilityDecisionSummaryQuery = opts.VulnerabilityDecisionSummaryQuery
	server.missingEvidenceQuery = opts.MissingEvidenceQuery
	server.releaseReadinessReportQuery = opts.ReleaseReadinessReportQuery
	server.customerPackageAccessCommands = opts.CustomerPackageAccessCommands
	server.customerPackageCreationCommands = opts.CustomerPackageCreationCommands
	server.htmlReportCommands = opts.HTMLReportCommands
	server.reportTemplateCommands = opts.ReportTemplateCommands
	server.bundleImportCommand = opts.BundleImportCommand
	server.releaseBundleCommands = opts.ReleaseBundleCommands
	server.evidenceBundleCommands = opts.EvidenceBundleCommands
	server.signingKeyCommands = opts.SigningKeyCommands
	server.releaseBundleVerification = opts.ReleaseBundleVerification
	server.evidenceVerification = opts.EvidenceVerification
	server.dsseVerification = opts.DSSEVerification
	server.cosignVerification = opts.CosignVerification
	server.artifactSignatureVerification = opts.ArtifactSignatureVerification
	server.merkleVerification = opts.MerkleVerification
	server.auditChainVerification = opts.AuditChainVerification
	server.merkleCheckpointVerification = opts.MerkleCheckpointVerification
	server.releaseManifestCheckpoint = opts.ReleaseManifestCheckpoint
	server.backupVerification = opts.BackupVerification
	server.backupGenerationCommands = opts.BackupGenerationCommands
	server.artifactSignatureCommands = opts.ArtifactSignatureCommands
	server.buildAttestationCommands = opts.BuildAttestationCommands
	server.buildCommands = opts.BuildCommands
	server.containerImageCommands = opts.ContainerImageCommands
	server.artifactCommands = opts.ArtifactCommands
	server.productCommands = opts.ProductCommands
	server.projectCommands = opts.ProjectCommands
	server.releaseCreationCommands = opts.ReleaseCreationCommands
	server.releaseStateCommands = opts.ReleaseStateCommands
	server.candidateStateCommands = opts.CandidateStateCommands
	server.candidateCommands = opts.CandidateCommands
	server.controlCommands = opts.ControlCommands
	server.controlTemplateCommands = opts.ControlTemplateCommands
	server.controlEvidenceCommands = opts.ControlEvidenceCommands
	server.vulnerabilityDecisionCommands = opts.VulnerabilityDecisionCommands
	server.approvalCommands = opts.ApprovalCommands
	server.waiverCommands = opts.WaiverCommands
	server.exceptionCommands = opts.ExceptionCommands
	server.vulnerabilityWorkflowCommands = opts.VulnerabilityWorkflowCommands
	server.customPolicyCommands = opts.CustomPolicyCommands
	server.policyEvaluationCommands = opts.PolicyEvaluationCommands
	server.sbomDiffCommands = opts.SBOMDiffCommands
	server.contractDiffCommands = opts.ContractDiffCommands
	server.durableCommandExecutor = opts.DurableCommandExecutor
	server.evidenceCreationCommands = opts.EvidenceCreationCommands
	server.openAPIIngestionCommands = opts.OpenAPIIngestionCommands
	server.sbomIngestionCommands = opts.SBOMIngestionCommands
	server.scanIngestionCommands = opts.ScanIngestionCommands
	server.vexIngestionCommands = opts.VEXIngestionCommands
	server.vexPreviewQuery = opts.VEXPreviewQuery
	server.securityDocumentCommands = opts.SecurityDocumentCommands
	server.incidentCommands = opts.IncidentCommands
	server.incidentWebhookCommands = opts.IncidentWebhookCommands
	server.collectorCommands = opts.CollectorCommands
	server.apiKeyCommands = opts.APIKeyCommands
	server.membershipCommands = opts.MembershipCommands
	server.roleBindingCommands = opts.RoleBindingCommands
	server.ssoProviderCommands = opts.SSOProviderCommands
	server.ssoIdentityLinkCommands = opts.SSOIdentityLinkCommands
	server.ssoSessionCommands = opts.SSOSessionCommands
	server.ssoSessionRevocationCommands = opts.SSOSessionRevocationCommands
	server.ssoExchangeCommands = opts.SSOExchangeCommands
	server.providerVerificationCommands = opts.ProviderVerificationCommands
	server.evidenceSummaryCommands = opts.EvidenceSummaryCommands
	server.graphSnapshotCommands = opts.GraphSnapshotCommands
	server.pdfReportCommands = opts.PDFReportCommands
	server.anomalyReportCommands = opts.AnomalyReportCommands
	server.signingOperationCommands = opts.SigningOperationCommands
	server.saasProfileCommands = opts.SaaSProfileCommands
	server.marketplaceCollectorCommands = opts.MarketplaceCollectorCommands
	server.publicTransparencyMetadata = opts.PublicTransparencyMetadataCommands
	server.publicTransparencyProofs = opts.PublicTransparencyProofCommands
	server.publicTransparencyFetch = opts.PublicTransparencyFetchCommands
	server.questionnaireDraftCommands = opts.QuestionnaireDraftCommands
	server.questionnairePackageCommands = opts.QuestionnairePackageCommands
	server.portalAccessCommands = opts.PortalAccessCommands
	server.portalTokenCommands = opts.PortalTokenCommands
	server.questionnaireTemplateCommands = opts.QuestionnaireTemplateCommands
	server.redactionProfileCommands = opts.RedactionProfileCommands
	server.answerLibraryCommands = opts.AnswerLibraryCommands
	server.durableStreamedCommandExecutor, _ = opts.DurableCommandExecutor.(DurableStreamedCommandExecutor)
	server.deploymentEnvironmentCommands = opts.DeploymentEnvironmentCommands
	server.deploymentCommands = opts.DeploymentCommands
	server.sourceRepositoryCommands = opts.SourceRepositoryCommands
	server.sourceCommitCommands = opts.SourceCommitCommands
	server.sourceBranchCommands = opts.SourceBranchCommands
	server.pullRequestCommands = opts.PullRequestCommands
	server.sourceSnapshotCommands = opts.SourceSnapshotCommands
	server.subjectVerification = opts.SubjectVerification
	server.transparencyCheckpointCommands = opts.TransparencyCheckpointCommands
	server.merkleCreationCommands = opts.MerkleCreationCommands
	server.signingCustodyQuery = opts.SigningCustodyQuery
	server.retentionCommands = opts.RetentionCommands
	server.retentionMarkerCommands = opts.RetentionMarkerCommands
	server.trustConfigurationCommands = opts.TrustConfigurationCommands
	server.releaseSecuritySummaryQuery = opts.ReleaseSecuritySummaryQuery
	server.bindLedger(ledger)
	if opts.Authenticator != nil {
		server.authn = opts.Authenticator
	}
	if err := server.registerRoutes(); err != nil {
		return nil, err
	}
	return server, nil
}

// bindLedger updates both the shrinking compatibility facade and every
// context-specific transport dependency. Idempotent commands must bind the
// isolated command ledger so domain changes and the replay record share the
// same transaction and are published only after commit.
func (s *Server) bindLedger(ledger *app.Ledger) {
	s.ledger = ledger
	s.authn = ledger
	s.idempotency = ledgerIdempotencyExecutor{ledger: ledger}
	s.identityAccess = ledger
	s.releaseCatalog = ledger
	s.evidenceIngestion = ledger
	s.riskDecisions = ledger
	s.packages = ledger
	s.verification = ledger
}

func (s *Server) Handler() http.Handler {
	return secureHeaders(requestIDMiddleware(s.inFlightMiddleware(s.ingressValidationMiddleware(s.rateLimitMiddleware(s.uploadConcurrencyMiddleware(s.conditionalReadMiddleware(s.mux)))))))
}

func (s *Server) OpenAPI() ([]byte, error) {
	return s.specs.OpenAPI()
}

func (s *Server) ValidateRoutes() error {
	return s.routes.Validate()
}

func (s *Server) createCollector(w http.ResponseWriter, r *http.Request) {
	if s.collectorCommands != nil {
		s.createDurableCollector(w, r)
		return
	}
	var req struct {
		Name    string   `json:"name"`
		Type    string   `json:"type"`
		Version string   `json:"version"`
		Scopes  []string `json:"scopes"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		collector, key, secret, err := s.ledger.CreateCollector(ctx, actor, app.CreateCollectorInput{
			Name:    req.Name,
			Type:    req.Type,
			Version: req.Version,
			Scopes:  req.Scopes,
		})
		return http.StatusCreated, map[string]any{"collector": collector, "api_key": key, "secret": secret}, err
	})
}

func (s *Server) listCollectors(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.collectorQuery != nil {
		request, err := s.parsePageRequest(r, actor, "collectors")
		if err != nil {
			writeProblem(w, r, err)
			return
		}
		page, err := s.collectorQuery.ListPage(r.Context(), actor, appquery.PageRequest{PageSize: request.pageSize, Sort: request.sort, Direction: request.direction}, request.after)
		if err != nil {
			writeProblem(w, r, mapIntegrationQueryError(err))
			return
		}
		mapped := appquery.Result[domain.Collector]{Next: page.Next, Items: make([]domain.Collector, 0, len(page.Items))}
		for _, collector := range page.Items {
			mapped.Items = append(mapped.Items, collectorFromQuery(collector))
		}
		writePage(s, w, r, actor, "collectors", request, mapped)
		return
	}
	collectors, err := s.ledger.ListCollectors(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "collectors", nil, collectors, func(collector domain.Collector) (string, time.Time) {
		return collector.ID, collector.CreatedAt
	})
}

func (s *Server) recordCollectorRelease(w http.ResponseWriter, r *http.Request) {
	if s.collectorCommands != nil {
		s.recordDurableCollectorRelease(w, r)
		return
	}
	var req struct {
		Version        string `json:"version"`
		ArtifactDigest string `json:"artifact_digest"`
		SignatureID    string `json:"signature_id"`
		SBOMID         string `json:"sbom_id"`
		ScanID         string `json:"scan_id"`
		Pinned         bool   `json:"pinned"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		release, err := s.ledger.RecordCollectorRelease(ctx, actor, app.RecordCollectorReleaseInput{
			CollectorID:    r.PathValue("id"),
			Version:        req.Version,
			ArtifactDigest: req.ArtifactDigest,
			SignatureID:    req.SignatureID,
			SBOMID:         req.SBOMID,
			ScanID:         req.ScanID,
			Pinned:         req.Pinned,
		})
		return http.StatusCreated, release, err
	})
}

func (s *Server) collectorHealthReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.collectorHealthQuery != nil {
		report, err := s.collectorHealthQuery.Report(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			writeProblem(w, r, mapIntegrationQueryError(err))
			return
		}
		writeData(w, http.StatusOK, collectorHealthFromQuery(report))
		return
	}
	report, err := s.ledger.CollectorHealthReport(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) listControlFrameworks(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.controlsQuery != nil {
		request, err := s.parsePageRequest(r, actor, "control-frameworks")
		if err != nil {
			writeProblem(w, r, err)
			return
		}
		page, err := s.controlsQuery.ListFrameworksPage(r.Context(), actor, appquery.PageRequest{PageSize: request.pageSize, Sort: request.sort, Direction: request.direction}, request.after)
		if err != nil {
			writeProblem(w, r, mapControlsQueryError(err))
			return
		}
		mapped := appquery.Result[domain.ControlFramework]{Next: page.Next, Items: make([]domain.ControlFramework, 0, len(page.Items))}
		for _, framework := range page.Items {
			mapped.Items = append(mapped.Items, controlFrameworkFromQuery(framework))
		}
		writePage(s, w, r, actor, "control-frameworks", request, mapped)
		return
	}
	frameworks, err := s.ledger.ListControlFrameworks(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "control-frameworks", nil, frameworks, func(framework domain.ControlFramework) (string, time.Time) {
		return framework.ID, framework.CreatedAt
	})
}

func (s *Server) listControlFrameworkTemplatePacks(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.controlTemplateQuery != nil {
		if _, err := s.parsePageRequest(r, actor, "control-framework-template-packs"); err != nil {
			writeProblem(w, r, err)
			return
		}
		packs, err := s.controlTemplateQuery.ListTemplatePacks(r.Context(), actor)
		if err != nil {
			writeProblem(w, r, mapControlsQueryError(err))
			return
		}
		mapped := make([]domain.ControlFrameworkTemplatePack, 0, len(packs))
		for _, pack := range packs {
			mapped = append(mapped, controlTemplatePackFromQuery(pack))
		}
		writePaginated(s, w, r, actor, "control-framework-template-packs", nil, mapped, func(pack domain.ControlFrameworkTemplatePack, sort appquery.Sort) appquery.SortKey {
			return appquery.RecordSortKey(pack.ID, time.Time{}, sort)
		})
		return
	}
	packs, err := s.ledger.ListControlFrameworkTemplatePacks(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writePaginated(s, w, r, actor, "control-framework-template-packs", nil, packs, func(pack domain.ControlFrameworkTemplatePack, sort appquery.Sort) appquery.SortKey {
		return appquery.RecordSortKey(pack.ID, time.Time{}, sort)
	})
}

func (s *Server) getSecurityControl(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.controlsQuery != nil {
		control, err := s.controlsQuery.GetSecurityControl(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			writeProblem(w, r, mapControlsQueryError(err))
			return
		}
		writeData(w, http.StatusOK, securityControlFromQuery(control))
		return
	}
	control, err := s.ledger.GetSecurityControl(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, control)
}

func (s *Server) listControlEvidence(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.controlEvidenceQuery != nil {
		request, err := s.parsePageRequest(r, actor, "control-evidence", "control_id", "product_id", "release_id")
		if err != nil {
			writeProblem(w, r, err)
			return
		}
		filter := riskquery.ControlEvidenceFilter{ControlID: r.URL.Query().Get("control_id"), ProductID: r.URL.Query().Get("product_id"), ReleaseID: r.URL.Query().Get("release_id")}
		result, err := s.controlEvidenceQuery.ListPage(r.Context(), actor, filter, appquery.PageRequest{PageSize: request.pageSize, Sort: request.sort, Direction: request.direction}, request.after)
		if err != nil {
			writeProblem(w, r, mapControlsQueryError(err))
			return
		}
		page := appquery.Result[domain.ControlEvidence]{Next: result.Next, Items: make([]domain.ControlEvidence, 0, len(result.Items))}
		for _, link := range result.Items {
			page.Items = append(page.Items, controlEvidenceFromQuery(link))
		}
		writePage(s, w, r, actor, "control-evidence", request, page)
		return
	}
	links, err := s.ledger.ListControlEvidence(r.Context(), actor, r.URL.Query().Get("control_id"), r.URL.Query().Get("product_id"), r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "control-evidence", []string{"control_id", "product_id", "release_id"}, links, func(link domain.ControlEvidence) (string, time.Time) {
		return link.ID, link.CreatedAt
	})
}

func (s *Server) createProduct(w http.ResponseWriter, r *http.Request) {
	var req struct{ Name, Slug string }
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		if s.productCommands != nil {
			product, err := s.productCommands.CreateProduct(ctx, actor, releaseapp.CreateProductInput{Name: req.Name, Slug: req.Slug})
			return http.StatusCreated, productFromCommand(product), mapBuildAttestationCommandError(err)
		}
		product, err := s.releaseCatalog.CreateProduct(ctx, actor, req.Name, req.Slug)
		return http.StatusCreated, product, err
	})
}

func (s *Server) listProducts(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.productQuery != nil {
		request, err := s.parsePageRequest(r, actor, "products")
		if err != nil {
			writeProblem(w, r, err)
			return
		}
		page, err := s.productQuery.ListProductsPage(r.Context(), actor, appquery.PageRequest{PageSize: request.pageSize, Sort: request.sort, Direction: request.direction}, request.after)
		if err != nil {
			switch {
			case errors.Is(err, releasequery.ErrValidation), errors.Is(err, appquery.ErrInvalidPage), errors.Is(err, appquery.ErrInvalidCursor):
				err = app.ErrValidation
			case errors.Is(err, application.ErrUnauthorized):
				err = app.ErrUnauthorized
			case errors.Is(err, application.ErrForbidden):
				err = app.ErrForbidden
			}
			writeProblem(w, r, err)
			return
		}
		mapped := appquery.Result[domain.Product]{Next: page.Next, Items: make([]domain.Product, 0, len(page.Items))}
		for _, product := range page.Items {
			mapped.Items = append(mapped.Items, domain.Product{ID: product.ID, TenantID: product.TenantID, Name: product.Name, Slug: product.Slug, CreatedAt: product.CreatedAt})
		}
		writePage(s, w, r, actor, "products", request, mapped)
		return
	}
	products, err := s.releaseCatalog.ListProducts(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "products", nil, products, func(product domain.Product) (string, time.Time) {
		return product.ID, product.CreatedAt
	})
}

func (s *Server) getProduct(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.productQuery != nil {
		product, err := s.productQuery.GetProduct(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			switch {
			case errors.Is(err, releasequery.ErrValidation):
				err = app.ErrValidation
			case errors.Is(err, releasequery.ErrNotFound):
				err = app.ErrNotFound
			case errors.Is(err, application.ErrUnauthorized):
				err = app.ErrUnauthorized
			case errors.Is(err, application.ErrForbidden):
				err = app.ErrForbidden
			}
			writeProblem(w, r, err)
			return
		}
		writeData(w, http.StatusOK, domain.Product{ID: product.ID, TenantID: product.TenantID, Name: product.Name, Slug: product.Slug, CreatedAt: product.CreatedAt})
		return
	}
	product, err := s.releaseCatalog.GetProduct(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, product)
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID string `json:"product_id"`
		Name      string `json:"name"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		if s.projectCommands != nil {
			project, err := s.projectCommands.CreateProject(ctx, actor, releaseapp.CreateProjectInput{ProductID: req.ProductID, Name: req.Name})
			return http.StatusCreated, projectFromCommand(project), mapBuildAttestationCommandError(err)
		}
		project, err := s.releaseCatalog.CreateProject(ctx, actor, req.ProductID, req.Name)
		return http.StatusCreated, project, err
	})
}

func (s *Server) getProject(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.catalogPointQuery != nil {
		project, err := s.catalogPointQuery.GetProject(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			writeProblem(w, r, mapCatalogPointQueryError(err))
			return
		}
		writeData(w, http.StatusOK, domain.Project{ID: project.ID, TenantID: project.TenantID, ProductID: project.ProductID, Name: project.Name, CreatedAt: project.CreatedAt})
		return
	}
	project, err := s.releaseCatalog.GetProject(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, project)
}

func (s *Server) createRelease(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID string `json:"product_id"`
		Version   string `json:"version"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		if s.releaseCreationCommands != nil {
			release, err := s.releaseCreationCommands.CreateRelease(ctx, actor, releaseapp.CreateReleaseInput{ProductID: req.ProductID, Version: req.Version})
			return http.StatusCreated, releaseFromCommand(release), mapBuildAttestationCommandError(err)
		}
		release, err := s.releaseCatalog.CreateRelease(ctx, actor, req.ProductID, req.Version)
		return http.StatusCreated, release, err
	})
}

func (s *Server) getRelease(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.catalogPointQuery != nil {
		release, err := s.catalogPointQuery.GetRelease(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			writeProblem(w, r, mapCatalogPointQueryError(err))
			return
		}
		writeData(w, http.StatusOK, domain.ReleaseFromContextModel(release))
		return
	}
	release, err := s.releaseCatalog.GetRelease(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, release)
}

func mapCatalogPointQueryError(err error) error {
	switch {
	case errors.Is(err, releasequery.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, releasequery.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}

func (s *Server) startReleaseEvidenceFlow(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.evidenceFlowQuery != nil {
		flow, err := s.evidenceFlowQuery.Plan(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			writeProblem(w, r, mapCatalogPointQueryError(err))
			return
		}
		writeData(w, http.StatusOK, domain.ReleaseEvidenceFlowFromContextModel(flow))
		return
	}
	flow, err := s.releaseCatalog.ReleaseEvidenceFlowPlan(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, flow)
}

func (s *Server) releaseSecuritySummary(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.releaseSecuritySummaryQuery != nil {
		summary, err := s.releaseSecuritySummaryQuery.Summary(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			writeProblem(w, r, mapReleaseSecuritySummaryQueryError(err))
			return
		}
		writeData(w, http.StatusOK, releaseSecuritySummaryFromQuery(summary))
		return
	}
	summary, err := s.ledger.ReleaseSecuritySummary(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, summary)
}

func (s *Server) freezeRelease(w http.ResponseWriter, r *http.Request) {
	s.createConditional(w, r, func(s *Server, ctx requestContext, actor domain.Actor, _ []byte) (int, any, error) {
		expectedRevision, err := expectedRevisionFromIfMatch(r)
		if err != nil {
			return 0, nil, err
		}
		if s.releaseStateCommands != nil {
			release, err := s.releaseStateCommands.FreezeRelease(ctx, actor, r.PathValue("id"), expectedRevision)
			return http.StatusOK, releaseFromCommand(release), mapReleaseStateCommandError(err)
		}
		release, err := s.releaseCatalog.FreezeRelease(ctx, actor, r.PathValue("id"), expectedRevision)
		return http.StatusOK, release, err
	})
}

func (s *Server) approveRelease(w http.ResponseWriter, r *http.Request) {
	s.createConditional(w, r, func(s *Server, ctx requestContext, actor domain.Actor, _ []byte) (int, any, error) {
		expectedRevision, err := expectedRevisionFromIfMatch(r)
		if err != nil {
			return 0, nil, err
		}
		if s.releaseStateCommands != nil {
			release, err := s.releaseStateCommands.ApproveRelease(ctx, actor, r.PathValue("id"), expectedRevision)
			return http.StatusOK, releaseFromCommand(release), mapReleaseStateCommandError(err)
		}
		release, err := s.releaseCatalog.ApproveRelease(ctx, actor, r.PathValue("id"), expectedRevision)
		return http.StatusOK, release, err
	})
}

func (s *Server) createReleaseCandidate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReleaseID   string   `json:"release_id"`
		Name        string   `json:"name"`
		BuildIDs    []string `json:"build_ids"`
		ArtifactIDs []string `json:"artifact_ids"`
		SBOMIDs     []string `json:"sbom_ids"`
		ScanIDs     []string `json:"scan_ids"`
		VEXIDs      []string `json:"vex_ids"`
		ContractIDs []string `json:"contract_ids"`
		BundleIDs   []string `json:"bundle_ids"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		if s.candidateCommands != nil {
			candidate, err := s.candidateCommands.CreateReleaseCandidate(ctx, actor, releaseapp.CreateReleaseCandidateInput{
				ReleaseID: req.ReleaseID, Name: req.Name, BuildIDs: req.BuildIDs, ArtifactIDs: req.ArtifactIDs,
				SBOMIDs: req.SBOMIDs, ScanIDs: req.ScanIDs, VEXIDs: req.VEXIDs, ContractIDs: req.ContractIDs, BundleIDs: req.BundleIDs,
			})
			return http.StatusCreated, releaseCandidateFromQuery(candidate), mapBuildAttestationCommandError(err)
		}
		candidate, err := s.releaseCatalog.CreateReleaseCandidate(ctx, actor, app.CreateReleaseCandidateInput{
			ReleaseID: req.ReleaseID, Name: req.Name, BuildIDs: req.BuildIDs, ArtifactIDs: req.ArtifactIDs,
			SBOMIDs: req.SBOMIDs, ScanIDs: req.ScanIDs, VEXIDs: req.VEXIDs, ContractIDs: req.ContractIDs, BundleIDs: req.BundleIDs,
		})
		return http.StatusCreated, candidate, err
	})
}

func (s *Server) listReleaseCandidates(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.releaseCandidateQuery != nil {
		request, err := s.parsePageRequest(r, actor, "release-candidates", "release_id")
		if err != nil {
			writeProblem(w, r, err)
			return
		}
		page, err := s.releaseCandidateQuery.ListPage(r.Context(), actor, r.URL.Query().Get("release_id"), appquery.PageRequest{PageSize: request.pageSize, Sort: request.sort, Direction: request.direction}, request.after)
		if err != nil {
			writeProblem(w, r, mapReleaseCandidateQueryError(err))
			return
		}
		mapped := appquery.Result[domain.ReleaseCandidate]{Next: page.Next, Items: make([]domain.ReleaseCandidate, 0, len(page.Items))}
		for _, candidate := range page.Items {
			mapped.Items = append(mapped.Items, releaseCandidateFromQuery(candidate))
		}
		writePage(s, w, r, actor, "release-candidates", request, mapped)
		return
	}
	candidates, err := s.releaseCatalog.ListReleaseCandidates(r.Context(), actor, r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "release-candidates", []string{"release_id"}, candidates, func(candidate domain.ReleaseCandidate) (string, time.Time) {
		return candidate.ID, candidate.CreatedAt
	})
}

func (s *Server) getReleaseCandidate(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.releaseCandidateQuery != nil {
		candidate, err := s.releaseCandidateQuery.GetReleaseCandidate(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			writeProblem(w, r, mapReleaseCandidateQueryError(err))
			return
		}
		writeData(w, http.StatusOK, releaseCandidateFromQuery(candidate))
		return
	}
	candidate, err := s.releaseCatalog.GetReleaseCandidate(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, candidate)
}

func (s *Server) promoteReleaseCandidate(w http.ResponseWriter, r *http.Request) {
	s.transitionReleaseCandidate(w, r, "promoted")
}

func (s *Server) rejectReleaseCandidate(w http.ResponseWriter, r *http.Request) {
	s.transitionReleaseCandidate(w, r, "rejected")
}

func (s *Server) transitionReleaseCandidate(w http.ResponseWriter, r *http.Request, state string) {
	var req struct {
		Reason string `json:"reason"`
	}
	s.createConditional(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		expectedRevision, err := expectedRevisionFromIfMatch(r)
		if err != nil {
			return 0, nil, err
		}
		if s.candidateStateCommands != nil {
			candidate, err := s.candidateStateCommands.UpdateReleaseCandidateState(ctx, actor, r.PathValue("id"), state, req.Reason, expectedRevision)
			return http.StatusOK, releaseCandidateFromQuery(candidate), mapReleaseStateCommandError(err)
		}
		candidate, err := s.releaseCatalog.UpdateReleaseCandidateState(ctx, actor, r.PathValue("id"), state, req.Reason, expectedRevision)
		return http.StatusOK, candidate, err
	})
}

func (s *Server) registerArtifact(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		MediaType string `json:"media_type"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		if s.artifactCommands != nil {
			artifact, err := s.artifactCommands.RegisterArtifact(ctx, actor, releaseapp.RegisterArtifactInput{
				Name: req.Name, MediaType: req.MediaType, Digest: req.Digest, Size: req.Size,
			})
			return http.StatusCreated, artifactFromQuery(artifact), mapBuildAttestationCommandError(err)
		}
		artifact, err := s.releaseCatalog.RegisterArtifact(ctx, actor, req.Name, req.MediaType, req.Digest, req.Size)
		return http.StatusCreated, artifact, err
	})
}

func (s *Server) getArtifact(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.artifactPointQuery != nil {
		artifact, err := s.artifactPointQuery.GetArtifact(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			writeProblem(w, r, mapArtifactPointQueryError(err))
			return
		}
		writeData(w, http.StatusOK, artifactFromQuery(artifact))
		return
	}
	artifact, err := s.releaseCatalog.GetArtifact(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, artifact)
}

func (s *Server) registerContainerImage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ArtifactID string `json:"artifact_id"`
		Repository string `json:"repository"`
		Tag        string `json:"tag"`
		Digest     string `json:"digest"`
		Platform   string `json:"platform"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		if s.containerImageCommands != nil {
			image, err := s.containerImageCommands.RegisterContainerImage(ctx, actor, releaseapp.RegisterContainerImageInput{
				ArtifactID: req.ArtifactID, Repository: req.Repository, Tag: req.Tag, Digest: req.Digest, Platform: req.Platform,
			})
			return http.StatusCreated, containerImageFromCommand(image), mapBuildAttestationCommandError(err)
		}
		image, err := s.releaseCatalog.RegisterContainerImage(ctx, actor, app.RegisterContainerImageInput{
			ArtifactID: req.ArtifactID, Repository: req.Repository, Tag: req.Tag, Digest: req.Digest, Platform: req.Platform,
		})
		return http.StatusCreated, image, err
	})
}

func (s *Server) getArtifactSignature(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.artifactSignatureQuery != nil {
		signature, err := s.artifactSignatureQuery.GetArtifactSignature(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			writeProblem(w, r, mapArtifactSignatureQueryError(err))
			return
		}
		writeData(w, http.StatusOK, artifactSignatureFromQuery(signature))
		return
	}
	sig, err := s.ledger.GetArtifactSignature(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, sig)
}

func (s *Server) getBuild(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.buildPointQuery != nil {
		build, err := s.buildPointQuery.GetBuildRun(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			writeProblem(w, r, mapCatalogPointQueryError(err))
			return
		}
		writeData(w, http.StatusOK, buildRunFromQuery(build))
		return
	}
	build, err := s.releaseCatalog.GetBuildRun(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, build)
}

func (s *Server) uploadBuildAttestation(w http.ResponseWriter, r *http.Request) {
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if s.buildAttestationCommands != nil {
			attestation, err := s.buildAttestationCommands.UploadBuildAttestation(ctx, actor, r.PathValue("id"), body)
			return http.StatusCreated, buildAttestationFromCommand(attestation), mapBuildAttestationCommandError(err)
		}
		attestation, err := s.releaseCatalog.UploadBuildAttestation(ctx, actor, r.PathValue("id"), body)
		return http.StatusCreated, attestation, err
	})
}

func (s *Server) listSourceRepositories(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.sourceRepositoryQuery != nil {
		request, err := s.parsePageRequest(r, actor, "source-repositories", "project_id")
		if err != nil {
			writeProblem(w, r, err)
			return
		}
		page, err := s.sourceRepositoryQuery.ListPage(r.Context(), actor, r.URL.Query().Get("project_id"), appquery.PageRequest{PageSize: request.pageSize, Sort: request.sort, Direction: request.direction}, request.after)
		if err != nil {
			writeProblem(w, r, mapIntegrationQueryError(err))
			return
		}
		mapped := appquery.Result[domain.SourceRepository]{Next: page.Next, Items: make([]domain.SourceRepository, 0, len(page.Items))}
		for _, repository := range page.Items {
			mapped.Items = append(mapped.Items, sourceRepositoryFromQuery(repository))
		}
		writePage(s, w, r, actor, "source-repositories", request, mapped)
		return
	}
	repos, err := s.ledger.ListSourceRepositories(r.Context(), actor, r.URL.Query().Get("project_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "source-repositories", []string{"project_id"}, repos, func(repo domain.SourceRepository) (string, time.Time) {
		return repo.ID, repo.CreatedAt
	})
}

func (s *Server) uploadGitHubSourceSnapshot(w http.ResponseWriter, r *http.Request) {
	s.recordSourceSnapshot(w, r, "github")
}

func (s *Server) uploadGitLabSourceSnapshot(w http.ResponseWriter, r *http.Request) {
	s.recordSourceSnapshot(w, r, "gitlab")
}

func (s *Server) createDeploymentEnvironment(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID string `json:"product_id"`
		Name      string `json:"name"`
		Kind      string `json:"kind"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		if s.deploymentEnvironmentCommands != nil {
			if err := validateNonNullableObjectFields(body, "product_id", "name", "kind"); err != nil {
				return 0, nil, err
			}
			env, err := s.deploymentEnvironmentCommands.CreateDeploymentEnvironment(ctx, actor, operationsapp.CreateEnvironmentInput{ProductID: req.ProductID, Name: req.Name, Kind: req.Kind})
			return http.StatusCreated, deploymentEnvironmentFromQuery(env), mapDeploymentCommandError(err)
		}
		env, err := s.ledger.CreateDeploymentEnvironment(ctx, actor, app.CreateEnvironmentInput{ProductID: req.ProductID, Name: req.Name, Kind: req.Kind})
		return http.StatusCreated, env, err
	})
}

func (s *Server) listDeploymentEnvironments(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.deploymentListQuery != nil {
		request, err := s.parsePageRequest(r, actor, "deployment-environments", "product_id")
		if err != nil {
			writeProblem(w, r, err)
			return
		}
		page, err := s.deploymentListQuery.ListEnvironmentsPage(r.Context(), actor, r.URL.Query().Get("product_id"), appquery.PageRequest{PageSize: request.pageSize, Sort: request.sort, Direction: request.direction}, request.after)
		if err != nil {
			writeProblem(w, r, mapDeploymentPointQueryError(err))
			return
		}
		mapped := appquery.Result[domain.DeploymentEnvironment]{Next: page.Next, Items: make([]domain.DeploymentEnvironment, 0, len(page.Items))}
		for _, environment := range page.Items {
			mapped.Items = append(mapped.Items, deploymentEnvironmentFromQuery(environment))
		}
		writePage(s, w, r, actor, "deployment-environments", request, mapped)
		return
	}
	envs, err := s.ledger.ListDeploymentEnvironments(r.Context(), actor, r.URL.Query().Get("product_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "deployment-environments", []string{"product_id"}, envs, func(environment domain.DeploymentEnvironment) (string, time.Time) {
		return environment.ID, environment.CreatedAt
	})
}

func (s *Server) recordDeployment(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EnvironmentID string     `json:"environment_id"`
		ReleaseID     string     `json:"release_id"`
		ArtifactIDs   []string   `json:"artifact_ids"`
		Status        string     `json:"status"`
		StartedAt     time.Time  `json:"started_at"`
		FinishedAt    *time.Time `json:"finished_at"`
		RollbackOf    string     `json:"rollback_of"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		if s.deploymentCommands != nil {
			if err := validateNonNullableObjectFields(body, "environment_id", "release_id", "artifact_ids", "status", "started_at", "finished_at", "rollback_of"); err != nil {
				return 0, nil, err
			}
			if err := validateNonNullableArrayItems(body, "artifact_ids"); err != nil {
				return 0, nil, err
			}
			deployment, err := s.deploymentCommands.RecordDeployment(ctx, actor, operationsapp.RecordDeploymentInput{EnvironmentID: req.EnvironmentID, ReleaseID: req.ReleaseID, ArtifactIDs: req.ArtifactIDs, Status: req.Status, StartedAt: req.StartedAt, FinishedAt: req.FinishedAt, RollbackOf: req.RollbackOf})
			return http.StatusCreated, deploymentEventFromQuery(deployment), mapDeploymentCommandError(err)
		}
		deployment, err := s.ledger.RecordDeployment(ctx, actor, app.RecordDeploymentInput{
			EnvironmentID: req.EnvironmentID, ReleaseID: req.ReleaseID, ArtifactIDs: req.ArtifactIDs,
			Status: req.Status, StartedAt: req.StartedAt, FinishedAt: req.FinishedAt, RollbackOf: req.RollbackOf,
		})
		return http.StatusCreated, deployment, err
	})
}

func (s *Server) listDeployments(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.deploymentListQuery != nil {
		request, err := s.parsePageRequest(r, actor, "deployments", "release_id", "environment_id")
		if err != nil {
			writeProblem(w, r, err)
			return
		}
		page, err := s.deploymentListQuery.ListDeploymentsPage(r.Context(), actor, r.URL.Query().Get("release_id"), r.URL.Query().Get("environment_id"), appquery.PageRequest{PageSize: request.pageSize, Sort: request.sort, Direction: request.direction}, request.after)
		if err != nil {
			writeProblem(w, r, mapDeploymentPointQueryError(err))
			return
		}
		mapped := appquery.Result[domain.DeploymentEvent]{Next: page.Next, Items: make([]domain.DeploymentEvent, 0, len(page.Items))}
		for _, deployment := range page.Items {
			mapped.Items = append(mapped.Items, deploymentEventFromQuery(deployment))
		}
		writePage(s, w, r, actor, "deployments", request, mapped)
		return
	}
	deployments, err := s.ledger.ListDeployments(r.Context(), actor, r.URL.Query().Get("release_id"), r.URL.Query().Get("environment_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "deployments", []string{"release_id", "environment_id"}, deployments, func(deployment domain.DeploymentEvent) (string, time.Time) {
		return deployment.ID, deployment.CreatedAt
	})
}

func (s *Server) getDeployment(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.deploymentPointQuery != nil {
		deployment, err := s.deploymentPointQuery.GetDeployment(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			writeProblem(w, r, mapDeploymentPointQueryError(err))
			return
		}
		writeData(w, http.StatusOK, deploymentEventFromQuery(deployment))
		return
	}
	deployment, err := s.ledger.GetDeployment(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, deployment)
}

func (s *Server) createIncident(w http.ResponseWriter, r *http.Request) {
	if s.incidentCommands != nil {
		s.createDurableIncident(w, r)
		return
	}
	var req struct {
		ProductID string    `json:"product_id"`
		ReleaseID string    `json:"release_id"`
		Title     string    `json:"title"`
		Severity  string    `json:"severity"`
		OpenedAt  time.Time `json:"opened_at"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		incident, err := s.ledger.CreateIncident(ctx, actor, app.CreateIncidentInput{ProductID: req.ProductID, ReleaseID: req.ReleaseID, Title: req.Title, Severity: req.Severity, OpenedAt: req.OpenedAt})
		return http.StatusCreated, incident, err
	})
}

func (s *Server) recordIncidentTimeline(w http.ResponseWriter, r *http.Request) {
	if s.incidentCommands != nil {
		s.recordDurableIncidentTimeline(w, r)
		return
	}
	var req struct {
		EventType  string    `json:"event_type"`
		Summary    string    `json:"summary"`
		EvidenceID string    `json:"evidence_id"`
		OccurredAt time.Time `json:"occurred_at"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		event, err := s.ledger.RecordIncidentTimelineEvent(ctx, actor, r.PathValue("id"), app.RecordIncidentTimelineInput{EventType: req.EventType, Summary: req.Summary, EvidenceID: req.EvidenceID, OccurredAt: req.OccurredAt})
		return http.StatusCreated, event, err
	})
}

func (s *Server) createIncidentWebhookReceiver(w http.ResponseWriter, r *http.Request) {
	if s.incidentWebhookCommands != nil {
		s.createDurableIncidentWebhookReceiver(w, r)
		return
	}
	var req struct {
		Name      string `json:"name"`
		Provider  string `json:"provider"`
		PublicKey string `json:"public_key"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		receiver, err := s.ledger.CreateIncidentWebhookReceiver(ctx, actor, app.CreateIncidentWebhookReceiverInput{IncidentID: r.PathValue("id"), Name: req.Name, Provider: req.Provider, PublicKey: req.PublicKey})
		return http.StatusCreated, receiver, err
	})
}

func (s *Server) receiveIncidentWebhook(w http.ResponseWriter, r *http.Request) {
	if s.incidentWebhookCommands != nil {
		s.receiveDurableIncidentWebhook(w, r)
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	timestamp, err := time.Parse(time.RFC3339, strings.TrimSpace(r.Header.Get("X-Evydence-Webhook-Timestamp")))
	if err != nil {
		writeProblem(w, r, app.ErrValidation)
		return
	}
	record, event, err := s.ledger.HandleIncidentWebhook(r.Context(), app.HandleIncidentWebhookInput{
		ReceiverID: r.PathValue("receiver_id"),
		EventID:    r.Header.Get("X-Evydence-Webhook-Event-ID"),
		Timestamp:  timestamp,
		Signature:  r.Header.Get("X-Evydence-Webhook-Signature"),
		Body:       body,
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusCreated, map[string]any{"webhook_event": record, "timeline_event": event})
}

func (s *Server) createRemediationTask(w http.ResponseWriter, r *http.Request) {
	if s.incidentCommands != nil {
		s.createDurableRemediationTask(w, r)
		return
	}
	var req struct {
		IncidentID string     `json:"incident_id"`
		ReleaseID  string     `json:"release_id"`
		Title      string     `json:"title"`
		Owner      string     `json:"owner"`
		DueAt      *time.Time `json:"due_at"`
		EvidenceID string     `json:"evidence_id"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		task, err := s.ledger.CreateRemediationTask(ctx, actor, app.CreateRemediationTaskInput{IncidentID: req.IncidentID, ReleaseID: req.ReleaseID, Title: req.Title, Owner: req.Owner, DueAt: req.DueAt, EvidenceID: req.EvidenceID})
		return http.StatusCreated, task, err
	})
}

func (s *Server) incidentReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.incidentReportQuery != nil {
		id, err := optionalSingletonQuery(r, "incident_id")
		if err != nil {
			writeProblem(w, r, err)
			return
		}
		report, err := s.incidentReportQuery.Report(r.Context(), actor, id)
		if err != nil {
			writeProblem(w, r, mapIncidentReportQueryError(err))
			return
		}
		writeData(w, http.StatusOK, incidentReportFromQuery(report))
		return
	}
	report, err := s.ledger.IncidentReport(r.Context(), actor, r.URL.Query().Get("incident_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) uploadSecurityScan(w http.ResponseWriter, r *http.Request) {
	if s.securityDocumentCommands != nil {
		s.uploadDurableSecurityScan(w, r, false)
		return
	}
	var req struct {
		ProductID  string          `json:"product_id"`
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Category   string          `json:"category"`
		Format     string          `json:"format"`
		Scanner    string          `json:"scanner"`
		TargetRef  string          `json:"target_ref"`
		Payload    json.RawMessage `json:"payload"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		scan, err := s.evidenceIngestion.UploadSecurityScan(ctx, actor, app.UploadSecurityScanInput{ProductID: req.ProductID, ReleaseID: req.ReleaseID, ArtifactID: req.ArtifactID, Category: req.Category, Format: req.Format, Scanner: req.Scanner, TargetRef: req.TargetRef, Raw: req.Payload})
		return http.StatusCreated, scan, err
	})
}

func (s *Server) uploadAPISecurityScan(w http.ResponseWriter, r *http.Request) {
	if s.securityDocumentCommands != nil {
		s.uploadDurableSecurityScan(w, r, true)
		return
	}
	var req struct {
		ProductID  string          `json:"product_id"`
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Format     string          `json:"format"`
		Scanner    string          `json:"scanner"`
		TargetRef  string          `json:"target_ref"`
		Payload    json.RawMessage `json:"payload"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		scan, err := s.evidenceIngestion.UploadAPISecurityScan(ctx, actor, app.UploadSecurityScanInput{ProductID: req.ProductID, ReleaseID: req.ReleaseID, ArtifactID: req.ArtifactID, Format: req.Format, Scanner: req.Scanner, TargetRef: req.TargetRef, Raw: req.Payload})
		return http.StatusCreated, scan, err
	})
}

func (s *Server) uploadManualSecurityDocument(w http.ResponseWriter, r *http.Request) {
	if s.securityDocumentCommands != nil {
		s.uploadDurableManualSecurityDocument(w, r)
		return
	}
	var req struct {
		ProductID    string          `json:"product_id"`
		ReleaseID    string          `json:"release_id"`
		DocumentType string          `json:"document_type"`
		Title        string          `json:"title"`
		Sensitivity  string          `json:"sensitivity"`
		MediaType    string          `json:"media_type"`
		Payload      json.RawMessage `json:"payload"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		doc, err := s.evidenceIngestion.UploadManualSecurityDocument(ctx, actor, app.UploadManualSecurityDocumentInput{ProductID: req.ProductID, ReleaseID: req.ReleaseID, DocumentType: req.DocumentType, Title: req.Title, Sensitivity: req.Sensitivity, Raw: req.Payload, MediaType: req.MediaType})
		return http.StatusCreated, doc, err
	})
}

func (s *Server) createWaiver(w http.ResponseWriter, r *http.Request) {
	if s.waiverCommands != nil {
		s.createDurableWaiver(w, r)
		return
	}
	var req struct {
		ScopeType  string    `json:"scope_type"`
		ScopeID    string    `json:"scope_id"`
		ControlID  string    `json:"control_id"`
		PolicyID   string    `json:"policy_id"`
		Owner      string    `json:"owner"`
		Risk       string    `json:"risk"`
		Reason     string    `json:"reason"`
		ExpiresAt  time.Time `json:"expires_at"`
		Supersedes string    `json:"supersedes"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		waiver, err := s.riskDecisions.CreateWaiver(ctx, actor, app.CreateWaiverInput{ScopeType: req.ScopeType, ScopeID: req.ScopeID, ControlID: req.ControlID, PolicyID: req.PolicyID, Owner: req.Owner, Risk: req.Risk, Reason: req.Reason, ExpiresAt: req.ExpiresAt, Supersedes: req.Supersedes})
		return http.StatusCreated, waiver, err
	})
}

func (s *Server) approveWaiver(w http.ResponseWriter, r *http.Request) {
	if s.waiverCommands != nil {
		s.approveDurableWaiver(w, r)
		return
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, _ []byte) (int, any, error) {
		waiver, err := s.riskDecisions.ApproveWaiver(ctx, actor, r.PathValue("id"))
		return http.StatusOK, waiver, err
	})
}

func (s *Server) createApproval(w http.ResponseWriter, r *http.Request) {
	if s.approvalCommands != nil {
		s.createDurableApproval(w, r)
		return
	}
	var req struct {
		SubjectType string `json:"subject_type"`
		SubjectID   string `json:"subject_id"`
		Decision    string `json:"decision"`
		Reason      string `json:"reason"`
		EvidenceID  string `json:"evidence_id"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		approval, err := s.riskDecisions.CreateApprovalRecord(ctx, actor, app.CreateApprovalInput{SubjectType: req.SubjectType, SubjectID: req.SubjectID, Decision: req.Decision, Reason: req.Reason, EvidenceID: req.EvidenceID})
		return http.StatusCreated, approval, err
	})
}

func (s *Server) createRedactionProfile(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	if s.redactionProfileCommands != nil {
		s.createDurableRedactionProfile(w, r)
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		req, err := decodeRedactionProfileRequest(body)
		if err != nil {
			return 0, nil, err
		}
		profile, err := s.packages.CreateRedactionProfile(ctx, actor, app.CreateRedactionProfileInput{Name: req.Name, Description: req.Description, Preset: req.Preset, AllowedTypes: req.AllowedTypes, ExcludedFields: req.ExcludedFields})
		return http.StatusCreated, profile, err
	}, func(r *http.Request, actor domain.Actor, body []byte) ([]byte, error) {
		if _, err := decodeRedactionProfileRequest(body); err != nil {
			return nil, err
		}
		if err := mapCustomerPackageAccessError(application.AuthorizeTenantWideScope(r.Context(), actor, app.ScopePackageWrite)); err != nil {
			return nil, err
		}
		return body, nil
	})
}

func (s *Server) getCustomerPackage(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.customerPackageAccessCommands != nil {
		pkg, err := s.customerPackageAccessCommands.AccessCustomerSecurityPackage(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			writeProblem(w, r, mapCustomerPackageAccessError(err))
			return
		}
		writeData(w, http.StatusOK, customerPackageFromAccess(pkg))
		return
	}
	pkg, err := s.packages.AccessCustomerSecurityPackage(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, pkg)
}

func (s *Server) downloadCustomerPackage(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	archive, err := s.customerPackageArchive(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeArchive(w, archive)
}

func (s *Server) securityReviewPackageReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.customerPackageAccessCommands != nil {
		id, err := optionalSingletonQuery(r, "package_id")
		if err != nil || id == "" {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		report, err := s.customerPackageAccessCommands.SecurityReviewPackageReport(r.Context(), actor, id)
		if err != nil {
			writeProblem(w, r, mapCustomerPackageAccessError(err))
			return
		}
		writeData(w, http.StatusOK, securityReviewPackageFromAccess(report))
		return
	}
	report, err := s.ledger.SecurityReviewPackageReport(r.Context(), actor, r.URL.Query().Get("package_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) craReadinessHTMLPackage(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	filter, err := controlReportFilters(r, true)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	if s.htmlReportCommands != nil {
		report, err := s.htmlReportCommands.CRAReadinessHTMLPackage(r.Context(), actor, filter.ProductID, filter.ReleaseID)
		if err != nil {
			writeProblem(w, r, mapCustomerPackageAccessError(mapControlCoverageQueryError(err)))
			return
		}
		writeData(w, http.StatusOK, htmlReportFromCommands(report))
		return
	}
	report, err := s.packages.CRAReadinessHTMLPackage(r.Context(), actor, filter.ProductID, filter.ReleaseID)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) createReportTemplate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name          string   `json:"name"`
		Version       string   `json:"version"`
		ReportType    string   `json:"report_type"`
		AllowedFields []string `json:"allowed_fields"`
		Template      string   `json:"template"`
	}
	s.createWithLimit(w, r, app.ReportTemplateRequestLimit, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		if s.reportTemplateCommands != nil {
			template, err := s.reportTemplateCommands.CreateCustomReportTemplate(ctx, actor, packageapp.CreateReportTemplateInput{Name: req.Name, Version: req.Version, ReportType: req.ReportType, AllowedFields: req.AllowedFields, Template: req.Template})
			return http.StatusCreated, reportTemplateFromCommands(template), mapCustomerPackageAccessError(err)
		}
		tpl, err := s.packages.CreateCustomReportTemplate(ctx, actor, app.CreateReportTemplateInput{Name: req.Name, Version: req.Version, ReportType: req.ReportType, AllowedFields: req.AllowedFields, Template: req.Template})
		return http.StatusCreated, tpl, err
	})
}

func (s *Server) renderReportTemplate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SubjectType string `json:"subject_type"`
		SubjectID   string `json:"subject_id"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		if strings.TrimSpace(req.SubjectType) == "" || strings.TrimSpace(req.SubjectID) == "" {
			return 0, nil, app.ErrValidation
		}
		if s.reportTemplateCommands != nil {
			report, err := s.reportTemplateCommands.RenderCustomReport(ctx, actor, packageapp.RenderReportInput{TemplateID: r.PathValue("id"), SubjectType: req.SubjectType, SubjectID: req.SubjectID})
			return http.StatusCreated, renderedReportFromCommands(report), mapCustomerPackageAccessError(err)
		}
		report, err := s.packages.RenderCustomReport(ctx, actor, app.RenderReportInput{TemplateID: r.PathValue("id"), SubjectType: req.SubjectType, SubjectID: req.SubjectID})
		return http.StatusCreated, report, err
	})
}

func (s *Server) exportEvidenceBundle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReleaseID   string   `json:"release_id"`
		EvidenceIDs []string `json:"evidence_ids"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		if err := validateNonNullableObjectFields(body, "release_id", "evidence_ids"); err != nil {
			return 0, nil, err
		}
		for _, id := range req.EvidenceIDs {
			if strings.TrimSpace(id) == "" {
				return 0, nil, app.ErrValidation
			}
		}
		if s.evidenceBundleCommands != nil {
			bundle, err := s.evidenceBundleCommands.ExportEvidenceBundle(ctx, actor, req.ReleaseID, req.EvidenceIDs)
			return http.StatusCreated, evidenceBundleFromCommands(bundle), mapCustomerPackageAccessError(err)
		}
		bundle, err := s.packages.ExportEvidenceBundle(ctx, actor, req.ReleaseID, req.EvidenceIDs)
		return http.StatusCreated, bundle, err
	})
}

func (s *Server) importEvidenceBundle(w http.ResponseWriter, r *http.Request) {
	var req domain.EvidenceBundle
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		if s.bundleImportCommand != nil {
			record, err := s.bundleImportCommand.ImportEvidenceBundle(ctx, actor, evidenceBundleForImport(req))
			return http.StatusCreated, evidenceBundleImportFromCommands(record), mapCustomerPackageAccessError(err)
		}
		record, err := s.packages.ImportEvidenceBundle(ctx, actor, req)
		return http.StatusCreated, record, err
	})
}

func (s *Server) uploadSPDXSBOM(w http.ResponseWriter, r *http.Request) {
	if s.sbomIngestionCommands != nil {
		s.uploadDurableSBOM(w, r, "spdx")
		return
	}
	if requestMediaType(r) == "application/spdx+json" {
		releaseID, err := requiredSingleHeader(r, "X-Evydence-Release-ID")
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		artifactID, err := optionalSingleHeader(r, "X-Evydence-Artifact-ID")
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		s.createStreamedEvidence(r.Context(), w, r, app.EvidenceDocumentLimit, map[string]string{
			"artifact_id": artifactID, "media_type": requestMediaType(r), "release_id": releaseID,
		}, func(s *Server, ctx requestContext, actor domain.Actor, source app.PayloadSource) (int, any, error) {
			sbom, err := s.evidenceIngestion.UploadSPDXSBOMPayload(ctx, actor, releaseID, artifactID, source)
			return http.StatusCreated, sbom, err
		})
		return
	}
	var req struct {
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Payload    json.RawMessage `json:"payload"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		sbom, err := s.evidenceIngestion.UploadSPDXSBOM(ctx, actor, req.ReleaseID, req.ArtifactID, req.Payload)
		return http.StatusCreated, sbom, err
	})
}

func (s *Server) createSBOMDiff(w http.ResponseWriter, r *http.Request) {
	if s.sbomDiffCommands != nil {
		s.createDurableSBOMDiff(w, r)
		return
	}
	var req struct {
		BaseSBOMID   string `json:"base_sbom_id"`
		TargetSBOMID string `json:"target_sbom_id"`
		ReleaseID    string `json:"release_id"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		diff, err := s.evidenceIngestion.CreateSBOMDiff(ctx, actor, app.CreateSBOMDiffInput{BaseSBOMID: req.BaseSBOMID, TargetSBOMID: req.TargetSBOMID, ReleaseID: req.ReleaseID})
		return http.StatusCreated, diff, err
	})
}

func (s *Server) createEvidence(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID        string              `json:"product_id"`
		ProjectID        string              `json:"project_id"`
		ReleaseID        string              `json:"release_id"`
		BuildID          string              `json:"build_id"`
		DeploymentID     string              `json:"deployment_id"`
		Type             string              `json:"type"`
		Subtype          string              `json:"subtype"`
		Title            string              `json:"title"`
		SourceSystem     string              `json:"source_system"`
		SourceIdentity   map[string]any      `json:"source_identity"`
		CollectorID      string              `json:"collector_id"`
		ObservedAt       time.Time           `json:"observed_at"`
		PayloadRef       string              `json:"payload_ref"`
		PayloadHash      string              `json:"payload_hash"`
		PayloadMediaType string              `json:"payload_media_type"`
		PayloadSize      int64               `json:"payload_size"`
		SubjectRefs      []domain.SubjectRef `json:"subject_refs"`
		Metadata         map[string]any      `json:"metadata"`
		Tags             []string            `json:"tags"`
		Limitations      []string            `json:"limitations"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		if s.evidenceCreationCommands != nil {
			refs := make([]evidencedomain.SubjectRef, 0, len(req.SubjectRefs))
			for _, ref := range req.SubjectRefs {
				refs = append(refs, evidencedomain.SubjectRef{Type: ref.Type, ID: ref.ID, Digest: ref.Digest})
			}
			item, err := s.evidenceCreationCommands.CreateEvidence(ctx, actor, evidenceapp.CreateEvidenceInput{
				ProductID: req.ProductID, ProjectID: req.ProjectID, ReleaseID: req.ReleaseID, BuildID: req.BuildID, DeploymentID: req.DeploymentID,
				Type: req.Type, Subtype: req.Subtype, Title: req.Title,
				SourceSystem: req.SourceSystem, SourceIdentity: req.SourceIdentity, CollectorID: req.CollectorID, ObservedAt: req.ObservedAt,
				PayloadRef: req.PayloadRef, PayloadHash: req.PayloadHash, PayloadMediaType: req.PayloadMediaType, PayloadSize: req.PayloadSize,
				SubjectRefs: refs, Metadata: req.Metadata, Tags: req.Tags, Limitations: req.Limitations,
			})
			return http.StatusCreated, domain.EvidenceFromContextModel(item), mapEvidenceCreationCommandError(err)
		}
		item, err := s.evidenceIngestion.CreateEvidence(ctx, actor, app.CreateEvidenceInput{
			ProductID: req.ProductID, ProjectID: req.ProjectID, ReleaseID: req.ReleaseID, BuildID: req.BuildID, DeploymentID: req.DeploymentID,
			Type: req.Type, Subtype: req.Subtype, Title: req.Title,
			SourceSystem: req.SourceSystem, SourceIdentity: req.SourceIdentity, CollectorID: req.CollectorID, ObservedAt: req.ObservedAt,
			PayloadRef: req.PayloadRef, PayloadHash: req.PayloadHash, PayloadMediaType: req.PayloadMediaType, PayloadSize: req.PayloadSize,
			SubjectRefs: req.SubjectRefs, Metadata: req.Metadata, Tags: req.Tags, Limitations: req.Limitations,
		})
		return http.StatusCreated, item, err
	})
}

func (s *Server) listEvidence(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	pageRequest, err := s.parsePageRequest(r, actor, "evidence", "release_id", "type")
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	query := r.URL.Query()
	page, err := s.evidenceIngestion.ListEvidencePage(r.Context(), actor, app.EvidencePageRequest{
		ReleaseID: query.Get("release_id"),
		Type:      query.Get("type"),
		Page: appquery.PageRequest{
			PageSize:  pageRequest.pageSize,
			Sort:      pageRequest.sort,
			Direction: pageRequest.direction,
		},
		After: pageRequest.after,
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writePage(s, w, r, actor, "evidence", pageRequest, page)
}

func (s *Server) searchEvidence(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	pageRequest, err := s.parsePageRequestWithLegacyLimit(r, actor, "evidence-search", true, "product_id", "project_id", "release_id", "build_id", "deployment_id", "type", "subtype", "source", "source_system", "collector_id", "verification_status", "subject_type", "subject_id", "tag", "created_after", "created_before")
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	query := r.URL.Query()
	sourceSystem := query.Get("source")
	if sourceSystem != "" && query.Get("source_system") != "" {
		writeProblem(w, r, app.ErrValidation)
		return
	}
	if sourceSystem == "" {
		sourceSystem = query.Get("source_system")
	}
	createdAfter, err := parseOptionalRFC3339(query.Get("created_after"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	createdBefore, err := parseOptionalRFC3339(query.Get("created_before"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	page, err := s.evidenceIngestion.SearchEvidencePage(r.Context(), actor, app.EvidenceSearchPageRequest{
		Filter: app.EvidenceSearchInput{
			ProductID:          query.Get("product_id"),
			ProjectID:          query.Get("project_id"),
			ReleaseID:          query.Get("release_id"),
			BuildID:            query.Get("build_id"),
			DeploymentID:       query.Get("deployment_id"),
			Type:               query.Get("type"),
			Subtype:            query.Get("subtype"),
			SourceSystem:       sourceSystem,
			CollectorID:        query.Get("collector_id"),
			VerificationStatus: query.Get("verification_status"),
			SubjectType:        query.Get("subject_type"),
			SubjectID:          query.Get("subject_id"),
			Tag:                query.Get("tag"),
			CreatedAfter:       createdAfter,
			CreatedBefore:      createdBefore,
		},
		Page: appquery.PageRequest{
			PageSize:  pageRequest.pageSize,
			Sort:      pageRequest.sort,
			Direction: pageRequest.direction,
		},
		After: pageRequest.after,
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writePage(s, w, r, actor, "evidence-search", pageRequest, page)
}

func (s *Server) getEvidence(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.evidencePointQuery != nil {
		item, err := s.evidencePointQuery.GetEvidence(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			writeProblem(w, r, mapEvidencePointQueryError(err))
			return
		}
		writeData(w, http.StatusOK, domain.EvidenceFromContextModel(item))
		return
	}
	item, err := s.evidenceIngestion.GetEvidence(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, item)
}

func (s *Server) supersedeEvidence(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReplacementEvidenceID string `json:"replacement_evidence_id"`
		Reason                string `json:"reason"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		item, err := s.evidenceIngestion.SupersedeEvidence(ctx, actor, r.PathValue("id"), req.ReplacementEvidenceID, req.Reason)
		return http.StatusCreated, item, err
	})
}

func (s *Server) linkEvidence(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TargetType string `json:"target_type"`
		TargetID   string `json:"target_id"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		item, err := s.evidenceIngestion.LinkEvidence(ctx, actor, r.PathValue("id"), req.TargetType, req.TargetID)
		return http.StatusCreated, item, err
	})
}

func (s *Server) recordEvidenceLifecycleEvent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action        string         `json:"action"`
		Reason        string         `json:"reason"`
		Details       map[string]any `json:"details"`
		ReplacementID string         `json:"replacement_id"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		event, err := s.evidenceIngestion.RecordEvidenceLifecycleEvent(ctx, actor, r.PathValue("id"), app.RecordEvidenceLifecycleInput{
			Action: req.Action, Reason: req.Reason, Details: req.Details, ReplacementID: req.ReplacementID,
		})
		return http.StatusCreated, event, err
	})
}

func (s *Server) listEvidenceLifecycleEvents(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	resource := "evidence/" + r.PathValue("id") + "/lifecycle-events"
	if s.lifecycleEventsQuery != nil {
		request, err := s.parsePageRequest(r, actor, resource)
		if err != nil {
			writeProblem(w, r, err)
			return
		}
		page, err := s.lifecycleEventsQuery.ListPage(r.Context(), actor, r.PathValue("id"), appquery.PageRequest{PageSize: request.pageSize, Sort: request.sort, Direction: request.direction}, request.after)
		if err != nil {
			writeProblem(w, r, mapEvidencePointQueryError(err))
			return
		}
		mapped := appquery.Result[domain.EvidenceLifecycleEvent]{Next: page.Next, Items: make([]domain.EvidenceLifecycleEvent, 0, len(page.Items))}
		for _, event := range page.Items {
			mapped.Items = append(mapped.Items, lifecycleEventFromQuery(event))
		}
		writePage(s, w, r, actor, resource, request, mapped)
		return
	}
	events, err := s.evidenceIngestion.ListEvidenceLifecycleEvents(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, resource, nil, events, func(event domain.EvidenceLifecycleEvent) (string, time.Time) {
		return event.ID, event.CreatedAt
	})
}

func (s *Server) uploadSBOM(w http.ResponseWriter, r *http.Request) {
	if s.sbomIngestionCommands != nil {
		s.uploadDurableSBOM(w, r, "cyclonedx")
		return
	}
	if requestMediaType(r) == "application/vnd.cyclonedx+json" {
		releaseID, err := requiredSingleHeader(r, "X-Evydence-Release-ID")
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		artifactID, err := optionalSingleHeader(r, "X-Evydence-Artifact-ID")
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		s.createStreamedEvidence(r.Context(), w, r, app.EvidenceDocumentLimit, map[string]string{
			"artifact_id": artifactID, "media_type": requestMediaType(r), "release_id": releaseID,
		}, func(s *Server, ctx requestContext, actor domain.Actor, source app.PayloadSource) (int, any, error) {
			sbom, err := s.evidenceIngestion.UploadSBOMPayload(ctx, actor, releaseID, artifactID, source)
			return http.StatusCreated, sbom, err
		})
		return
	}
	var req struct {
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Payload    json.RawMessage `json:"payload"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		sbom, err := s.evidenceIngestion.UploadSBOM(ctx, actor, req.ReleaseID, req.ArtifactID, req.Payload)
		return http.StatusCreated, sbom, err
	})
}

func (s *Server) getSBOM(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.sbomPointQuery != nil {
		sbom, err := s.sbomPointQuery.GetSBOM(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			writeProblem(w, r, mapEvidencePointQueryError(err))
			return
		}
		writeData(w, http.StatusOK, sbomFromQuery(sbom))
		return
	}
	sbom, err := s.evidenceIngestion.GetSBOM(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, sbom)
}

func (s *Server) listSBOMComponents(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.sbomComponentsQuery != nil {
		request, err := s.parsePageRequestWithLegacyLimit(r, actor, "sbom-components", true, "sbom_id", "release_id", "artifact_id", "query", "purl")
		if err != nil {
			writeProblem(w, r, err)
			return
		}
		query := r.URL.Query()
		page, err := s.sbomComponentsQuery.ListPage(r.Context(), actor, evidencequery.SBOMComponentFilter{
			SBOMID: query.Get("sbom_id"), ReleaseID: query.Get("release_id"), ArtifactID: query.Get("artifact_id"),
			Query: query.Get("query"), PURL: query.Get("purl"),
		}, appquery.PageRequest{PageSize: request.pageSize, Sort: request.sort, Direction: request.direction}, request.after)
		if err != nil {
			writeProblem(w, r, mapEvidencePointQueryError(err))
			return
		}
		mapped := appquery.Result[domain.SBOMComponentRecord]{Next: page.Next, Items: make([]domain.SBOMComponentRecord, 0, len(page.Items))}
		for _, component := range page.Items {
			mapped.Items = append(mapped.Items, sbomComponentFromQuery(component))
		}
		writePage(s, w, r, actor, "sbom-components", request, mapped)
		return
	}
	query := r.URL.Query()
	components, err := s.evidenceIngestion.ListSBOMComponents(r.Context(), actor, app.ListSBOMComponentsInput{
		SBOMID:     query.Get("sbom_id"),
		ReleaseID:  query.Get("release_id"),
		ArtifactID: query.Get("artifact_id"),
		Query:      query.Get("query"),
		PURL:       query.Get("purl"),
		Limit:      500,
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writePaginatedWithLegacyLimit(s, w, r, actor, "sbom-components", []string{"sbom_id", "release_id", "artifact_id", "query", "purl"}, true, components, func(component domain.SBOMComponentRecord, sort appquery.Sort) appquery.SortKey {
		return appquery.RecordSortKey(component.ID, time.Time{}, sort)
	})
}

func (s *Server) uploadVEX(w http.ResponseWriter, r *http.Request) {
	if s.vexIngestionCommands != nil {
		s.uploadDurableVEX(w, r, "openvex")
		return
	}
	if requestMediaType(r) == "application/vnd.openvex+json" {
		releaseID, err := requiredSingleHeader(r, "X-Evydence-Release-ID")
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		artifactID, err := optionalSingleHeader(r, "X-Evydence-Artifact-ID")
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		s.createStreamedEvidence(r.Context(), w, r, app.EvidenceDocumentLimit, map[string]string{
			"artifact_id": artifactID, "media_type": requestMediaType(r), "release_id": releaseID,
		}, func(s *Server, ctx requestContext, actor domain.Actor, source app.PayloadSource) (int, any, error) {
			vex, err := s.evidenceIngestion.UploadVEXPayload(ctx, actor, releaseID, artifactID, source)
			return http.StatusCreated, vex, err
		})
		return
	}
	var req struct {
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Payload    json.RawMessage `json:"payload"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		vex, err := s.evidenceIngestion.UploadVEX(ctx, actor, req.ReleaseID, req.ArtifactID, req.Payload)
		return http.StatusCreated, vex, err
	})
}

func (s *Server) previewVEXImport(w http.ResponseWriter, r *http.Request) {
	if s.vexPreviewQuery != nil {
		s.previewDurableVEX(w, r, "openvex")
		return
	}
	var req struct {
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Payload    json.RawMessage `json:"payload"`
	}
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	if err := decodeJSON(body, &req); err != nil {
		writeProblem(w, r, err)
		return
	}
	preview, err := s.evidenceIngestion.PreviewVEXImport(r.Context(), actor, req.ReleaseID, req.ArtifactID, req.Payload)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, preview)
}

func (s *Server) getVEX(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.vexPointQuery != nil {
		vex, err := s.vexPointQuery.GetVEXDocument(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			writeProblem(w, r, mapEvidencePointQueryError(err))
			return
		}
		writeData(w, http.StatusOK, vexDocumentFromQuery(vex))
		return
	}
	vex, err := s.evidenceIngestion.GetVEXDocument(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, vex)
}

func (s *Server) getVEXImportReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.vexPointQuery != nil {
		report, err := s.vexPointQuery.GetVEXImportReport(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			writeProblem(w, r, mapEvidencePointQueryError(err))
			return
		}
		writeData(w, http.StatusOK, vexImportReportFromQuery(report))
		return
	}
	report, err := s.evidenceIngestion.GetVEXImportReport(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) uploadCycloneDXVEX(w http.ResponseWriter, r *http.Request) {
	if s.vexIngestionCommands != nil {
		s.uploadDurableVEX(w, r, "cyclonedx")
		return
	}
	var req struct {
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Payload    json.RawMessage `json:"payload"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		vex, err := s.evidenceIngestion.UploadCycloneDXVEX(ctx, actor, req.ReleaseID, req.ArtifactID, req.Payload)
		return http.StatusCreated, vex, err
	})
}

func (s *Server) previewCycloneDXVEXImport(w http.ResponseWriter, r *http.Request) {
	if s.vexPreviewQuery != nil {
		s.previewDurableVEX(w, r, "cyclonedx")
		return
	}
	var req struct {
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Payload    json.RawMessage `json:"payload"`
	}
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	if err := decodeJSON(body, &req); err != nil {
		writeProblem(w, r, err)
		return
	}
	preview, err := s.evidenceIngestion.PreviewCycloneDXVEXImport(r.Context(), actor, req.ReleaseID, req.ArtifactID, req.Payload)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, preview)
}

func (s *Server) uploadVulnerabilityScan(w http.ResponseWriter, r *http.Request) {
	if s.scanIngestionCommands != nil {
		s.uploadDurableVulnerabilityScan(w, r)
		return
	}
	s.createStreamedEvidence(r.Context(), w, r, app.EvidenceDocumentLimit, nil, func(s *Server, ctx requestContext, actor domain.Actor, source app.PayloadSource) (int, any, error) {
		scan, err := s.evidenceIngestion.UploadVulnerabilityScanPayload(ctx, actor, source)
		return http.StatusCreated, scan, err
	})
}

func (s *Server) getVulnerabilityScan(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.vulnerabilityScanPointQuery != nil {
		scan, err := s.vulnerabilityScanPointQuery.GetVulnerabilityScan(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			writeProblem(w, r, mapEvidencePointQueryError(err))
			return
		}
		writeData(w, http.StatusOK, vulnerabilityScanFromQuery(scan))
		return
	}
	scan, err := s.evidenceIngestion.GetVulnerabilityScan(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, scan)
}

func (s *Server) createVulnerabilityDecision(w http.ResponseWriter, r *http.Request) {
	if s.vulnerabilityDecisionCommands != nil {
		s.createDurableVulnerabilityDecision(w, r)
		return
	}
	var req struct {
		Status          string              `json:"status"`
		Justification   string              `json:"justification"`
		ImpactStatement string              `json:"impact_statement"`
		ActionStatement string              `json:"action_statement"`
		CustomerVisible bool                `json:"customer_visible"`
		InternalNotes   string              `json:"internal_notes"`
		EvidenceIDs     []string            `json:"evidence_ids"`
		SupportingRefs  []domain.SubjectRef `json:"supporting_refs"`
		VEXDocumentID   string              `json:"vex_document_id"`
		ReviewedAt      *time.Time          `json:"reviewed_at"`
		ReviewDueAt     *time.Time          `json:"review_due_at"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		decision, err := s.riskDecisions.CreateVulnerabilityDecision(ctx, actor, r.PathValue("id"), app.CreateVulnerabilityDecisionInput{
			Status:          req.Status,
			Justification:   req.Justification,
			ImpactStatement: req.ImpactStatement,
			ActionStatement: req.ActionStatement,
			CustomerVisible: req.CustomerVisible,
			InternalNotes:   req.InternalNotes,
			EvidenceIDs:     req.EvidenceIDs,
			SupportingRefs:  req.SupportingRefs,
			VEXDocumentID:   req.VEXDocumentID,
			ReviewedAt:      req.ReviewedAt,
			ReviewDueAt:     req.ReviewDueAt,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, externalVulnerabilityDecision(decision), nil
	})
}

func (s *Server) listVulnerabilityDecisions(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.vulnerabilityDecisionQuery != nil {
		request, err := s.parsePageRequest(r, actor, "vulnerability-decisions", "product_id", "release_id", "vulnerability", "component", "status", "active")
		if err != nil {
			writeProblem(w, r, err)
			return
		}
		filter := riskquery.DecisionFilter{
			ProductID: r.URL.Query().Get("product_id"), ReleaseID: r.URL.Query().Get("release_id"),
			Vulnerability: r.URL.Query().Get("vulnerability"), Component: r.URL.Query().Get("component"), Status: r.URL.Query().Get("status"),
		}
		if filter.Status != "" {
			if _, err := riskdomain.ParseDecisionStatus(filter.Status); err != nil {
				writeProblem(w, r, app.ErrValidation)
				return
			}
		}
		if raw := r.URL.Query().Get("active"); raw != "" {
			active, err := strconv.ParseBool(raw)
			if err != nil {
				writeProblem(w, r, app.ErrValidation)
				return
			}
			filter.Active = &active
		}
		page, err := s.vulnerabilityDecisionQuery.ListPage(r.Context(), actor, filter, appquery.PageRequest{PageSize: request.pageSize, Sort: request.sort, Direction: request.direction}, request.after)
		if err != nil {
			writeProblem(w, r, mapControlsQueryError(err))
			return
		}
		mapped := appquery.Result[vulnerabilityDecisionResponse]{Next: page.Next, Items: make([]vulnerabilityDecisionResponse, 0, len(page.Items))}
		for _, item := range page.Items {
			mapped.Items = append(mapped.Items, externalRiskVulnerabilityDecision(item))
		}
		writePage(s, w, r, actor, "vulnerability-decisions", request, mapped)
		return
	}
	query := r.URL.Query()
	var active *bool
	if value := strings.TrimSpace(query.Get("active")); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		active = &parsed
	}
	decisions, err := s.riskDecisions.ListVulnerabilityDecisions(r.Context(), actor, app.ListVulnerabilityDecisionsInput{
		ProductID:     query.Get("product_id"),
		ReleaseID:     query.Get("release_id"),
		Vulnerability: query.Get("vulnerability"),
		Component:     query.Get("component"),
		Status:        query.Get("status"),
		Active:        active,
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	responses := make([]vulnerabilityDecisionResponse, 0, len(decisions))
	for _, decision := range decisions {
		responses = append(responses, externalVulnerabilityDecision(decision))
	}
	writeCreatedAtPaginated(s, w, r, actor, "vulnerability-decisions", []string{"product_id", "release_id", "vulnerability", "component", "status", "active"}, responses, func(decision vulnerabilityDecisionResponse) (string, time.Time) {
		return decision.ID, decision.CreatedAt
	})
}

// vulnerabilityDecisionResponse is the external projection of an append-only
// decision. Tenant-internal notes remain in the ledger for authorized internal
// workflows but never cross the HTTP response boundary or idempotency replay.
type vulnerabilityDecisionResponse struct {
	ID                string              `json:"id"`
	TenantID          string              `json:"tenant_id"`
	FindingID         string              `json:"finding_id"`
	ScanID            string              `json:"scan_id"`
	ReleaseID         string              `json:"release_id,omitempty"`
	Vulnerability     string              `json:"vulnerability"`
	Component         string              `json:"component,omitempty"`
	SBOMID            string              `json:"sbom_id,omitempty"`
	SBOMComponentPURL string              `json:"sbom_component_purl,omitempty"`
	SBOMComponentName string              `json:"sbom_component_name,omitempty"`
	Status            string              `json:"status"`
	Justification     string              `json:"justification"`
	ImpactStatement   string              `json:"impact_statement,omitempty"`
	ActionStatement   string              `json:"action_statement,omitempty"`
	CustomerVisible   bool                `json:"customer_visible"`
	Source            string              `json:"source"`
	EvidenceID        string              `json:"evidence_id,omitempty"`
	EvidenceIDs       []string            `json:"evidence_ids,omitempty"`
	SupportingRefs    []domain.SubjectRef `json:"supporting_refs,omitempty"`
	VEXDocumentID     string              `json:"vex_document_id,omitempty"`
	Supersedes        string              `json:"supersedes,omitempty"`
	SupersededBy      string              `json:"superseded_by,omitempty"`
	ApprovedBy        string              `json:"approved_by,omitempty"`
	ReviewedAt        *time.Time          `json:"reviewed_at,omitempty"`
	ReviewDueAt       *time.Time          `json:"review_due_at,omitempty"`
	SchemaVersion     string              `json:"schema_version"`
	CreatedAt         time.Time           `json:"created_at"`
}

func externalVulnerabilityDecision(decision domain.VulnerabilityDecision) vulnerabilityDecisionResponse {
	return vulnerabilityDecisionResponse{
		ID:                decision.ID,
		TenantID:          decision.TenantID,
		FindingID:         decision.FindingID,
		ScanID:            decision.ScanID,
		ReleaseID:         decision.ReleaseID,
		Vulnerability:     decision.Vulnerability,
		Component:         decision.Component,
		SBOMID:            decision.SBOMID,
		SBOMComponentPURL: decision.SBOMComponentPURL,
		SBOMComponentName: decision.SBOMComponentName,
		Status:            decision.Status,
		Justification:     decision.Justification,
		ImpactStatement:   decision.ImpactStatement,
		ActionStatement:   decision.ActionStatement,
		CustomerVisible:   decision.CustomerVisible,
		Source:            decision.Source,
		EvidenceID:        decision.EvidenceID,
		EvidenceIDs:       decision.EvidenceIDs,
		SupportingRefs:    decision.SupportingRefs,
		VEXDocumentID:     decision.VEXDocumentID,
		Supersedes:        decision.Supersedes,
		SupersededBy:      decision.SupersededBy,
		ApprovedBy:        decision.ApprovedBy,
		ReviewedAt:        decision.ReviewedAt,
		ReviewDueAt:       decision.ReviewDueAt,
		SchemaVersion:     decision.SchemaVersion,
		CreatedAt:         decision.CreatedAt,
	}
}

func (s *Server) recordVulnerabilityWorkflow(w http.ResponseWriter, r *http.Request) {
	if s.vulnerabilityWorkflowCommands != nil {
		s.recordDurableVulnerabilityWorkflow(w, r)
		return
	}
	var req struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		record, err := s.ledger.RecordVulnerabilityWorkflow(ctx, actor, app.RecordVulnerabilityWorkflowInput{FindingID: r.PathValue("id"), Action: req.Action, Reason: req.Reason})
		return http.StatusCreated, record, err
	})
}

func (s *Server) vulnerabilityPostureReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	releaseID, err := optionalSingletonQuery(r, "release_id")
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	if s.vulnerabilityPostureQuery != nil {
		report, err := s.vulnerabilityPostureQuery.Report(r.Context(), actor, releaseID)
		if err != nil {
			writeProblem(w, r, mapVulnerabilityPostureQueryError(err))
			return
		}
		writeData(w, http.StatusOK, vulnerabilityPostureFromQuery(report))
		return
	}
	report, err := s.ledger.VulnerabilityPostureReport(r.Context(), actor, releaseID)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) vulnerabilityDecisionSummaryReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	releaseID, err := optionalSingletonQuery(r, "release_id")
	if err != nil || releaseID == "" {
		writeProblem(w, r, app.ErrValidation)
		return
	}
	if s.vulnerabilityDecisionSummaryQuery != nil {
		report, err := s.vulnerabilityDecisionSummaryQuery.SummaryReport(r.Context(), actor, releaseID)
		if err != nil {
			writeProblem(w, r, mapControlsQueryError(err))
			return
		}
		writeData(w, http.StatusOK, decisionSummaryFromQuery(report))
		return
	}
	report, err := s.riskDecisions.VulnerabilityDecisionSummaryReport(r.Context(), actor, releaseID)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) uploadOpenAPIContract(w http.ResponseWriter, r *http.Request) {
	if s.openAPIIngestionCommands != nil {
		s.uploadDurableOpenAPIContract(w, r)
		return
	}
	if requestMediaType(r) == "application/vnd.oai.openapi+json" {
		productID, err := requiredSingleHeader(r, "X-Evydence-Product-ID")
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		releaseID, err := requiredSingleHeader(r, "X-Evydence-Release-ID")
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		version, err := requiredSingleHeader(r, "X-Evydence-Version")
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		s.createStreamedEvidence(r.Context(), w, r, app.EvidenceDocumentLimit, map[string]string{
			"media_type": requestMediaType(r), "product_id": productID, "release_id": releaseID, "version": version,
		}, func(s *Server, ctx requestContext, actor domain.Actor, source app.PayloadSource) (int, any, error) {
			contract, err := s.evidenceIngestion.UploadOpenAPIContractPayload(ctx, actor, productID, releaseID, version, source)
			return http.StatusCreated, contract, err
		})
		return
	}
	var req struct {
		ProductID string          `json:"product_id"`
		ReleaseID string          `json:"release_id"`
		Version   string          `json:"version"`
		Spec      json.RawMessage `json:"spec"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		contract, err := s.evidenceIngestion.UploadOpenAPIContract(ctx, actor, req.ProductID, req.ReleaseID, req.Version, req.Spec)
		return http.StatusCreated, contract, err
	})
}

func (s *Server) getOpenAPIContract(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.openAPIContractPointQuery != nil {
		contract, err := s.openAPIContractPointQuery.GetOpenAPIContract(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			writeProblem(w, r, mapEvidencePointQueryError(err))
			return
		}
		writeData(w, http.StatusOK, openAPIContractFromQuery(contract))
		return
	}
	contract, err := s.evidenceIngestion.GetOpenAPIContract(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, contract)
}

func (s *Server) createOpenAPIDiff(w http.ResponseWriter, r *http.Request) {
	if s.contractDiffCommands != nil {
		s.createDurableContractDiff(w, r)
		return
	}
	var req struct {
		BaseContractID   string `json:"base_contract_id"`
		TargetContractID string `json:"target_contract_id"`
		ReleaseID        string `json:"release_id"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		diff, err := s.evidenceIngestion.CreateContractDiff(ctx, actor, app.CreateContractDiffInput{BaseContractID: req.BaseContractID, TargetContractID: req.TargetContractID, ReleaseID: req.ReleaseID})
		return http.StatusCreated, diff, err
	})
}

func (s *Server) evaluatePolicy(w http.ResponseWriter, r *http.Request) {
	if s.policyEvaluationCommands != nil {
		s.evaluateDurablePolicy(w, r)
		return
	}
	var req struct {
		ReleaseID string `json:"release_id"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		eval, err := s.riskDecisions.EvaluateRelease(ctx, actor, req.ReleaseID)
		return http.StatusCreated, eval, err
	})
}

func (s *Server) createCustomPolicy(w http.ResponseWriter, r *http.Request) {
	if s.customPolicyCommands != nil {
		s.createDurableCustomPolicy(w, r)
		return
	}
	var req struct {
		Name        string              `json:"name"`
		Version     string              `json:"version"`
		Description string              `json:"description"`
		Rules       []domain.PolicyRule `json:"rules"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		policy, err := s.ledger.CreateCustomPolicy(ctx, actor, app.CreateCustomPolicyInput{Name: req.Name, Version: req.Version, Description: req.Description, Rules: req.Rules})
		return http.StatusCreated, policy, err
	})
}

func (s *Server) evaluateCustomPolicy(w http.ResponseWriter, r *http.Request) {
	if s.customPolicyCommands != nil {
		s.evaluateDurableCustomPolicy(w, r)
		return
	}
	var req struct {
		ReleaseID string `json:"release_id"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		eval, err := s.ledger.EvaluateCustomPolicy(ctx, actor, r.PathValue("id"), req.ReleaseID)
		return http.StatusCreated, eval, err
	})
}

func (s *Server) missingEvidenceReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.missingEvidenceQuery != nil {
		releaseID, err := optionalSingletonQuery(r, "release_id")
		if err != nil || releaseID == "" {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		report, err := s.missingEvidenceQuery.Report(r.Context(), actor, releaseID)
		if err != nil {
			writeProblem(w, r, mapMissingEvidenceQueryError(err))
			return
		}
		writeData(w, http.StatusOK, report)
		return
	}
	report, err := s.ledger.MissingEvidenceReport(r.Context(), actor, r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) createException(w http.ResponseWriter, r *http.Request) {
	if s.exceptionCommands != nil {
		s.createDurableException(w, r)
		return
	}
	var req struct {
		ReleaseID string    `json:"release_id"`
		FindingID string    `json:"finding_id"`
		ControlID string    `json:"control_id"`
		Reason    string    `json:"reason"`
		Owner     string    `json:"owner"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		exception, err := s.riskDecisions.CreateException(ctx, actor, app.CreateExceptionInput{
			ReleaseID: req.ReleaseID,
			FindingID: req.FindingID,
			ControlID: req.ControlID,
			Reason:    req.Reason,
			Owner:     req.Owner,
			ExpiresAt: req.ExpiresAt,
		})
		return http.StatusCreated, exception, err
	})
}

func (s *Server) listExceptions(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.exceptionsQuery != nil {
		request, err := s.parsePageRequest(r, actor, "exceptions", "release_id")
		if err != nil {
			writeProblem(w, r, err)
			return
		}
		page, err := s.exceptionsQuery.ListPage(r.Context(), actor, r.URL.Query().Get("release_id"), appquery.PageRequest{PageSize: request.pageSize, Sort: request.sort, Direction: request.direction}, request.after)
		if err != nil {
			writeProblem(w, r, mapControlsQueryError(err))
			return
		}
		mapped := appquery.Result[domain.Exception]{Next: page.Next, Items: make([]domain.Exception, 0, len(page.Items))}
		for _, item := range page.Items {
			mapped.Items = append(mapped.Items, exceptionFromQuery(item))
		}
		writePage(s, w, r, actor, "exceptions", request, mapped)
		return
	}
	exceptions, err := s.riskDecisions.ListExceptions(r.Context(), actor, r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "exceptions", []string{"release_id"}, exceptions, func(exception domain.Exception) (string, time.Time) {
		return exception.ID, exception.CreatedAt
	})
}

func (s *Server) approveException(w http.ResponseWriter, r *http.Request) {
	if s.exceptionCommands != nil {
		s.approveDurableException(w, r)
		return
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, _ []byte) (int, any, error) {
		exception, err := s.riskDecisions.ApproveException(ctx, actor, r.PathValue("id"))
		return http.StatusOK, exception, err
	})
}

func (s *Server) releaseReadinessReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.releaseReadinessReportQuery != nil {
		releaseID, err := optionalSingletonQuery(r, "release_id")
		if err != nil || releaseID == "" {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		report, err := s.releaseReadinessReportQuery.Report(r.Context(), actor, releaseID)
		if err != nil {
			writeProblem(w, r, mapReleaseReadinessReportQueryError(err))
			return
		}
		writeData(w, http.StatusOK, releaseReadinessReportFromQuery(report))
		return
	}
	report, err := s.packages.ReleaseReadinessReport(r.Context(), actor, r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) controlCoverageReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.controlCoverageQuery != nil {
		filter, err := controlReportFilters(r, false)
		if err != nil {
			writeProblem(w, r, err)
			return
		}
		report, err := s.controlCoverageQuery.Coverage(r.Context(), actor, filter)
		if err != nil {
			writeProblem(w, r, mapControlCoverageQueryError(err))
			return
		}
		writeData(w, http.StatusOK, controlCoverageFromQuery(report))
		return
	}
	report, err := s.ledger.ControlCoverageReport(r.Context(), actor, app.ControlCoverageReportInput{
		FrameworkID: r.URL.Query().Get("framework_id"),
		ProductID:   r.URL.Query().Get("product_id"),
		ReleaseID:   r.URL.Query().Get("release_id"),
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) craReadinessReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.controlCoverageQuery != nil {
		filter, err := controlReportFilters(r, true)
		if err != nil {
			writeProblem(w, r, err)
			return
		}
		report, err := s.controlCoverageQuery.CRAReadiness(r.Context(), actor, filter.ProductID, filter.ReleaseID)
		if err != nil {
			writeProblem(w, r, mapControlCoverageQueryError(err))
			return
		}
		writeData(w, http.StatusOK, craReadinessFromQuery(report))
		return
	}
	report, err := s.ledger.CRAReadinessReport(r.Context(), actor, app.CRAReadinessReportInput{
		ProductID: r.URL.Query().Get("product_id"),
		ReleaseID: r.URL.Query().Get("release_id"),
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) craVulnerabilityHandlingReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.craVulnerabilityQuery != nil {
		productID, releaseID, err := releaseReportFilters(r)
		if err != nil {
			writeProblem(w, r, err)
			return
		}
		report, err := s.craVulnerabilityQuery.Report(r.Context(), actor, productID, releaseID)
		if err != nil {
			writeProblem(w, r, mapCRAVulnerabilityQueryError(err))
			return
		}
		writeData(w, http.StatusOK, craVulnerabilityFromQuery(report))
		return
	}
	report, err := s.ledger.CRAVulnerabilityHandlingReport(r.Context(), actor, r.URL.Query().Get("product_id"), r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) securityUpdateEvidenceReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.securityUpdateEvidenceQuery != nil {
		productID, releaseID, err := releaseReportFilters(r)
		if err != nil {
			writeProblem(w, r, err)
			return
		}
		report, err := s.securityUpdateEvidenceQuery.Report(r.Context(), actor, productID, releaseID)
		if err != nil {
			writeProblem(w, r, mapSecurityUpdateQueryError(err))
			return
		}
		writeData(w, http.StatusOK, securityUpdateFromQuery(report))
		return
	}
	report, err := s.ledger.SecurityUpdateEvidenceReport(r.Context(), actor, r.URL.Query().Get("product_id"), r.URL.Query().Get("release_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) createReleaseBundle(w http.ResponseWriter, r *http.Request) {
	s.createReleaseBundleCommand(w, r)
}

func (s *Server) getReleaseBundle(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.releaseBundleQuery != nil {
		bundle, err := s.releaseBundleQuery.GetReleaseBundle(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			writeProblem(w, r, mapReleaseBundleQueryError(err))
			return
		}
		writeData(w, http.StatusOK, releaseBundleFromQuery(bundle))
		return
	}
	bundle, err := s.ledger.GetReleaseBundle(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, bundle)
}

func (s *Server) getReleaseBundleManifest(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.releaseBundleQuery != nil {
		bundle, err := s.releaseBundleQuery.GetReleaseBundle(r.Context(), actor, r.PathValue("id"))
		if err != nil {
			writeProblem(w, r, mapReleaseBundleQueryError(err))
			return
		}
		writeData(w, http.StatusOK, bundle.Manifest)
		return
	}
	bundle, err := s.ledger.GetReleaseBundle(r.Context(), actor, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, bundle.Manifest)
}

func (s *Server) verifyReleaseBundle(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	result, err := s.verifyReleaseBundleResult(r.Context(), actor, r.PathValue("id"))
	if err != nil && !errors.Is(err, app.ErrVerificationFailed) {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, result)
}

func (s *Server) verifyAuditChain(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.auditChainVerification != nil {
		result, err := s.auditChainVerification.VerifyAuditChain(r.Context(), actor)
		err = mapVerificationCommandError(err)
		if err != nil && !errors.Is(err, app.ErrVerificationFailed) {
			writeProblem(w, r, err)
			return
		}
		writeData(w, http.StatusOK, verificationResultFromFocused(result))
		return
	}
	result, err := s.verification.VerifySubject(r.Context(), actor, "audit_chain", "")
	if err != nil && !errors.Is(err, app.ErrVerificationFailed) {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, result)
}

func (s *Server) listAuditLog(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	var pageRequest pageRequest
	if s.auditLogQuery != nil {
		var err error
		pageRequest, err = s.parsePageRequestWithLegacyLimit(r, actor, "audit-log", true, "subject_type", "subject_id", "since")
		if err != nil {
			writeProblem(w, r, err)
			return
		}
	}
	var since *time.Time
	if value := strings.TrimSpace(r.URL.Query().Get("since")); value != "" {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		since = &parsed
	}
	if s.auditLogQuery != nil {
		result, err := s.auditLogQuery.ListPage(r.Context(), actor, verificationquery.AuditFilter{
			SubjectType: r.URL.Query().Get("subject_type"), SubjectID: r.URL.Query().Get("subject_id"), Since: since,
		}, appquery.PageRequest{PageSize: pageRequest.pageSize, Sort: pageRequest.sort, Direction: pageRequest.direction}, pageRequest.after)
		if err != nil {
			switch {
			case errors.Is(err, verificationquery.ErrValidation), errors.Is(err, appquery.ErrInvalidPage), errors.Is(err, appquery.ErrInvalidCursor):
				err = app.ErrValidation
			case errors.Is(err, application.ErrUnauthorized):
				err = app.ErrUnauthorized
			case errors.Is(err, application.ErrForbidden):
				err = app.ErrForbidden
			}
			writeProblem(w, r, err)
			return
		}
		page := appquery.Result[domain.AuditChainEntry]{Next: result.Next, Items: make([]domain.AuditChainEntry, 0, len(result.Items))}
		for _, entry := range result.Items {
			page.Items = append(page.Items, auditChainEntryFromQuery(entry))
		}
		writePage(s, w, r, actor, "audit-log", pageRequest, page)
		return
	}
	entries, err := s.ledger.ListAuditLog(r.Context(), actor, app.AuditLogFilter{
		SubjectType: r.URL.Query().Get("subject_type"),
		SubjectID:   r.URL.Query().Get("subject_id"),
		Since:       since,
		Limit:       500,
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginatedWithLegacyLimit(s, w, r, actor, "audit-log", []string{"subject_type", "subject_id", "since"}, entries, func(entry domain.AuditChainEntry) (string, time.Time) {
		return entry.ID, entry.OccurredAt
	})
}

func (s *Server) verifyMerkleBatch(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.merkleVerification != nil {
		result, err := s.merkleVerification.VerifyMerkleBatch(r.Context(), actor, r.PathValue("id"))
		err = mapVerificationCommandError(err)
		if err != nil && !errors.Is(err, app.ErrVerificationFailed) {
			writeProblem(w, r, err)
			return
		}
		writeData(w, http.StatusOK, verificationResultFromFocused(result))
		return
	}
	result, err := s.verification.VerifyMerkleBatch(r.Context(), actor, r.PathValue("id"))
	if err != nil && !errors.Is(err, app.ErrVerificationFailed) {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, result)
}

func (s *Server) signingCustodyReviewReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		writeProblem(w, r, app.ErrValidation)
		return
	}
	if s.signingCustodyQuery != nil {
		report, err := s.signingCustodyQuery.Report(r.Context(), actor)
		if err != nil {
			writeProblem(w, r, mapSigningCustodyQueryError(err))
			return
		}
		writeData(w, http.StatusOK, domain.SigningCustodyReviewFromContextModel(report))
		return
	}
	report, err := s.verification.SigningCustodyReviewReport(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

func (s *Server) verifyBackupManifest(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.backupVerification != nil {
		result, err := s.backupVerification.VerifyBackupManifest(r.Context(), actor, r.PathValue("id"))
		mapped := mapVerificationCommandError(err)
		if mapped != nil && !errors.Is(mapped, app.ErrVerificationFailed) {
			writeProblem(w, r, mapped)
			return
		}
		writeData(w, http.StatusOK, verificationResultFromFocused(result))
		return
	}
	result, err := s.verification.VerifyBackupManifest(r.Context(), actor, r.PathValue("id"))
	if err != nil && !errors.Is(err, app.ErrVerificationFailed) {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, result)
}

func (s *Server) listSigningKeys(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.signingKeyQuery != nil {
		request, err := s.parsePageRequest(r, actor, "signing-keys")
		if err != nil {
			writeProblem(w, r, err)
			return
		}
		result, err := s.signingKeyQuery.ListPage(r.Context(), actor, appquery.PageRequest{PageSize: request.pageSize, Sort: request.sort, Direction: request.direction}, request.after)
		if err != nil {
			writeProblem(w, r, mapSigningKeyQueryError(err))
			return
		}
		page := appquery.Result[domain.SigningKey]{Next: result.Next, Items: make([]domain.SigningKey, 0, len(result.Items))}
		for _, key := range result.Items {
			page.Items = append(page.Items, signingKeyFromQuery(key))
		}
		writePage(s, w, r, actor, "signing-keys", request, page)
		return
	}
	keys, err := s.verification.ListSigningKeys(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "signing-keys", nil, keys, func(key domain.SigningKey) (string, time.Time) {
		return key.ID, key.CreatedAt
	})
}

func (s *Server) createCommercialCollector(w http.ResponseWriter, r *http.Request) {
	if s.collectorCommands != nil {
		s.createDurableCommercialCollector(w, r)
		return
	}
	var req struct {
		Name          string   `json:"name"`
		Provider      string   `json:"provider"`
		Version       string   `json:"version"`
		ManifestHash  string   `json:"manifest_hash"`
		AllowedScopes []string `json:"allowed_scopes"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		definition, err := s.ledger.CreateCommercialCollectorDefinition(ctx, actor, app.CreateCommercialCollectorInput{
			Name:          req.Name,
			Provider:      req.Provider,
			Version:       req.Version,
			ManifestHash:  req.ManifestHash,
			AllowedScopes: req.AllowedScopes,
		})
		return http.StatusCreated, definition, err
	})
}

func (s *Server) listCommercialCollectors(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.commercialCollectorQuery != nil {
		request, err := s.parsePageRequest(r, actor, "commercial-collectors")
		if err != nil {
			writeProblem(w, r, err)
			return
		}
		result, err := s.commercialCollectorQuery.ListPage(r.Context(), actor, appquery.PageRequest{PageSize: request.pageSize, Sort: request.sort, Direction: request.direction}, request.after)
		if err != nil {
			writeProblem(w, r, mapCommercialCollectorQueryError(err))
			return
		}
		page := appquery.Result[domain.CommercialCollectorDefinition]{Next: result.Next, Items: make([]domain.CommercialCollectorDefinition, 0, len(result.Items))}
		for _, definition := range result.Items {
			page.Items = append(page.Items, commercialCollectorFromQuery(definition))
		}
		writePage(s, w, r, actor, "commercial-collectors", request, page)
		return
	}
	definitions, err := s.ledger.ListCommercialCollectorDefinitions(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "commercial-collectors", nil, definitions, func(definition domain.CommercialCollectorDefinition) (string, time.Time) {
		return definition.ID, definition.CreatedAt
	})
}

func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	if s.apiKeyCommands != nil {
		s.createDurableAPIKey(w, r)
		return
	}
	var req struct {
		Name      string     `json:"name"`
		Scopes    []string   `json:"scopes"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	s.create(w, r, func(s *Server, ctx requestContext, actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		key, secret, err := s.identityAccess.CreateAPIKey(ctx, actor, req.Name, req.Scopes, req.ExpiresAt)
		return http.StatusCreated, map[string]any{"api_key": key, "secret": secret}, err
	})
}

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.apiKeyQuery != nil {
		request, err := s.parsePageRequest(r, actor, "api-keys")
		if err != nil {
			writeProblem(w, r, err)
			return
		}
		result, err := s.apiKeyQuery.ListPage(r.Context(), actor, appquery.PageRequest{PageSize: request.pageSize, Sort: request.sort, Direction: request.direction}, request.after)
		if err != nil {
			switch {
			case errors.Is(err, identityquery.ErrValidation), errors.Is(err, appquery.ErrInvalidPage), errors.Is(err, appquery.ErrInvalidCursor):
				err = app.ErrValidation
			case errors.Is(err, application.ErrUnauthorized):
				err = app.ErrUnauthorized
			case errors.Is(err, application.ErrForbidden):
				err = app.ErrForbidden
			}
			writeProblem(w, r, err)
			return
		}
		page := appquery.Result[domain.APIKey]{Next: result.Next, Items: make([]domain.APIKey, 0, len(result.Items))}
		for _, key := range result.Items {
			page.Items = append(page.Items, apiKeyFromQuery(key))
		}
		writePage(s, w, r, actor, "api-keys", request, page)
		return
	}
	keys, err := s.identityAccess.ListAPIKeys(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeCreatedAtPaginated(s, w, r, actor, "api-keys", nil, keys, func(key domain.APIKey) (string, time.Time) {
		return key.ID, key.CreatedAt
	})
}

func (s *Server) create(w http.ResponseWriter, r *http.Request, run func(*Server, requestContext, domain.Actor, []byte) (int, any, error)) {
	s.createWithLimit(w, r, app.SmallJSONRequestLimit, run)
}

func (s *Server) createWithLimit(w http.ResponseWriter, r *http.Request, limit int64, run func(*Server, requestContext, domain.Actor, []byte) (int, any, error)) {
	s.createWithFingerprint(w, r, limit, run, nil)
}

func (s *Server) createWithFingerprint(w http.ResponseWriter, r *http.Request, limit int64, run func(*Server, requestContext, domain.Actor, []byte) (int, any, error), fingerprint func(*http.Request, []byte) ([]byte, error)) {
	var actorFingerprint func(*http.Request, domain.Actor, []byte) ([]byte, error)
	if fingerprint != nil {
		actorFingerprint = func(r *http.Request, _ domain.Actor, body []byte) ([]byte, error) { return fingerprint(r, body) }
	}
	s.createWithActorFingerprint(w, r, limit, run, actorFingerprint)
}

func (s *Server) createWithActorFingerprint(w http.ResponseWriter, r *http.Request, limit int64, run func(*Server, requestContext, domain.Actor, []byte) (int, any, error), fingerprint func(*http.Request, domain.Actor, []byte) ([]byte, error)) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	body, err := readBodyLimit(r, limit)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	input := body
	if fingerprint != nil {
		input, err = fingerprint(r, actor, body)
		if err != nil {
			writeProblem(w, r, err)
			return
		}
	}
	status, response, err := s.idempotency.WithBody(ctx, actor, r.Method, r.URL.Path, r.Header.Get("Idempotency-Key"), input, func(commandCtx context.Context, scope commandScope) (int, any, error) {
		commandServer := *s
		scope.bind(&commandServer)
		return run(&commandServer, commandCtx, actor, body)
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	if r.Header.Get("Idempotency-Key") != "" {
		w.Header().Set("Idempotency-Key", r.Header.Get("Idempotency-Key"))
	}
	writeData(w, status, response)
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (domain.Actor, bool) {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	if authHeader == "" {
		if cookie, err := r.Cookie(ssoSessionCookieName); err == nil {
			token = strings.TrimSpace(cookie.Value)
		}
	}
	actor, err := s.authn.Authenticate(r.Context(), token)
	if err != nil {
		switch {
		case errors.Is(err, identityapp.ErrUnauthorized):
			err = app.ErrUnauthorized
		case errors.Is(err, identityapp.ErrForbidden):
			err = app.ErrForbidden
		}
		writeProblem(w, r, err)
		return domain.Actor{}, false
	}
	if !s.allowExpensiveTenantRequest(actor, r) {
		writeProblem(w, r, app.ErrRateLimited)
		return domain.Actor{}, false
	}
	return actor, true
}

func readBody(r *http.Request) ([]byte, error) {
	return readBodyLimit(r, app.SmallJSONRequestLimit)
}

func readBodyLimit(r *http.Request, limit int64) ([]byte, error) {
	if r == nil || r.Body == nil || limit <= 0 || r.ContentLength > limit {
		return nil, app.NewValidationError(app.FieldViolation{Field: "/body", Code: "invalid_size"})
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, app.NewValidationError(app.FieldViolation{Field: "/body", Code: "unreadable"})
	}
	if int64(len(body)) > limit {
		return nil, app.NewValidationError(app.FieldViolation{Field: "/body", Code: "too_large"})
	}
	return body, nil
}

func decodeJSON(body []byte, out any) error {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		trimmed = []byte(`{}`)
	}
	if err := jsonbounds.Validate(trimmed, jsonbounds.DefaultLimits()); err != nil {
		return app.NewValidationError()
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return jsonValidationError(err)
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return app.NewValidationError()
	}
	return nil
}

func jsonValidationError(err error) error {
	var typeError *json.UnmarshalTypeError
	if errors.As(err, &typeError) {
		return app.NewValidationError(app.FieldViolation{Field: jsonFieldPointer(typeError.Field), Code: "invalid_type"})
	}
	const unknownFieldPrefix = "json: unknown field "
	if raw := strings.TrimPrefix(err.Error(), unknownFieldPrefix); raw != err.Error() {
		if field, unquoteErr := strconv.Unquote(raw); unquoteErr == nil {
			return app.NewValidationError(app.FieldViolation{Field: jsonFieldPointer(field), Code: "unknown_field"})
		}
	}
	return app.NewValidationError()
}

func jsonFieldPointer(field string) string {
	field = strings.TrimSpace(field)
	if field == "" {
		return ""
	}
	parts := strings.Split(field, ".")
	for index, part := range parts {
		parts[index] = strings.ReplaceAll(strings.ReplaceAll(part, "~", "~0"), "/", "~1")
	}
	return "/" + strings.Join(parts, "/")
}

func parseOptionalRFC3339(value string) (time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return time.Time{}, app.ErrValidation
	}
	return parsed, nil
}

func expectedRevisionFromIfMatch(r *http.Request) (int64, error) {
	if r == nil || len(r.Header.Values("If-Match")) != 1 {
		return 0, app.ErrValidation
	}
	raw := strings.TrimSpace(r.Header.Get("If-Match"))
	if len(raw) < 3 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return 0, app.ErrValidation
	}
	value := raw[1 : len(raw)-1]
	revision, err := strconv.ParseInt(value, 10, 64)
	if err != nil || revision < 1 || strconv.FormatInt(revision, 10) != value {
		return 0, app.ErrValidation
	}
	return revision, nil
}

func writeData(w http.ResponseWriter, status int, data any) {
	httpx.WriteJSON(w, status, map[string]any{"data": data, "meta": map[string]string{"api_version": "v1"}})
}

func writeArchive(w http.ResponseWriter, archive app.CustomerPackageArchive) {
	w.Header().Set("Content-Type", archive.MediaType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+archive.Filename+`"`)
	w.Header().Set("Content-Length", strconv.FormatInt(archive.Size, 10))
	w.Header().Set("X-Evydence-Archive-Hash", archive.Hash)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(archive.Bytes)
}

func writeProblem(w http.ResponseWriter, r *http.Request, err error) {
	details := app.DescribeProblem(err)
	status := details.Status
	requestID := requestIDFromRequest(r)
	w.Header().Set(requestIDHeader, requestID)
	if details.RetryAfterSeconds > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(details.RetryAfterSeconds))
	}
	problem := httpx.Problem{
		Type:   "https://evydence.local/problems/" + strings.ToLower(strings.ReplaceAll(string(details.Code), "_", "-")),
		Title:  http.StatusText(status),
		Detail: details.Detail,
		Ext: map[string]any{
			"code":        details.Code,
			"request_id":  requestID,
			"retryable":   details.Retryable,
			"retry_class": details.RetryClass,
		},
	}
	if details.RetryAfterSeconds > 0 {
		problem.Ext["retry_after_seconds"] = details.RetryAfterSeconds
	}
	if len(details.Violations) > 0 {
		problem.Ext["violations"] = details.Violations
	}
	if revision, ok := app.CurrentRevision(err); ok {
		problem.Ext["current_revision"] = revision
	}
	if r != nil {
		problem.Instance = r.URL.Path
	}
	httpx.WriteProblem(w, status, problem)
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := strings.TrimSpace(r.Header.Get(requestIDHeader))
		if !safeRequestID(requestID) {
			requestID = newRequestID()
		}
		r.Header.Set(requestIDHeader, requestID)
		w.Header().Set(requestIDHeader, requestID)
		next.ServeHTTP(w, r)
	})
}

func requestIDFromRequest(r *http.Request) string {
	if r == nil {
		return newRequestID()
	}
	requestID := strings.TrimSpace(r.Header.Get(requestIDHeader))
	if safeRequestID(requestID) {
		return requestID
	}
	return newRequestID()
}

func newRequestID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "req_unavailable"
	}
	return "req_" + hex.EncodeToString(buf[:])
}

func safeRequestID(value string) bool {
	if len(value) < 3 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == ':' {
			continue
		}
		return false
	}
	return true
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

type serveMuxRouter struct {
	mux *http.ServeMux
}

func (r *serveMuxRouter) Get(pattern string, h http.HandlerFunc) {
	r.mux.HandleFunc("GET "+pattern, h)
}

func (r *serveMuxRouter) Post(pattern string, h http.HandlerFunc) {
	r.mux.HandleFunc("POST "+pattern, h)
}

func (r *serveMuxRouter) Put(pattern string, h http.HandlerFunc) {
	r.mux.HandleFunc("PUT "+pattern, h)
}

func (r *serveMuxRouter) Delete(pattern string, h http.HandlerFunc) {
	r.mux.HandleFunc("DELETE "+pattern, h)
}

func (r *serveMuxRouter) Patch(pattern string, h http.HandlerFunc) {
	r.mux.HandleFunc("PATCH "+pattern, h)
}

func op(id, method, path, summary string, scopes []string) specs.Operation {
	successStatus := defaultSuccessStatus(id, method)
	operation := specs.Operation{
		OperationID: id,
		Method:      method,
		Path:        path,
		Summary:     summary,
		Tags:        []string{"evydence"},
		Responses: map[int]specs.Response{
			successStatus: {Description: summary + " response"},
			400:           {Description: "Bad request"},
			401:           {Description: "Unauthorized"},
			403:           {Description: "Forbidden"},
			404:           {Description: "Not found"},
			409:           {Description: "Conflict"},
			422:           {Description: "Verification failed"},
		},
	}
	if len(scopes) > 0 {
		operation.Security = []specs.SecurityRequirement{{Name: "BearerAuth"}}
		operation.Scopes = scopes
	}
	if method == http.MethodPost {
		operation.Extensions = withStability(id, idempotent.OperationExtensions(true))
	} else {
		operation.Extensions = withStability(id, nil)
	}
	return withCriticalOperationDetails(operation)
}

func authenticatedOp(id, method, path, summary string) specs.Operation {
	operation := op(id, method, path, summary, nil)
	operation.Security = []specs.SecurityRequirement{{Name: "BearerAuth"}}
	return operation
}

func readOnlyPostOp(id, method, path, summary string, scopes []string) specs.Operation {
	operation := op(id, method, path, summary, scopes)
	operation.Extensions = withStability(id, idempotent.OperationExtensions(false))
	return operation
}

func publicPostOp(id, method, path, summary string) specs.Operation {
	operation := op(id, method, path, summary, nil)
	operation.Security = nil
	operation.Scopes = nil
	operation.Extensions = withStability(id, nil)
	return operation
}

func withStability(operationID string, extensions map[string]any) map[string]any {
	result := make(map[string]any, len(extensions)+1)
	for name, value := range extensions {
		result[name] = value
	}
	result["x-evydence-stability"] = stabilityForOperation(operationID)
	return result
}

func stabilityForOperation(operationID string) string {
	switch operationID {
	case "createProduct", "listProducts", "getProduct",
		"createProject", "getProject",
		"createRelease", "getRelease", "startReleaseEvidenceFlow",
		"freezeRelease", "approveRelease",
		"registerArtifact", "getArtifact",
		"createBuild", "getBuild", "uploadBuildAttestation",
		"createEvidence", "getEvidence", "listEvidence", "linkEvidence",
		"uploadSBOM", "uploadSPDXSBOM", "getSBOM", "listSBOMComponents",
		"uploadVulnerabilityScan", "getVulnerabilityScan",
		"uploadVEX", "uploadCycloneDXVEX", "getVEX",
		"createVulnerabilityDecision", "listVulnerabilityDecisions",
		"createException", "approveException", "createApproval",
		"releaseReadinessReport", "releaseSecuritySummary",
		"createReleaseBundle", "getReleaseBundle", "getReleaseBundleManifest",
		"verifyReleaseBundle", "createCustomerPackage", "getCustomerPackage",
		"downloadCustomerPackage", "verify":
		return "core"
	case "health", "ready", "version", "openapi", "metrics",
		"createAPIKey", "listAPIKeys", "exchangeSSOCredential",
		"logoutSSOSession", "createCustomerPortalAccess",
		"accessCustomerPortalPackage", "downloadCustomerPortalPackage":
		return "supported"
	default:
		return "experimental"
	}
}

func defaultSuccessStatus(operationID, method string) int {
	if method == http.MethodGet {
		return http.StatusOK
	}
	if method != http.MethodPost {
		return http.StatusOK
	}
	switch operationID {
	case "deactivateUser",
		"logoutSSOSession",
		"revokeSSOSession",
		"refreshSSOProviderOIDCTrustMaterial",
		"updateSSOProviderTrustMaterial",
		"freezeRelease",
		"approveRelease",
		"promoteReleaseCandidate",
		"rejectReleaseCandidate",
		"verifyCosignSignature",
		"verifyBuildAttestationSignature",
		"previewVEXImport",
		"previewCycloneDXVEXImport",
		"approveWaiver",
		"accessCustomerPortalPackage",
		"downloadCustomerPortalPackage",
		"customerPortalPackageView",
		"downloadCustomerPortalPackageView",
		"revokeCustomerPortalAccess",
		"approveException",
		"verifyObjectRetentionPolicy",
		"verifyPublicTransparencyLogEntry",
		"fetchPublicTransparencyLogEntryProof",
		"revokeSigningKey",
		"verify":
		return http.StatusOK
	default:
		return http.StatusCreated
	}
}
