package httpapi

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
)

// authenticator is the transport's identity-verification boundary. Keeping it
// separate from the identity administration surface makes authentication an
// explicit dependency of every protected route.
type authenticator interface {
	Authenticate(context.Context, string) (domain.Actor, error)
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

var (
	_ authenticator            = (*app.Ledger)(nil)
	_ idempotencyExecutor      = ledgerIdempotencyExecutor{}
	_ identityAccessService    = (*app.Ledger)(nil)
	_ releaseCatalogService    = (*app.Ledger)(nil)
	_ evidenceIngestionService = (*app.Ledger)(nil)
)
