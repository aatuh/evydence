package httpapi

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
)

// Constructor-only dependencies: promoted methods are deliberately unusable.
// No business or authentication claim is inferred from these stubs.
type nativeConstructorExecutor struct {
	DurableCommandExecutor
	DurableStreamedCommandExecutor
	DurableReplayCommandExecutor
}

func nativeConstructorOptions() ServerOptions {
	return ServerOptions{
		PaginationSecret:             []byte("native-constructor-stable-test-key"),
		Authenticator:                &struct{ Authenticator }{},
		APIKeyCommands:               &struct{ APIKeyCommands }{},
		MembershipCommands:           &struct{ MembershipCommands }{},
		RoleBindingCommands:          &struct{ RoleBindingCommands }{},
		SSOProviderCommands:          &struct{ SSOProviderCommands }{},
		SSOIdentityLinkCommands:      &struct{ SSOIdentityLinkCommands }{},
		SSOSessionCommands:           &struct{ SSOSessionCommands }{},
		SSOSessionRevocationCommands: &struct{ SSOSessionRevocationCommands }{},
		SSOExchangeCommands:          &struct{ SSOExchangeCommands }{},
		ProviderVerificationCommands: &struct{ ProviderVerificationCommands }{},
		EvidenceSummaryCommands:      &struct{ EvidenceSummaryCommands }{},
		GraphSnapshotCommands:        &struct{ GraphSnapshotCommands }{},
		PDFReportCommands:            &struct{ PDFReportCommands }{},
		AnomalyReportCommands:        &struct{ AnomalyReportCommands }{},
		SigningOperationCommands:     &struct{ SigningOperationCommands }{},
		SaaSProfileCommands:          &struct{ SaaSProfileCommands }{},
		MarketplaceCollectorCommands: &struct{ MarketplaceCollectorCommands }{},
		PublicTransparencyMetadataCommands: &struct {
			PublicTransparencyMetadataCommands
		}{},
		PublicTransparencyProofCommands: &struct {
			PublicTransparencyProofCommands
		}{},
		PublicTransparencyFetchCommands: &struct {
			PublicTransparencyFetchCommands
		}{},
		QuestionnaireDraftCommands:    &struct{ QuestionnaireDraftCommands }{},
		QuestionnairePackageCommands:  &struct{ QuestionnairePackageCommands }{},
		PortalAccessCommands:          &struct{ PortalAccessCommands }{},
		PortalTokenCommands:           &struct{ PortalTokenCommands }{},
		QuestionnaireTemplateCommands: &struct{ QuestionnaireTemplateCommands }{},
		RedactionProfileCommands:      &struct{ RedactionProfileCommands }{},
		AnswerLibraryCommands:         &struct{ AnswerLibraryCommands }{},
		ReadinessQuery:                &struct{ ReadinessQuery }{},
		MetricsQuery:                  &struct{ MetricsQuery }{},
		RetentionQuery:                &struct{ RetentionQuery }{},
		IncidentReportQuery:           &struct{ IncidentReportQuery }{},
		SecurityUpdateEvidenceQuery:   &struct{ SecurityUpdateEvidenceQuery }{},
		CRAVulnerabilityQuery:         &struct{ CRAVulnerabilityQuery }{},
		MissingEvidenceQuery:          &struct{ MissingEvidenceQuery }{},
		ReleaseReadinessReportQuery:   &struct{ ReleaseReadinessReportQuery }{},
		CustomerPackageAccessCommands: &struct{ CustomerPackageAccessCommands }{},
		CustomerPackageCreationCommands: &struct {
			CustomerPackageCreationCommands
		}{},
		HTMLReportCommands:            &struct{ HTMLReportCommands }{},
		ReportTemplateCommands:        &struct{ ReportTemplateCommands }{},
		BundleImportCommand:           &struct{ BundleImportCommand }{},
		ReleaseBundleCommands:         &struct{ ReleaseBundleCommands }{},
		EvidenceBundleCommands:        &struct{ EvidenceBundleCommands }{},
		SigningKeyCommands:            &struct{ SigningKeyCommands }{},
		ReleaseBundleVerification:     &struct{ ReleaseBundleVerification }{},
		EvidenceVerification:          &struct{ EvidenceVerification }{},
		DSSEVerification:              &struct{ DSSEVerification }{},
		CosignVerification:            &struct{ CosignVerification }{},
		ArtifactSignatureVerification: &struct{ ArtifactSignatureVerification }{},
		MerkleVerification:            &struct{ MerkleVerification }{},
		AuditChainVerification:        &struct{ AuditChainVerification }{},
		MerkleCheckpointVerification:  &struct{ MerkleCheckpointVerification }{},
		ReleaseManifestCheckpoint:     &struct{ ReleaseManifestCheckpoint }{},
		BackupVerification:            &struct{ BackupVerification }{},
		BackupGenerationCommands:      &struct{ BackupGenerationCommands }{},
		ArtifactSignatureCommands:     &struct{ ArtifactSignatureCommands }{},
		BuildAttestationCommands:      &struct{ BuildAttestationCommands }{},
		BuildCommands:                 &struct{ BuildCommands }{},
		ContainerImageCommands:        &struct{ ContainerImageCommands }{},
		ArtifactCommands:              &struct{ ArtifactCommands }{},
		ProductCommands:               &struct{ ProductCommands }{},
		ProjectCommands:               &struct{ ProjectCommands }{},
		ReleaseCreationCommands:       &struct{ ReleaseCreationCommands }{},
		ReleaseStateCommands:          &struct{ ReleaseStateCommands }{},
		CandidateStateCommands:        &struct{ CandidateStateCommands }{},
		CandidateCommands:             &struct{ CandidateCommands }{},
		ControlCommands:               &struct{ ControlCommands }{},
		ControlTemplateCommands:       &struct{ ControlTemplateCommands }{},
		ControlEvidenceCommands:       &struct{ ControlEvidenceCommands }{},
		VulnerabilityDecisionCommands: &struct{ VulnerabilityDecisionCommands }{},
		ApprovalCommands:              &struct{ ApprovalCommands }{},
		WaiverCommands:                &struct{ WaiverCommands }{},
		ExceptionCommands:             &struct{ ExceptionCommands }{},
		VulnerabilityWorkflowCommands: &struct{ VulnerabilityWorkflowCommands }{},
		CustomPolicyCommands:          &struct{ CustomPolicyCommands }{},
		PolicyEvaluationCommands:      &struct{ PolicyEvaluationCommands }{},
		SBOMDiffCommands:              &struct{ SBOMDiffCommands }{},
		ContractDiffCommands:          &struct{ ContractDiffCommands }{},
		DurableCommandExecutor:        &nativeConstructorExecutor{},
		EvidenceCreationCommands:      &struct{ EvidenceCreationCommands }{},
		EvidenceRelationshipCommands:  &struct{ EvidenceRelationshipCommands }{},
		OpenAPIIngestionCommands:      &struct{ OpenAPIIngestionCommands }{},
		SBOMIngestionCommands:         &struct{ SBOMIngestionCommands }{},
		ScanIngestionCommands: &struct {
			VulnerabilityScanIngestionCommands
		}{},
		VEXIngestionCommands:           &struct{ VEXIngestionCommands }{},
		VEXPreviewQuery:                &struct{ VEXPreviewQuery }{},
		SecurityDocumentCommands:       &struct{ SecurityDocumentCommands }{},
		IncidentCommands:               &struct{ IncidentCommands }{},
		IncidentWebhookCommands:        &struct{ IncidentWebhookCommands }{},
		CollectorCommands:              &struct{ CollectorCommands }{},
		DeploymentEnvironmentCommands:  &struct{ DeploymentEnvironmentCommands }{},
		DeploymentCommands:             &struct{ DeploymentCommands }{},
		SourceRepositoryCommands:       &struct{ SourceRepositoryCommands }{},
		SourceCommitCommands:           &struct{ SourceCommitCommands }{},
		SourceBranchCommands:           &struct{ SourceBranchCommands }{},
		PullRequestCommands:            &struct{ PullRequestCommands }{},
		SourceSnapshotCommands:         &struct{ SourceSnapshotCommands }{},
		SubjectVerification:            &struct{ SubjectVerification }{},
		TransparencyCheckpointCommands: &struct{ TransparencyCheckpointCommands }{},
		MerkleCreationCommands:         &struct{ MerkleCreationCommands }{},
		SigningCustodyQuery:            &struct{ SigningCustodyQuery }{},
		RetentionCommands:              &struct{ RetentionCommands }{},
		RetentionMarkerCommands:        &struct{ RetentionMarkerCommands }{},
		TrustConfigurationCommands:     &struct{ TrustConfigurationCommands }{},
		ReleaseSecuritySummaryQuery:    &struct{ ReleaseSecuritySummaryQuery }{},
		ControlCoverageQuery:           &struct{ ControlCoverageQuery }{},
		InstanceAdminQuery:             &struct{ InstanceAdminQuery }{},
		OutboxDiagnosticsQuery:         &struct{ OutboxDiagnosticsQuery }{},
		OutboxReplayCommand:            &struct{ OutboxReplayCommand }{},
		ProductQuery:                   &struct{ ProductQuery }{},
		CatalogPointQuery:              &struct{ CatalogPointQuery }{},
		EvidenceFlowQuery:              &struct{ EvidenceFlowQuery }{},
		BuildPointQuery:                &struct{ BuildPointQuery }{},
		ArtifactPointQuery:             &struct{ ArtifactPointQuery }{},
		ReleaseCandidateQuery:          &struct{ ReleaseCandidateQuery }{},
		DeploymentPointQuery:           &struct{ DeploymentPointQuery }{},
		DeploymentListQuery:            &struct{ DeploymentListQuery }{},
		EvidencePointQuery:             &struct{ EvidencePointQuery }{},
		EvidencePageQuery:              &struct{ EvidencePageQuery }{},
		LifecycleEventsQuery:           &struct{ LifecycleEventsQuery }{},
		OpenAPIContractPointQuery:      &struct{ OpenAPIContractPointQuery }{},
		SBOMPointQuery:                 &struct{ SBOMPointQuery }{},
		VulnerabilityScanPointQuery:    &struct{ VulnerabilityScanPointQuery }{},
		VEXPointQuery:                  &struct{ VEXPointQuery }{},
		SBOMComponentsQuery:            &struct{ SBOMComponentsQuery }{},
		SourceRepositoryQuery:          &struct{ SourceRepositoryQuery }{},
		CollectorQuery:                 &struct{ CollectorQuery }{},
		CollectorHealthQuery:           &struct{ CollectorHealthQuery }{},
		CommercialCollectorQuery:       &struct{ CommercialCollectorQuery }{},
		MarketplaceCollectorQuery:      &struct{ MarketplaceCollectorQuery }{},
		VulnerabilityPostureQuery:      &struct{ VulnerabilityPostureQuery }{},
		ControlsQuery:                  &struct{ ControlsQuery }{},
		ControlTemplateQuery:           &struct{ ControlTemplateQuery }{},
		ExceptionsQuery:                &struct{ ExceptionsQuery }{},
		VulnerabilityDecisionQuery:     &struct{ VulnerabilityDecisionQuery }{},
		VulnerabilityDecisionSummaryQuery: &struct {
			VulnerabilityDecisionSummaryQuery
		}{},
		ControlEvidenceQuery:   &struct{ ControlEvidenceQuery }{},
		ArtifactSignatureQuery: &struct{ ArtifactSignatureQuery }{},
		SigningKeyQuery:        &struct{ SigningKeyQuery }{},
		ReleaseBundleQuery:     &struct{ ReleaseBundleQuery }{},
		AnswerLibraryQuery:     &struct{ AnswerLibraryQuery }{},
		PortalAccessQuery:      &struct{ PortalAccessQuery }{},
		AuditLogQuery:          &struct{ AuditLogQuery }{},
		APIKeyQuery:            &struct{ APIKeyQuery }{},
		RoleBindingQuery:       &struct{ RoleBindingQuery }{},
	}
}
func TestNativeServerRejectsEveryMissingOrTypedNilDependency(t *testing.T) {
	options := nativeConstructorOptions()
	value, typ := reflect.ValueOf(options), reflect.TypeOf(options)
	tested := 0
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Type.Kind() != reflect.Interface {
			continue
		}
		name := typ.Field(i).Name
		t.Run(name, func(t *testing.T) {
			for _, typedNil := range []bool{false, true} {
				missing := options
				field := reflect.ValueOf(&missing).Elem().Field(i)
				if typedNil {
					concrete := value.Field(i).Elem().Type()
					if concrete.Kind() != reflect.Pointer {
						t.Fatalf("constructor fixture %s is not a pointer", name)
					}
					field.Set(reflect.Zero(concrete))
				} else {
					field.Set(reflect.Zero(field.Type()))
				}
				server, err := NewNativeServerWithOptionsContext(t.Context(), missing)
				if err == nil || server != nil || !strings.Contains(err.Error(), name) || strings.Contains(err.Error(), string(options.PaginationSecret)) {
					t.Fatalf("missing dependency %s typedNil=%t: server=%v err=%v", name, typedNil, server, err)
				}
			}
		})
		tested++
	}
	if tested == 0 {
		t.Fatal("no native dependencies tested")
	}
}
func TestNativeServerInstallsNoAggregateOrLocalFallbackAndPreservesRoutes(t *testing.T) {
	options := nativeConstructorOptions()
	s, err := NewNativeServerWithOptionsContext(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	if s.ledger != nil || s.idempotency != nil || s.identityAccess != nil || s.evidenceIngestion != nil || s.riskDecisions != nil || s.packages != nil || s.verification != nil || s.localDeployments != nil || s.localEvidenceCreation != nil || s.localEvidenceRelationships != nil || s.localReportTemplates != nil || s.localBundleImport != nil || s.localEvidenceBundles != nil {
		t.Fatal("native server installed aggregate or local dependencies")
	}
	if s.authn != options.Authenticator || s.durableCommandExecutor != options.DurableCommandExecutor {
		t.Fatal("native explicit dependencies not bound")
	}
	local, err := newLegacyServerFixtureWithOptionsContext(t.Context(), newLegacyLedgerFixture(app.Config{}), ServerOptions{PaginationSecret: options.PaginationSecret})
	if err != nil {
		t.Fatal(err)
	}
	nativeSpec, err := s.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	localSpec, err := local.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(nativeSpec, localSpec) {
		t.Fatal("native composition changed the API contract")
	}
	if err := s.ValidateRoutes(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/health", "/v1/version", "/v1/openapi.json"} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Fatal("native public system route failed", path, w.Code)
		}
	}
}
func TestNativeServerRequiresContextStableCursorAndReplayCapabilities(t *testing.T) {
	options := nativeConstructorOptions()
	if s, err := NewNativeServerWithOptionsContext(nil, options); s != nil || err == nil { //nolint:staticcheck // Deliberately exercise defensive nil-context rejection.
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if s, err := NewNativeServerWithOptionsContext(ctx, ServerOptions{}); s != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled construction reached validation/dependencies", err)
	}
	for _, secret := range [][]byte{nil, []byte("short")} {
		bad := options
		bad.PaginationSecret = secret
		if s, err := NewNativeServerWithOptionsContext(t.Context(), bad); s != nil || err == nil || !strings.Contains(err.Error(), "PaginationSecret") {
			t.Fatal("unstable/short cursor key accepted", err)
		}
	}
	for _, executor := range []DurableCommandExecutor{&struct{ DurableCommandExecutor }{}, &struct {
		DurableCommandExecutor
		DurableStreamedCommandExecutor
	}{}} {
		bad := options
		bad.DurableCommandExecutor = executor
		if s, err := NewNativeServerWithOptionsContext(t.Context(), bad); s != nil || err == nil || !strings.Contains(err.Error(), "DurableCommandExecutor") {
			t.Fatal("incomplete replay capabilities accepted", err)
		}
	}
}
