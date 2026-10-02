package wiring

import (
	"context"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
)

func TestBuildAPIReadServicesRejectsIncompleteRuntimeWithoutLeakingSecrets(t *testing.T) {
	for _, test := range []struct {
		name    string
		runtime *Runtime
	}{
		{"nil runtime", nil},
		{"postgres without store", &Runtime{Process: API, Profile: PostgreSQL}},
		{"memory with store", &Runtime{Process: API, Profile: LocalMemory, Postgres: &postgres.Store{}}},
		{"unknown profile", &Runtime{Process: API, Profile: Profile("other")}},
		{"worker runtime", &Runtime{Process: Worker, Profile: PostgreSQL, Postgres: &postgres.Store{}}},
		{"production memory", &Runtime{Process: API, Profile: LocalMemory, Production: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := BuildAPIReadServices(test.runtime, "private-pepper", nil)
			if err == nil || strings.Contains(err.Error(), "private-pepper") {
				t.Fatalf("unsafe runtime error=%v", err)
			}
		})
	}
}

func TestBuildAPIReadServicesComposesDurableQueriesOnlyForPostgres(t *testing.T) {
	memory, err := BuildAPIReadServices(&Runtime{Process: API, Profile: LocalMemory}, "", nil)
	if err != nil || memory.ReadinessQuery != nil || memory.MetricsQuery != nil || memory.RetentionQuery != nil || memory.IncidentReportQuery != nil || memory.SecurityUpdateEvidenceQuery != nil || memory.CRAVulnerabilityQuery != nil || memory.MissingEvidenceQuery != nil || memory.ReleaseSecuritySummaryQuery != nil || memory.ControlCoverageQuery != nil || memory.Authenticator != nil || memory.InstanceAdminQuery != nil || memory.OutboxDiagnosticsQuery != nil || memory.OutboxReplayCommand != nil || memory.ProductQuery != nil || memory.ArtifactPointQuery != nil || memory.EvidenceFlowQuery != nil || memory.OpenAPIContractPointQuery != nil || memory.SBOMPointQuery != nil || memory.VulnerabilityScanPointQuery != nil || memory.VEXPointQuery != nil || memory.SBOMComponentsQuery != nil || memory.ReleaseBundleQuery != nil || memory.ControlEvidenceQuery != nil || memory.ControlTemplateQuery != nil || memory.ExceptionsQuery != nil || memory.VulnerabilityDecisionQuery != nil || memory.VulnerabilityDecisionSummaryQuery != nil || memory.MarketplaceCollectorQuery != nil || memory.CollectorHealthQuery != nil || memory.VulnerabilityPostureQuery != nil {
		t.Fatalf("local memory dependencies=%#v error=%v", memory, err)
	}
	store := &postgres.Store{}
	if memory.ControlCommands != nil {
		t.Fatal("local memory bound durable control creation")
	}
	if memory.ControlTemplateCommands != nil {
		t.Fatal("local memory bound durable control template installation")
	}
	if memory.ControlEvidenceCommands != nil {
		t.Fatal("local memory bound durable control evidence linking")
	}
	if memory.VulnerabilityDecisionCommands != nil || memory.DurableCommandExecutor != nil {
		t.Fatal("local memory bound durable decision/idempotency commands")
	}
	if memory.ApprovalCommands != nil {
		t.Fatal("local memory bound durable approval commands")
	}
	if memory.WaiverCommands != nil {
		t.Fatal("local memory bound durable waiver commands")
	}
	if memory.ExceptionCommands != nil {
		t.Fatal("local memory bound durable exception commands")
	}
	if memory.ReleaseReadinessReportQuery != nil {
		t.Fatal("local-memory profile unexpectedly bound durable readiness reports")
	}
	if memory.CustomerPackageAccessCommands != nil {
		t.Fatal("local-memory profile unexpectedly bound durable package access")
	}
	if memory.HTMLReportCommands != nil {
		t.Fatal("local-memory profile unexpectedly bound durable HTML reports")
	}
	if memory.ReportTemplateCommands != nil {
		t.Fatal("local-memory profile unexpectedly bound durable template commands")
	}
	if memory.BundleImportCommand != nil {
		t.Fatal("local-memory profile unexpectedly bound durable bundle imports")
	}
	if memory.ReleaseBundleCommands != nil {
		t.Fatal("local-memory profile bound durable bundle commands")
	}
	if memory.EvidenceBundleCommands != nil {
		t.Fatal("local memory silently received durable export")
	}
	if memory.SigningKeyCommands != nil {
		t.Fatal("local memory bound durable signing-key commands")
	}
	if memory.ReleaseBundleVerification != nil {
		t.Fatal("local memory bound durable bundle verification")
	}
	if memory.EvidenceVerification != nil {
		t.Fatal("local memory bound durable evidence verification")
	}
	if memory.DSSEVerification != nil {
		t.Fatal("local memory bound durable DSSE verification")
	}
	if memory.CosignVerification != nil {
		t.Fatal("local memory bound durable Cosign verification")
	}
	if memory.ArtifactSignatureVerification != nil {
		t.Fatal("local memory bound durable signature metadata verification")
	}
	if memory.MerkleVerification != nil {
		t.Fatal("local memory bound durable Merkle verification")
	}
	if memory.AuditChainVerification != nil {
		t.Fatal("local memory bound durable audit chain verification")
	}
	if memory.MerkleCheckpointVerification != nil {
		t.Fatal("local memory must retain its explicit checkpoint path")
	}
	if memory.ReleaseManifestCheckpoint != nil {
		t.Fatal("local memory must retain its explicit manifest checkpoint path")
	}
	if memory.BackupVerification != nil {
		t.Fatal("local memory must retain its explicit backup verification path")
	}
	if memory.SubjectVerification != nil {
		t.Fatal("local memory must retain its explicit generic verification path")
	}
	if memory.TransparencyCheckpointCommands != nil {
		t.Fatal("local memory must retain its explicit checkpoint creation path")
	}
	if memory.MerkleCreationCommands != nil {
		t.Fatal("local memory bound durable Merkle creation")
	}
	if memory.BackupGenerationCommands != nil {
		t.Fatal("local memory bound durable backup generation")
	}
	if memory.ArtifactSignatureCommands != nil {
		t.Fatal("local memory bound durable artifact signature creation")
	}
	if memory.BuildAttestationCommands != nil {
		t.Fatal("local memory must keep explicit attestation compatibility binding")
	}
	if memory.BuildCommands != nil {
		t.Fatal("local memory must keep explicit build creation compatibility binding")
	}
	if memory.ContainerImageCommands != nil {
		t.Fatal("local memory must keep explicit container image compatibility binding")
	}
	if memory.ArtifactCommands != nil {
		t.Fatal("local memory must keep explicit artifact compatibility binding")
	}
	if memory.ProjectCommands != nil {
		t.Fatal("local memory must keep explicit project compatibility binding")
	}
	if memory.ProductCommands != nil {
		t.Fatal("local memory must keep explicit product creation compatibility binding")
	}
	if memory.CandidateStateCommands != nil {
		t.Fatal("local memory must keep explicit candidate transition compatibility binding")
	}
	if memory.CandidateCommands != nil {
		t.Fatal("local memory must keep explicit candidate creation compatibility binding")
	}
	if memory.ReleaseCreationCommands != nil {
		t.Fatal("local memory must keep explicit release creation compatibility binding")
	}
	if memory.ReleaseStateCommands != nil {
		t.Fatal("local memory must keep explicit release transition compatibility binding")
	}
	if memory.EvidenceCreationCommands != nil {
		t.Fatal("local memory must keep explicit evidence compatibility binding")
	}
	if memory.DeploymentEnvironmentCommands != nil {
		t.Fatal("local memory bound durable environment creation")
	}
	if memory.DeploymentCommands != nil {
		t.Fatal("local memory bound durable deployment recording")
	}
	if memory.SourceRepositoryCommands != nil {
		t.Fatal("local memory bound durable source repository creation")
	}
	if memory.SourceCommitCommands != nil {
		t.Fatal("local memory bound durable source commit recording")
	}
	if memory.SourceBranchCommands != nil {
		t.Fatal("local memory bound durable source branch upserts")
	}
	if memory.PullRequestCommands != nil {
		t.Fatal("local memory bound durable pull request recording")
	}
	if memory.SourceSnapshotCommands != nil {
		t.Fatal("local memory bound durable source snapshot recording")
	}
	if memory.SigningCustodyQuery != nil {
		t.Fatal("local memory bound durable custody query")
	}
	if memory.RetentionCommands != nil {
		t.Fatal("local memory unexpectedly binds durable retention commands")
	}
	if memory.TrustConfigurationCommands != nil {
		t.Fatal("local memory binds durable trust commands")
	}
	checks := []app.ReadinessCheck{
		{Name: "postgres", Check: func(context.Context) error { return nil }},
		{Name: "migrations", Check: func(context.Context) error { return nil }},
		{Name: "writer_lease", Check: func(context.Context) error { return nil }},
		{Name: "signing_config", Check: func(context.Context) error { return nil }},
	}
	options, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store, Production: true}, "non-default-pepper", checks)
	if err != nil {
		t.Fatal(err)
	}
	if options.ReleaseReadinessReportQuery == nil {
		t.Fatal("PostgreSQL profile omitted readiness reports")
	}
	if options.CustomerPackageAccessCommands == nil {
		t.Fatal("PostgreSQL profile omitted package access")
	}
	if options.HTMLReportCommands == nil {
		t.Fatal("PostgreSQL profile omitted HTML reports")
	}
	if options.ReportTemplateCommands == nil {
		t.Fatal("PostgreSQL profile omitted report template commands")
	}
	if options.BundleImportCommand == nil {
		t.Fatal("PostgreSQL profile omitted bundle imports")
	}
	if options.ReleaseBundleCommands == nil {
		t.Fatal("PostgreSQL profile omitted release bundle commands")
	}
	if options.EvidenceBundleCommands == nil {
		t.Fatal("PostgreSQL export still uses Ledger")
	}
	if options.SigningKeyCommands == nil {
		t.Fatal("PostgreSQL signing-key lifecycle still uses Ledger")
	}
	if options.ReleaseBundleVerification == nil {
		t.Fatal("PostgreSQL bundle verification still uses Ledger")
	}
	if options.EvidenceVerification == nil {
		t.Fatal("PostgreSQL evidence verification still uses Ledger")
	}
	if options.DSSEVerification == nil {
		t.Fatal("PostgreSQL DSSE verification still uses Ledger")
	}
	if options.CosignVerification == nil {
		t.Fatal("PostgreSQL Cosign verification still uses Ledger")
	}
	if options.ArtifactSignatureVerification == nil {
		t.Fatal("PostgreSQL signature metadata verification still uses Ledger")
	}
	if options.MerkleVerification == nil {
		t.Fatal("PostgreSQL Merkle verification still uses Ledger")
	}
	if options.AuditChainVerification == nil {
		t.Fatal("PostgreSQL audit chain verification still uses Ledger")
	}
	if options.MerkleCheckpointVerification == nil {
		t.Fatal("PostgreSQL checkpoint verification must be focused")
	}
	if options.ReleaseManifestCheckpoint == nil {
		t.Fatal("PostgreSQL manifest checkpoint verification must be focused")
	}
	if options.BackupVerification == nil {
		t.Fatal("PostgreSQL backup verification must be focused")
	}
	if options.SubjectVerification == nil {
		t.Fatal("PostgreSQL generic verification must not fall back to Ledger")
	}
	if options.TransparencyCheckpointCommands == nil {
		t.Fatal("PostgreSQL checkpoint creation must not use Ledger")
	}
	if options.MerkleCreationCommands == nil {
		t.Fatal("PostgreSQL Merkle creation still uses Ledger")
	}
	if options.BackupGenerationCommands == nil {
		t.Fatal("PostgreSQL backup generation still uses Ledger")
	}
	if options.ArtifactSignatureCommands == nil {
		t.Fatal("PostgreSQL artifact signature creation still uses Ledger")
	}
	if options.BuildAttestationCommands == nil {
		t.Fatal("PostgreSQL attestation upload still uses Ledger")
	}
	if options.BuildCommands == nil {
		t.Fatal("PostgreSQL build creation still uses Ledger")
	}
	if options.ContainerImageCommands == nil {
		t.Fatal("PostgreSQL container image registration still uses Ledger")
	}
	if options.ArtifactCommands == nil {
		t.Fatal("PostgreSQL artifact registration still uses Ledger")
	}
	if options.ProjectCommands == nil {
		t.Fatal("PostgreSQL project creation still uses Ledger")
	}
	if options.ProductCommands == nil {
		t.Fatal("PostgreSQL product creation still uses Ledger")
	}
	if options.CandidateStateCommands == nil {
		t.Fatal("PostgreSQL candidate transitions still use Ledger")
	}
	if options.CandidateCommands == nil {
		t.Fatal("PostgreSQL candidate creation still uses Ledger")
	}
	if options.ReleaseCreationCommands == nil {
		t.Fatal("PostgreSQL release creation still uses Ledger")
	}
	if options.ReleaseStateCommands == nil {
		t.Fatal("PostgreSQL release transitions still use Ledger")
	}
	if options.EvidenceCreationCommands == nil {
		t.Fatal("PostgreSQL evidence creation still uses Ledger")
	}
	if options.DeploymentEnvironmentCommands == nil {
		t.Fatal("PostgreSQL environment creation still uses Ledger")
	}
	if options.DeploymentCommands == nil {
		t.Fatal("PostgreSQL deployment recording still uses Ledger")
	}
	if options.SourceRepositoryCommands == nil {
		t.Fatal("PostgreSQL source repository creation still uses Ledger")
	}
	if options.SourceCommitCommands == nil {
		t.Fatal("PostgreSQL source commit recording still uses Ledger")
	}
	if options.SourceBranchCommands == nil {
		t.Fatal("PostgreSQL source branch upserts still use Ledger")
	}
	if options.PullRequestCommands == nil {
		t.Fatal("PostgreSQL pull request recording still uses Ledger")
	}
	if options.SourceSnapshotCommands == nil {
		t.Fatal("PostgreSQL source snapshots still use Ledger")
	}
	if options.SigningCustodyQuery == nil {
		t.Fatal("PostgreSQL custody report still uses Ledger")
	}
	if options.RetentionCommands == nil {
		t.Fatal("PostgreSQL does not bind durable retention commands")
	}
	if options.ControlCommands == nil {
		t.Fatal("PostgreSQL control creation still uses Ledger")
	}
	if options.ControlTemplateCommands == nil {
		t.Fatal("PostgreSQL control template installation still uses Ledger")
	}
	if options.ControlEvidenceCommands == nil {
		t.Fatal("PostgreSQL control evidence linking still uses Ledger")
	}
	if options.VulnerabilityDecisionCommands == nil || options.DurableCommandExecutor == nil {
		t.Fatal("PostgreSQL decision commands still use Ledger/idempotency")
	}
	if options.ApprovalCommands == nil {
		t.Fatal("PostgreSQL approval creation still uses Ledger")
	}
	if options.WaiverCommands == nil {
		t.Fatal("PostgreSQL waiver commands still use Ledger")
	}
	if options.ExceptionCommands == nil {
		t.Fatal("PostgreSQL exception commands still use Ledger")
	}
	if options.TrustConfigurationCommands == nil {
		t.Fatal("PostgreSQL lacks durable trust commands")
	}
	if options.ReadinessQuery == nil || options.MetricsQuery == nil || options.RetentionQuery == nil || options.IncidentReportQuery == nil || options.SecurityUpdateEvidenceQuery == nil || options.CRAVulnerabilityQuery == nil || options.MissingEvidenceQuery == nil || options.ReleaseSecuritySummaryQuery == nil || options.ControlCoverageQuery == nil || options.Authenticator == nil || options.InstanceAdminQuery == nil || options.OutboxDiagnosticsQuery == nil || options.OutboxReplayCommand == nil || options.ProductQuery == nil || options.CatalogPointQuery == nil || options.EvidenceFlowQuery == nil ||
		options.BuildPointQuery == nil || options.ArtifactPointQuery == nil || options.ReleaseCandidateQuery == nil || options.DeploymentPointQuery == nil ||
		options.DeploymentListQuery == nil || options.EvidencePointQuery == nil || options.OpenAPIContractPointQuery == nil || options.SBOMPointQuery == nil || options.VulnerabilityScanPointQuery == nil || options.VEXPointQuery == nil || options.SBOMComponentsQuery == nil || options.SourceRepositoryQuery == nil ||
		options.CollectorQuery == nil || options.CollectorHealthQuery == nil || options.CommercialCollectorQuery == nil || options.MarketplaceCollectorQuery == nil || options.VulnerabilityPostureQuery == nil || options.ControlsQuery == nil || options.ControlTemplateQuery == nil || options.ExceptionsQuery == nil || options.VulnerabilityDecisionQuery == nil || options.VulnerabilityDecisionSummaryQuery == nil || options.ControlEvidenceQuery == nil || options.ArtifactSignatureQuery == nil ||
		options.ReleaseBundleQuery == nil || options.AnswerLibraryQuery == nil || options.AuditLogQuery == nil ||
		options.SigningKeyQuery == nil ||
		options.PortalAccessQuery == nil || options.APIKeyQuery == nil || options.RoleBindingQuery == nil {
		t.Fatalf("incomplete durable dependencies=%#v", options)
	}
	if _, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store, Production: true}, "", checks); err == nil {
		t.Fatal("production accepted a missing credential pepper")
	}
	if _, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store, Production: true}, "non-default-pepper", nil); err == nil {
		t.Fatal("production accepted missing dependency probes")
	}
	status, err := options.ReadinessQuery.Public(t.Context())
	if err != nil || status["status"] != "ok" {
		t.Fatalf("composed readiness=%#v err=%v", status, err)
	}
}
