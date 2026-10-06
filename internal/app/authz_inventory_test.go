package app

import (
	"os"
	"strings"
	"testing"
)

func TestResourceScopedAuthorizationCoverageInventory(t *testing.T) {
	files := map[string][]string{
		"report_template_replay_guard.go":     {"AuthorizeReportTemplateCreation", "AuthorizeReportRendering"},
		"evidence_creation_replay_guard.go":   {"AuthorizeEvidenceCreation"},
		"deployment_creation_replay_guard.go": {"AuthorizeEnvironmentCreation", "AuthorizeDeploymentRecording"},
		"state_transition_replay_guard.go":    {"AuthorizeReleaseTransition", "AuthorizeCandidateTransition", "authorizeStateTransition"},
		"candidate_creation_replay_guard.go":  {"AuthorizeCandidateCreation"},
		"artifact_image_replay_guard.go":      {"AuthorizeArtifactRegistration", "AuthorizeContainerImageRegistration"},
		"catalog_creation_replay_guard.go":    {"AuthorizeProductCreation", "AuthorizeProjectCreation", "AuthorizeReleaseCreation", "authorizeCatalogCreation"},
		"build_creation_replay_guard.go":      {"AuthorizeBuildCreation"},
		"build_attestation_creation_guard.go": {"AuthorizeBuildAttestationCreation"},
		"builds.go": {
			"CreateBuildRun",
			"GetBuildRun",
			"UploadBuildAttestation",
		},
		"controls.go": {
			"LinkControlEvidence",
			"ListControlEvidence",
			"ControlCoverageReport",
			"CRAReadinessReport",
			"CRAVulnerabilityHandlingReport",
			"SecurityUpdateEvidenceReport",
		},
		"control_evidence_replay_guard.go":  {"AuthorizeControlEvidenceLink", "authorizeControlEvidenceLinkLocked"},
		"source_repository_replay_guard.go": {"AuthorizeSourceRepositoryCreation", "authorizeSourceRepositoryCreationLocked"},
		"source_write_replay_guard.go":      {"AuthorizeSourceCommitRecording", "AuthorizeSourceBranchUpsert", "AuthorizePullRequestRecording", "authorizeLocalSourceWriteLocked"},
		"enterprise.go": {
			"CreateCustomerPortalAccess",
			"RevokeCustomerPortalAccess",
			"CreateQuestionnairePackage",
			"CreateQuestionnaireAnswerLibraryEntry",
			"ListQuestionnaireAnswerLibrary",
		},
		"portal_access_creation.go":                {"AuthorizeCustomerPortalAccessCreate", "AuthorizeCustomerPortalAccessRevoke", "authorizePortalWriteLocked"},
		"graph_snapshot_creation.go":               {"AuthorizeCreateGraphSnapshot", "authorizeGraphSnapshotLocked"},
		"product_release_authorization.go":         {"authorizeProductReleaseLocked"},
		"pdf_report_creation.go":                   {"AuthorizeCreatePDFReportPackage"},
		"anomaly_report_creation.go":               {"AuthorizeGenerateAnomalyReport"},
		"signing_operation_creation.go":            {"AuthorizeCreateSigningOperation"},
		"saas_profile_creation.go":                 {"AuthorizeCreateSaaSEditionProfile"},
		"marketplace_collector_creation.go":        {"AuthorizeCreateMarketplaceCollector"},
		"public_transparency_metadata_creation.go": {"AuthorizeCreatePublicTransparencyLog", "AuthorizePublishPublicTransparencyLogEntry"},
		"public_transparency_verification.go":      {"AuthorizeVerifyPublicTransparencyLogEntry"},
		"public_transparency_fetch.go":             {"AuthorizeFetchPublicTransparencyLogEntryProof", "FetchAndVerifyPublicTransparencyLogEntry"},
		"future_extensions.go":                     {"CreateGraphSnapshot", "CreatePDFReportPackage", "GenerateAnomalyReport", "CreateSigningOperation", "CreateSaaSEditionProfile", "CreateMarketplaceCollector", "CreatePublicTransparencyLog", "PublishPublicTransparencyLogEntry", "VerifyPublicTransparencyLogEntry"},
		"answer_library_creation.go": {
			"AuthorizeQuestionnaireAnswerLibraryCreate",
			"authorizeAnswerLibraryCreateLocked",
		},
		"questionnaire_package_creation.go": {
			"AuthorizeQuestionnairePackageCreate",
			"authorizeQuestionnairePackageCreateLocked",
		},
		"risk_workflows.go": {
			"CreateIncident",
			"RecordIncidentTimelineEvent",
			"CreateRemediationTask",
			"IncidentReport",
			"UploadSecurityScan",
			"UploadManualSecurityDocument",
			"VulnerabilityPostureReport",
			"EvaluateCustomPolicy",
		},
		"implementation_increments.go": {
			"SearchEvidence",
			"CreateReleaseCandidate",
			"GetReleaseCandidate",
			"ListReleaseCandidates",
			"UpdateReleaseCandidateState",
			"ListSourceRepositories",
			"CreateSourceRepository",
			"RecordSourceCommit",
			"UpsertSourceBranch",
			"RecordPullRequest",
			"ListDeploymentEnvironments",
			"CreateDeploymentEnvironment",
			"RecordDeployment",
			"GetDeployment",
			"ListDeployments",
		},
	}
	for file, funcs := range files {
		bodyBytes, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		body := string(bodyBytes)
		for _, name := range funcs {
			fn := functionBody(t, body, name)
			if !strings.Contains(fn, "authorizeResourceLocked") && !strings.Contains(fn, "resourceAllowedLocked") &&
				!strings.Contains(fn, "releaseCommands.") && !strings.Contains(fn, "evidenceCommands.") &&
				!strings.Contains(fn, "authorizeAnswerLibraryCreateLocked") && !strings.Contains(fn, "packagequery.NewAnswerLibraryAuthorizer().Authorize") &&
				!strings.Contains(fn, "authorizeQuestionnairePackageCreateLocked") && !strings.Contains(fn, "packagequery.NewQuestionnairePackageAuthorizer().Authorize") &&
				!strings.Contains(fn, "authorizePortalWriteLocked") && !strings.Contains(fn, "packagequery.NewPortalAccessWriteAuthorizer().Authorize") &&
				!strings.Contains(fn, "authorizeGraphSnapshotLocked") && !strings.Contains(fn, "authorizeProductReleaseLocked") &&
				!strings.Contains(fn, "authorizeControlEvidenceLinkLocked") &&
				!strings.Contains(fn, "packagequery.NewTemplateAuthorizer().Authorize") &&
				!strings.Contains(fn, "authorizeSourceRepositoryCreationLocked") &&
				!strings.Contains(fn, "authorizeLocalSourceWriteLocked") &&
				!strings.Contains(fn, "l.authorizeCatalogCreation(") &&
				!strings.Contains(fn, "l.authorizeStateTransition(") &&
				!strings.Contains(fn, "verificationquery.NewSigningKeyAdminAuthorizer().Authorize") && !strings.Contains(fn, "l.AuthorizeCreateSigningOperation(") &&
				!strings.Contains(fn, "experimentalapp.AuthorizeSaaSProfileActor(") && !strings.Contains(fn, "l.AuthorizeCreateSaaSEditionProfile(") &&
				!strings.Contains(fn, "experimentalapp.AuthorizeMarketplaceCollectorActor(") && !strings.Contains(fn, "l.AuthorizeCreateMarketplaceCollector(") &&
				!strings.Contains(fn, "experimentalapp.AuthorizePublicTransparencyMetadataActor(") && !strings.Contains(fn, "e.AuthorizePublicTransparencyMetadataActor(") && !strings.Contains(fn, "l.AuthorizeFetchPublicTransparencyLogEntryProof(") && !strings.Contains(fn, "l.AuthorizeVerifyPublicTransparencyLogEntry(") && !strings.Contains(fn, "l.AuthorizeCreatePublicTransparencyLog(") && !strings.Contains(fn, "l.AuthorizePublishPublicTransparencyLogEntry(") {
				t.Fatalf("%s.%s missing resource-scoped authorization call", file, name)
			}
		}
	}
}

func functionBody(t *testing.T, fileBody, name string) string {
	t.Helper()
	markers := []string{
		"func (l *Ledger) " + name,
		"func (s identityService) " + name,
		"func (s releaseEvidenceService) " + name,
		"func (s packageReportService) " + name,
	}
	start := -1
	marker := ""
	for _, candidate := range markers {
		if idx := strings.Index(fileBody, candidate); idx >= 0 {
			start = idx
			marker = candidate
			break
		}
	}
	if marker == "" {
		t.Fatalf("missing function %s", name)
	}
	rest := fileBody[start+len(marker):]
	next := strings.Index(rest, "\nfunc ")
	if next < 0 {
		return rest
	}
	return rest[:next]
}
