package app

import (
	"os"
	"strings"
	"testing"
)

func TestResourceScopedAuthorizationCoverageInventory(t *testing.T) {
	files := map[string][]string{
		"evidence_bundle_replay_guard.go":     {"AuthorizeEvidenceBundleExport"},
		"bundle_import_replay_guard.go":       {"AuthorizeBundleImport"},
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
			"UploadBuildAttestation",
		},
		"legacy_catalog_query_oracle_test.go":         {"GetBuildRun", "GetReleaseCandidate", "ListReleaseCandidates"},
		"legacy_vulnerability_posture_oracle_test.go": {"VulnerabilityPostureReport"},
		"legacy_risk_workflow_oracle_test.go":         {"EvaluateCustomPolicy"},
		"controls.go": {
			"LinkControlEvidence",
			"ListControlEvidence",
		},
		"legacy_security_update_report_oracle_test.go": {"SecurityUpdateEvidenceReport"},
		"legacy_control_reports_oracle_test.go":        {"ControlCoverageReport", "CRAReadinessReport", "CRAVulnerabilityHandlingReport"},
		"control_evidence_replay_guard.go":             {"AuthorizeControlEvidenceLink", "authorizeControlEvidenceLinkLocked"},
		"source_repository_replay_guard.go":            {"AuthorizeSourceRepositoryCreation", "authorizeSourceRepositoryCreationLocked"},
		"source_write_replay_guard.go":                 {"AuthorizeSourceCommitRecording", "AuthorizeSourceBranchUpsert", "AuthorizePullRequestRecording", "authorizeLocalSourceWriteLocked"},
		"legacy_answer_library_oracle_test.go": {
			"CreateQuestionnaireAnswerLibraryEntry",
			"ListQuestionnaireAnswerLibrary",
			"AuthorizeQuestionnaireAnswerLibraryCreate",
			"authorizeAnswerLibraryCreateLocked",
		},
		// Preserve the historical command authorization assertions in their
		// test-only oracle. Uncalled replay guards are now covered by the
		// production-surface retirement test, not a live runtime inventory.
		"legacy_portal_oracle_test.go":                       {"CreateCustomerPortalAccess", "RevokeCustomerPortalAccess", "authorizePortalWriteLocked"},
		"legacy_peripheral_oracle_test.go":                   {"AuthorizeCreateGraphSnapshot", "authorizeGraphSnapshotLocked", "AuthorizeCreateSaaSEditionProfile", "AuthorizeCreateMarketplaceCollector", "CreateGraphSnapshot", "CreateSaaSEditionProfile", "CreateMarketplaceCollector"},
		"product_release_authorization.go":                   {"authorizeProductReleaseLocked"},
		"legacy_pdf_signing_oracle_test.go":                  {"AuthorizeCreatePDFReportPackage", "AuthorizeCreateSigningOperation", "CreatePDFReportPackage", "CreateSigningOperation"},
		"legacy_anomaly_oracle_test.go":                      {"AuthorizeGenerateAnomalyReport", "GenerateAnomalyReport"},
		"legacy_public_transparency_metadata_oracle_test.go": {"AuthorizeCreatePublicTransparencyLog", "AuthorizePublishPublicTransparencyLogEntry"},
		"legacy_public_transparency_proof_oracle_test.go":    {"AuthorizeVerifyPublicTransparencyLogEntry", "AuthorizeFetchPublicTransparencyLogEntryProof", "FetchAndVerifyPublicTransparencyLogEntry"},
		"legacy_public_transparency_oracle_test.go":          {"CreatePublicTransparencyLog", "PublishPublicTransparencyLogEntry", "VerifyPublicTransparencyLogEntry"},
		"legacy_questionnaire_oracle_test.go": {
			"CreateQuestionnairePackage",
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
		},
		"implementation_increments.go": {
			"CreateReleaseCandidate",
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
		"legacy_leaf_oracle_test.go": {"SearchEvidence"},
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
				!strings.Contains(fn, "packagequery.NewBundleImportAuthorizer().Authorize") &&
				!strings.Contains(fn, "packagequery.NewEvidenceBundleAuthorizer().Authorize") &&
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
