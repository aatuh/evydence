package app

import (
	"os"
	"strings"
	"testing"
)

func TestResourceScopedAuthorizationCoverageInventory(t *testing.T) {
	files := map[string][]string{
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
		"enterprise.go": {
			"CreateQuestionnaireAnswerLibraryEntry",
			"ListQuestionnaireAnswerLibrary",
		},
		"risk_workflows.go": {
			"CreateIncident",
			"RecordIncidentTimelineEvent",
			"CreateRemediationTask",
			"IncidentReport",
			"uploadSecurityScan",
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
			if !strings.Contains(fn, "authorizeResourceLocked") && !strings.Contains(fn, "resourceAllowedLocked") {
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
