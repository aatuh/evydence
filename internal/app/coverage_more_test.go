package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestImplementationIncrementReadListAndHelperBranches(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	project, err := ledger.CreateProject(ctx, actor, release.ProductID, "api")
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	build, err := ledger.CreateBuildRun(ctx, actor, CreateBuildRunInput{
		ProjectID: project.ID,
		ReleaseID: release.ID,
		Provider:  "generic_ci",
		CommitSHA: "0123456789abcdef0123456789abcdef01234567",
		Status:    "passed",
		StartedAt: fixedNow(),
		Outputs:   []domain.BuildOutput{{ArtifactID: artifact.ID, Digest: artifact.Digest}},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	sbom, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"api","purl":"pkg:oci/api"}]}`))
	if err != nil {
		t.Fatalf("sbom: %v", err)
	}
	scan, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{"scanner":"grype","target_ref":"pkg:oci/api","release_id":"`+release.ID+`","findings":[{"vulnerability":"CVE-2026-0001","component":"api","severity":"critical","state":"open"}]}`))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	vex, err := ledger.UploadVEX(ctx, actor, release.ID, artifact.ID, []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex","author":"security@example.test","timestamp":"2026-05-28T12:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-2026-0001"},"products":[{"@id":"pkg:oci/api"}],"status":"under_investigation","justification":"triage","impact_statement":"reviewing","action_statement":"track"}]}`))
	if err != nil {
		t.Fatalf("vex: %v", err)
	}
	contract, err := ledger.UploadOpenAPIContract(ctx, actor, release.ProductID, release.ID, "v1", []byte(`{"openapi":"3.1.0","info":{"title":"API","version":"1"},"paths":{"/health":{"get":{"responses":{"200":{"description":"ok"}}}}}}`))
	if err != nil {
		t.Fatalf("contract: %v", err)
	}
	bundle, err := ledger.CreateReleaseBundle(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	candidate, err := ledger.CreateReleaseCandidate(ctx, actor, CreateReleaseCandidateInput{
		ReleaseID:   release.ID,
		Name:        "rc-full",
		BuildIDs:    []string{build.ID},
		ArtifactIDs: []string{artifact.ID},
		SBOMIDs:     []string{sbom.ID},
		ScanIDs:     []string{scan.ID},
		VEXIDs:      []string{vex.ID},
		ContractIDs: []string{contract.ID},
		BundleIDs:   []string{bundle.ID},
	})
	if err != nil {
		t.Fatalf("candidate with all refs: %v", err)
	}
	if got, err := ledger.GetReleaseCandidate(ctx, actor, candidate.ID); err != nil || got.ID != candidate.ID {
		t.Fatalf("get candidate=%#v err=%v", got, err)
	}
	if listed, err := ledger.ListReleaseCandidates(ctx, actor, release.ID); err != nil || len(listed) != 1 {
		t.Fatalf("list candidates=%#v err=%v", listed, err)
	}
	reject, err := ledger.CreateReleaseCandidate(ctx, actor, CreateReleaseCandidateInput{ReleaseID: release.ID, Name: "rc-reject"})
	if err != nil {
		t.Fatalf("reject candidate: %v", err)
	}
	if rejected, err := ledger.UpdateReleaseCandidateState(ctx, actor, reject.ID, candidateRejected, "bad build"); err != nil || rejected.RejectedAt == nil {
		t.Fatalf("rejected candidate=%#v err=%v", rejected, err)
	}
	if _, err := ledger.CreateReleaseCandidate(ctx, actor, CreateReleaseCandidateInput{ReleaseID: release.ID, Name: "bad", BuildIDs: []string{"missing"}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing build candidate err=%v, want not found", err)
	}

	sig, err := ledger.CreateArtifactSignature(ctx, actor, CreateArtifactSignatureInput{ArtifactID: artifact.ID, Algorithm: "cosign", Signature: "sig"})
	if err != nil {
		t.Fatalf("artifact signature: %v", err)
	}
	if got, err := ledger.GetArtifactSignature(ctx, actor, sig.ID); err != nil || got.ID != sig.ID {
		t.Fatalf("get artifact signature=%#v err=%v", got, err)
	}
	if duplicate, err := ledger.RegisterContainerImage(ctx, actor, RegisterContainerImageInput{ArtifactID: artifact.ID, Repository: "ghcr.io/example/api", Digest: artifact.Digest}); err != nil {
		t.Fatalf("image: %v", err)
	} else if again, err := ledger.RegisterContainerImage(ctx, actor, RegisterContainerImageInput{ArtifactID: artifact.ID, Repository: "ghcr.io/example/api", Digest: artifact.Digest}); err != nil || again.ID != duplicate.ID {
		t.Fatalf("duplicate image=%#v err=%v", again, err)
	}

	repo, err := ledger.CreateSourceRepository(ctx, actor, CreateRepositoryInput{ProjectID: project.ID, Provider: "github", FullName: "aatuh/evydence", DefaultBranch: "main"})
	if err != nil {
		t.Fatalf("repo: %v", err)
	}
	if again, err := ledger.CreateSourceRepository(ctx, actor, CreateRepositoryInput{ProjectID: project.ID, Provider: "github", FullName: "aatuh/evydence"}); err != nil || again.ID != repo.ID {
		t.Fatalf("duplicate repo=%#v err=%v", again, err)
	}
	commit, err := ledger.RecordSourceCommit(ctx, actor, RecordCommitInput{RepositoryID: repo.ID, SHA: "1123456789abcdef0123456789abcdef01234567", Message: "change"})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	branch, err := ledger.UpsertSourceBranch(ctx, actor, UpsertBranchInput{RepositoryID: repo.ID, Name: "main", HeadCommitID: commit.ID, Protected: true, ProtectionHash: sampleDigest("branch")})
	if err != nil {
		t.Fatalf("branch: %v", err)
	}
	updated, err := ledger.UpsertSourceBranch(ctx, actor, UpsertBranchInput{RepositoryID: repo.ID, Name: "main", HeadCommitID: commit.ID, Protected: false})
	if err != nil || updated.ID != branch.ID || updated.Protected {
		t.Fatalf("updated branch=%#v err=%v", updated, err)
	}
	if _, err := ledger.RecordPullRequest(ctx, actor, RecordPullRequestInput{RepositoryID: repo.ID, ProviderID: "1", Title: "Change", State: "closed", HeadCommitID: commit.ID}); err != nil {
		t.Fatalf("pr closed: %v", err)
	}
	if listed, err := ledger.ListSourceRepositories(ctx, actor, project.ID); err != nil || len(listed) == 0 {
		t.Fatalf("list repos=%#v err=%v", listed, err)
	}
	if _, err := ledger.UploadGitHubSourceSnapshot(ctx, actor, []byte(`{"project_id":"`+project.ID+`","repository":{"full_name":"aatuh/evydence","default_branch":"main"},"commit":{"sha":"2123456789abcdef0123456789abcdef01234567","author":"dev@example.test","message":"change","committed_at":"2026-05-28T12:00:00Z"},"branch":{"name":"main","protected":true,"protection_hash":"`+sampleDigest("protection")+`"},"pull_request":{"provider_id":"2","title":"Change 2","state":"open","source_branch":"feature","target_branch":"main","review_decision":"review_required"}}`)); err != nil {
		t.Fatalf("github snapshot: %v", err)
	}

	env, err := ledger.CreateDeploymentEnvironment(ctx, actor, CreateEnvironmentInput{ProductID: release.ProductID, Name: "prod", Kind: "production"})
	if err != nil {
		t.Fatalf("env: %v", err)
	}
	if envAgain, err := ledger.CreateDeploymentEnvironment(ctx, actor, CreateEnvironmentInput{ProductID: release.ProductID, Name: "prod", Kind: "production"}); err != nil || envAgain.ID != env.ID {
		t.Fatalf("duplicate env=%#v err=%v", envAgain, err)
	}
	if envs, err := ledger.ListDeploymentEnvironments(ctx, actor, release.ProductID); err != nil || len(envs) != 1 {
		t.Fatalf("list envs=%#v err=%v", envs, err)
	}
	deployment, err := ledger.RecordDeployment(ctx, actor, RecordDeploymentInput{EnvironmentID: env.ID, ReleaseID: release.ID, ArtifactIDs: []string{artifact.ID}, Status: deploymentStatusFailed, StartedAt: fixedNow()})
	if err != nil {
		t.Fatalf("deployment: %v", err)
	}
	rollback, err := ledger.RecordDeployment(ctx, actor, RecordDeploymentInput{EnvironmentID: env.ID, ReleaseID: release.ID, Status: deploymentStatusRolledBack, RollbackOf: deployment.ID})
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if got, err := ledger.GetDeployment(ctx, actor, rollback.ID); err != nil || got.RollbackOf != deployment.ID {
		t.Fatalf("get rollback=%#v err=%v", got, err)
	}
	if listed, err := ledger.ListDeployments(ctx, actor, release.ID, env.ID); err != nil || len(listed) != 2 {
		t.Fatalf("list deployments=%#v err=%v", listed, err)
	}
}

func TestSearchAndControlHelperBranches(t *testing.T) {
	item := domain.EvidenceItem{
		ID:                 "ev_1",
		TenantID:           "ten_1",
		ProductID:          "prod_1",
		ProjectID:          "proj_1",
		ReleaseID:          "rel_1",
		BuildID:            "build_1",
		DeploymentID:       "dep_1",
		Type:               "sbom",
		Subtype:            "cyclonedx",
		SourceSystem:       "github",
		CollectorID:        "collector_1",
		VerificationStatus: "verified",
		Tags:               []string{"release"},
		SubjectRefs:        []domain.SubjectRef{{Type: "artifact", ID: "art_1", Digest: sampleDigest("artifact")}},
		CreatedAt:          fixedNow(),
	}
	matching := EvidenceSearchInput{ProductID: "prod_1", ProjectID: "proj_1", ReleaseID: "rel_1", BuildID: "build_1", DeploymentID: "dep_1", Type: "sbom", Subtype: "cyclonedx", SourceSystem: "github", CollectorID: "collector_1", VerificationStatus: "verified", SubjectType: "artifact", SubjectID: "art_1", Tag: "release", CreatedAfter: fixedNow().Add(-time.Hour), CreatedBefore: fixedNow().Add(time.Hour)}
	if !matchesEvidenceSearch(item, matching) {
		t.Fatal("expected all search fields to match")
	}
	negativeCases := []EvidenceSearchInput{
		{ProductID: "other"}, {ProjectID: "other"}, {ReleaseID: "other"}, {BuildID: "other"}, {DeploymentID: "other"},
		{Type: "scan"}, {Subtype: "spdx"}, {SourceSystem: "gitlab"}, {CollectorID: "other"}, {VerificationStatus: "failed"},
		{CreatedAfter: fixedNow().Add(time.Hour)}, {CreatedBefore: fixedNow().Add(-time.Hour)}, {Tag: "missing"},
		{SubjectType: "release"}, {SubjectID: "missing"},
	}
	for _, in := range negativeCases {
		if matchesEvidenceSearch(item, in) {
			t.Fatalf("search should not match for %#v", in)
		}
	}
	for _, action := range []string{lifecycleAmendment, lifecycleRedaction, lifecycleTombstone, lifecycleRetentionMarker} {
		if !validLifecycleAction(action) {
			t.Fatalf("valid lifecycle action rejected: %s", action)
		}
	}
	if validLifecycleAction("delete") || validPullRequestState("draft") || validDeploymentStatus("unknown") {
		t.Fatal("invalid helper values should be rejected")
	}
	for _, state := range []string{"open", "closed", "merged"} {
		if !validPullRequestState(state) {
			t.Fatalf("valid pull request state rejected: %s", state)
		}
	}
	for _, status := range []string{deploymentStatusStarted, deploymentStatusSucceeded, deploymentStatusFailed, deploymentStatusRolledBack} {
		if !validDeploymentStatus(status) {
			t.Fatalf("valid deployment status rejected: %s", status)
		}
	}
}

func TestControlSubjectResolutionCoversAllSupportedSubjects(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	project, err := ledger.CreateProject(ctx, actor, release.ProductID, "api")
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	evidence, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ProductID: release.ProductID, ProjectID: project.ID, ReleaseID: release.ID, Type: "manual", Title: "manual", PayloadHash: sampleDigest("evidence")})
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	sbom, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"api"}]}`))
	if err != nil {
		t.Fatalf("sbom: %v", err)
	}
	scan, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{"scanner":"grype","target_ref":"pkg:oci/api","release_id":"`+release.ID+`","findings":[{"vulnerability":"CVE-2026-0001","component":"api","severity":"critical","state":"open"}]}`))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	decision, err := ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{Status: decisionStatusFixed, Justification: "fixed"})
	if err != nil {
		t.Fatalf("decision: %v", err)
	}
	vex, err := ledger.UploadVEX(ctx, actor, release.ID, artifact.ID, []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex","author":"security@example.test","timestamp":"2026-05-28T12:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-2026-0001"},"products":[{"@id":"pkg:oci/api"}],"status":"fixed","justification":"fixed","impact_statement":"fixed","action_statement":"none"}]}`))
	if err != nil {
		t.Fatalf("vex: %v", err)
	}
	exception, err := ledger.CreateException(ctx, actor, CreateExceptionInput{ReleaseID: release.ID, FindingID: scan.Findings[0].ID, Reason: "accepted", Owner: "security", ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("exception: %v", err)
	}
	build, err := ledger.CreateBuildRun(ctx, actor, CreateBuildRunInput{ProjectID: project.ID, ReleaseID: release.ID, Provider: "generic_ci", CommitSHA: "3123456789abcdef0123456789abcdef01234567", Status: "passed", StartedAt: fixedNow(), Outputs: []domain.BuildOutput{{ArtifactID: artifact.ID, Digest: artifact.Digest}}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	attestation, err := ledger.UploadBuildAttestation(ctx, actor, build.ID, dsseForDigest(t, artifact.Digest))
	if err != nil {
		t.Fatalf("attestation: %v", err)
	}
	contract, err := ledger.UploadOpenAPIContract(ctx, actor, release.ProductID, release.ID, "v1", []byte(`{"openapi":"3.1.0","info":{"title":"API","version":"1"},"paths":{"/health":{"get":{"responses":{"200":{"description":"ok"}}}}}}`))
	if err != nil {
		t.Fatalf("contract: %v", err)
	}
	bundle, err := ledger.CreateReleaseBundle(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}

	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	subjects := map[string]string{
		"evidence":               evidence.ID,
		"evidence_item":          evidence.ID,
		"product":                release.ProductID,
		"release":                release.ID,
		"artifact":               artifact.ID,
		"sbom":                   sbom.ID,
		"vulnerability_scan":     scan.ID,
		"vex":                    vex.ID,
		"vulnerability_decision": decision.ID,
		"finding":                scan.Findings[0].ID,
		"vulnerability_finding":  scan.Findings[0].ID,
		"exception":              exception.ID,
		"build":                  build.ID,
		"build_attestation":      attestation.ID,
		"openapi_contract":       contract.ID,
		"release_bundle":         bundle.ID,
	}
	for subjectType, subjectID := range subjects {
		if !ledger.controlSubjectExistsLocked(actor.TenantID, subjectType, subjectID, release.ProductID, release.ID) {
			t.Fatalf("expected control subject %s/%s to exist", subjectType, subjectID)
		}
	}
	if ledger.controlSubjectExistsLocked(actor.TenantID, "unknown", "id", release.ProductID, release.ID) {
		t.Fatal("unknown control subject should not exist")
	}
	refs := []resourceRefs{
		ledger.refsForControlEvidenceSubjectLocked("evidence", evidence.ID, "", ""),
		ledger.refsForControlEvidenceSubjectLocked("build_attestation", attestation.ID, "", ""),
		ledger.refsForControlEvidenceSubjectLocked("vulnerability_scan", scan.ID, "", ""),
		ledger.refsForControlEvidenceSubjectLocked("openapi_contract", contract.ID, "", ""),
		ledger.refsForControlEvidenceSubjectLocked("release_bundle", bundle.ID, "", ""),
		ledger.refsForControlEvidenceSubjectLocked("customer_package", "pkg_1", "", ""),
	}
	if refs[0].ProductID != release.ProductID || refs[1].BuildID != build.ID || refs[5].CustomerPackageID != "pkg_1" {
		t.Fatalf("unexpected refs: %#v", refs)
	}
	for subjectType, subjectID := range map[string]string{
		"evidence": evidence.ID, "sbom": sbom.ID, "vulnerability_scan": scan.ID, "vex": vex.ID,
		"vulnerability_decision": decision.ID, "exception": exception.ID, "build": build.ID,
		"build_attestation": attestation.ID, "openapi_contract": contract.ID, "release_bundle": bundle.ID,
	} {
		if got := ledger.controlEvidenceTimeLocked(domain.ControlEvidence{SubjectType: subjectType, SubjectID: subjectID, CreatedAt: fixedNow().Add(-time.Hour)}); got.IsZero() {
			t.Fatalf("zero evidence time for %s", subjectType)
		}
	}
}
