package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestAppReadListLifecycleAndReportGaps(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)

	if !ledger.HasTenants() {
		t.Fatal("bootstrap fixture should create a tenant")
	}
	if _, err := ledger.ApproveRelease(ctx, actor, release.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("approve draft release err=%v, want conflict", err)
	}
	frozen, err := ledger.FreezeRelease(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("freeze release: %v", err)
	}
	if frozen.State != "frozen" || frozen.FrozenAt == nil {
		t.Fatalf("frozen release = %#v", frozen)
	}
	approved, err := ledger.ApproveRelease(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("approve release: %v", err)
	}
	if approved.State != "approved" || approved.ApprovedAt == nil {
		t.Fatalf("approved release = %#v", approved)
	}
	if _, err := ledger.FreezeRelease(ctx, actor, release.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("freeze approved release err=%v, want conflict", err)
	}

	original, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ProductID: release.ProductID, ReleaseID: release.ID, Type: "security_review", Title: "Original", PayloadHash: sampleDigest("original")})
	if err != nil {
		t.Fatalf("original evidence: %v", err)
	}
	replacement, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ProductID: release.ProductID, Type: "security_review", Title: "Replacement", PayloadHash: sampleDigest("replacement")})
	if err != nil {
		t.Fatalf("replacement evidence: %v", err)
	}
	linked, err := ledger.LinkEvidence(ctx, actor, replacement.ID, "release", release.ID)
	if err != nil {
		t.Fatalf("link evidence: %v", err)
	}
	if linked.ReleaseID != release.ID {
		t.Fatalf("linked release_id=%q want %q", linked.ReleaseID, release.ID)
	}
	superseded, err := ledger.SupersedeEvidence(ctx, actor, original.ID, replacement.ID, "newer review")
	if err != nil {
		t.Fatalf("supersede evidence: %v", err)
	}
	if superseded.SupersededBy != replacement.ID {
		t.Fatalf("superseded evidence = %#v", superseded)
	}
	if _, err := ledger.SupersedeEvidence(ctx, actor, original.ID, replacement.ID, "again"); !errors.Is(err, ErrConflict) {
		t.Fatalf("repeat supersede err=%v, want conflict", err)
	}
	listed, err := ledger.ListEvidence(ctx, actor, release.ID, "security_review")
	if err != nil {
		t.Fatalf("list evidence: %v", err)
	}
	if len(listed) != 2 {
		t.Fatalf("security_review evidence count=%d want 2: %#v", len(listed), listed)
	}

	sbom, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"api","purl":"pkg:oci/api"}]}`))
	if err != nil {
		t.Fatalf("sbom: %v", err)
	}
	if got, err := ledger.GetSBOM(ctx, actor, sbom.ID); err != nil || got.ID != sbom.ID {
		t.Fatalf("get sbom=%#v err=%v", got, err)
	}
	scan, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{"scanner":"grype","target_ref":"pkg:oci/api","release_id":"`+release.ID+`","findings":[]}`))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if got, err := ledger.GetVulnerabilityScan(ctx, actor, scan.ID); err != nil || got.ID != scan.ID {
		t.Fatalf("get scan=%#v err=%v", got, err)
	}
	contract, err := ledger.UploadOpenAPIContract(ctx, actor, release.ProductID, release.ID, "v1", []byte(`{"openapi":"3.1.0","info":{"title":"API","version":"1"},"paths":{"/health":{"get":{"responses":{"200":{"description":"ok"}}}}}}`))
	if err != nil {
		t.Fatalf("openapi: %v", err)
	}
	if got, err := ledger.GetOpenAPIContract(ctx, actor, contract.ID); err != nil || got.ID != contract.ID {
		t.Fatalf("get contract=%#v err=%v", got, err)
	}
	vex, err := ledger.UploadVEX(ctx, actor, release.ID, artifact.ID, []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex","author":"security@example.test","timestamp":"2026-05-28T12:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-2026-0000"},"products":[{"@id":"pkg:oci/api"}],"status":"fixed","justification":"fixed","impact_statement":"fixed","action_statement":"none"}]}`))
	if err != nil {
		t.Fatalf("vex: %v", err)
	}
	if got, err := ledger.GetVEXDocument(ctx, actor, vex.ID); err != nil || got.ID != vex.ID {
		t.Fatalf("get vex=%#v err=%v", got, err)
	}

	bundle, err := ledger.CreateReleaseBundle(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if got, err := ledger.GetReleaseBundle(ctx, actor, bundle.ID); err != nil || got.ID != bundle.ID {
		t.Fatalf("get bundle=%#v err=%v", got, err)
	}
	report, err := ledger.MissingEvidenceReport(ctx, actor, release.ID)
	if err != nil {
		t.Fatalf("missing evidence report: %v", err)
	}
	if report["report_type"] != "missing_evidence" || report["release_id"] != release.ID {
		t.Fatalf("missing evidence report = %#v", report)
	}

	keysBefore, err := ledger.ListSigningKeys(ctx, actor)
	if err != nil || len(keysBefore) == 0 {
		t.Fatalf("signing keys before=%#v err=%v", keysBefore, err)
	}
	rotated, err := ledger.RotateSigningKey(ctx, actor, "scheduled rotation")
	if err != nil {
		t.Fatalf("rotate signing key: %v", err)
	}
	if rotated.Private != nil || rotated.Status != "active" {
		t.Fatalf("public rotated key leaked private material: %#v", rotated)
	}
	revoked, err := ledger.RevokeSigningKey(ctx, actor, keysBefore[0].ID, "retire old key")
	if err != nil {
		t.Fatalf("revoke signing key: %v", err)
	}
	if revoked.Status != "revoked" || revoked.RevokedAt == nil {
		t.Fatalf("revoked key = %#v", revoked)
	}
}

func TestAppListAndScopeHelperGaps(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)

	collector, _, _, err := ledger.CreateCollector(ctx, actor, CreateCollectorInput{Name: "gha", Type: "github_actions", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("collector: %v", err)
	}
	collectors, err := ledger.ListCollectors(ctx, actor)
	if err != nil || len(collectors) != 1 || collectors[0].ID != collector.ID {
		t.Fatalf("collectors=%#v err=%v", collectors, err)
	}

	framework, err := ledger.CreateControlFramework(ctx, actor, CreateControlFrameworkInput{Name: "Framework", Slug: "fw", Version: "1"})
	if err != nil {
		t.Fatalf("framework: %v", err)
	}
	listedFrameworks, err := ledger.ListControlFrameworks(ctx, actor)
	if err != nil || len(listedFrameworks) != 1 || listedFrameworks[0].ID != framework.ID {
		t.Fatalf("frameworks=%#v err=%v", listedFrameworks, err)
	}
	control, err := ledger.CreateSecurityControl(ctx, actor, CreateSecurityControlInput{
		FrameworkID: framework.ID,
		Code:        "BUILD",
		Title:       "Build evidence",
		Objective:   "Build evidence exists.",
		EvidenceRequirements: []domain.ControlEvidenceRequirement{{
			Type:     "build",
			Required: true,
		}},
	})
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	buildProject, err := ledger.CreateProject(ctx, actor, release.ProductID, "control-build")
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	build, err := ledger.CreateBuildRun(ctx, actor, CreateBuildRunInput{
		ProjectID: buildProject.ID,
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
	link, err := ledger.LinkControlEvidence(ctx, actor, control.ID, LinkControlEvidenceInput{EvidenceType: "build", SubjectType: "build", SubjectID: build.ID, ProductID: release.ProductID, ReleaseID: release.ID, Confidence: "medium"})
	if err != nil {
		t.Fatalf("link control evidence: %v", err)
	}
	links, err := ledger.ListControlEvidence(ctx, actor, control.ID, release.ProductID, release.ID)
	if err != nil || len(links) != 1 || links[0].ID != link.ID {
		t.Fatalf("control links=%#v err=%v", links, err)
	}
	if _, err := ledger.LinkControlEvidence(ctx, actor, control.ID, LinkControlEvidenceInput{EvidenceType: "build", SubjectType: "missing", SubjectID: "missing", ProductID: release.ProductID, ReleaseID: release.ID, Confidence: "unsupported"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing subject err=%v, want not found", err)
	}

	ex, err := ledger.CreateException(ctx, actor, CreateExceptionInput{ReleaseID: release.ID, ControlID: control.ID, Reason: "temporary control waiver", Owner: "security", ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("exception: %v", err)
	}
	exceptions, err := ledger.ListExceptions(ctx, actor, release.ID)
	if err != nil || len(exceptions) != 1 || exceptions[0].ID != ex.ID {
		t.Fatalf("exceptions=%#v err=%v", exceptions, err)
	}

	if !(domain.Actor{Scopes: []string{"*"}}).HasScope("anything") {
		t.Fatal("wildcard actor should satisfy arbitrary scope")
	}
	if (domain.Actor{Scopes: []string{"evidence:read"}}).HasScope("evidence:write") {
		t.Fatal("read-only actor should not satisfy write scope")
	}
	for _, err := range []error{ErrValidation, ErrUnauthorized, ErrForbidden, ErrNotFound, ErrConflict, ErrIdempotencyConflict, ErrVerificationFailed, errors.New("raw sql detail")} {
		if ProblemCode(err) == "" || StatusCode(err) == 0 || SafeErrorDetail(err) == "" {
			t.Fatalf("problem mapping incomplete for %v", err)
		}
	}
	if !IsValidation(ErrValidation) || IsValidation(ErrForbidden) {
		t.Fatal("validation helper returned unexpected result")
	}
}
