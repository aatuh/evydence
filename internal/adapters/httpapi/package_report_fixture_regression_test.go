package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

type packageReportFixtureScope struct {
	controlFixtureScope
	bundle domain.ReleaseBundle
}

func seedPackageReportFixtureScope(t *testing.T, ledger *app.Ledger, name string) packageReportFixtureScope {
	t.Helper()
	f := packageReportFixtureScope{controlFixtureScope: seedControlFixtureScope(t, ledger, name)}
	for _, kind := range []string{"sbom", "vex"} {
		control, err := ledger.CreateSecurityControl(t.Context(), f.actor, app.CreateSecurityControlInput{FrameworkID: f.framework.ID, Code: strings.ToUpper(kind), Title: kind + " review", Objective: "Record " + kind, EvidenceRequirements: []domain.ControlEvidenceRequirement{{Type: kind, Required: true}}, Limitations: []string{"Review required"}})
		if err != nil {
			t.Fatal("report control", kind, err)
		}
		if kind == "vex" {
			exception, err := ledger.CreateException(t.Context(), f.actor, app.CreateExceptionInput{ReleaseID: f.release.ID, ControlID: control.ID, Reason: "Recorded exception", Owner: "Security Team", ExpiresAt: f.release.CreatedAt.Add(time.Hour)})
			if err != nil {
				t.Fatal("report exception:", err)
			}
			if _, err := ledger.ApproveException(t.Context(), f.actor, exception.ID); err != nil {
				t.Fatal("report exception approval:", err)
			}
		}
	}
	if _, err := ledger.LinkControlEvidence(t.Context(), f.actor, f.control.ID, app.LinkControlEvidenceInput{EvidenceType: "build", SubjectType: "evidence", SubjectID: f.evidence.ID, ProductID: f.product.ID, ReleaseID: f.release.ID, Confidence: "high", Notes: "Recorded link"}); err != nil {
		t.Fatal("report control evidence:", err)
	}
	scan, err := ledger.UploadVulnerabilityScan(t.Context(), f.actor, []byte(fmt.Sprintf(`{"scanner":"grype","target_ref":"pkg:oci/report","release_id":%q,"findings":[{"vulnerability":"CVE-2026-0001","component":"api","severity":"high","state":"open"}]}`, f.release.ID)))
	if err != nil || len(scan.Findings) != 1 {
		t.Fatal("report scan:", err)
	}
	due, reviewed := f.release.CreatedAt.Add(24*time.Hour), f.release.CreatedAt
	if _, err := ledger.CreateVulnerabilityDecision(t.Context(), f.actor, scan.Findings[0].ID, app.CreateVulnerabilityDecisionInput{Status: "fixed", Justification: "Reviewed", ImpactStatement: "Patched", ActionStatement: "Ship patch", InternalNotes: "private-triage-" + name, EvidenceIDs: []string{f.evidence.ID}, SupportingRefs: []domain.SubjectRef{{Type: "incident", ID: f.incident.ID}}, ReviewedAt: &reviewed, ReviewDueAt: &due}); err != nil {
		t.Fatal("report fixed decision:", err)
	}
	if _, err := ledger.CreateRemediationTask(t.Context(), f.actor, app.CreateRemediationTaskInput{IncidentID: f.incident.ID, ReleaseID: f.release.ID, Title: "Patch", Owner: "Security Team", DueAt: &due, EvidenceID: f.evidence.ID}); err != nil {
		t.Fatal("report remediation task:", err)
	}
	f.bundle, err = ledger.CreateReleaseBundle(t.Context(), f.actor, f.release.ID)
	if err != nil {
		t.Fatal("report bundle:", err)
	}
	return f
}

func TestPackageReportFixturesPreserveCompleteResponsesAuthorityPrivacyAndReadOnlyState(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedPackageReportFixtureScope(t, ledger, "Owner")
	foreign := seedPackageReportFixtureScope(t, ledger, "Foreign")
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "reader", Scopes: []string{"report:read", "verify:read", "bundle:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"report:read", "verify:read", "bundle:read"}}}}
	auth := &configuredAuthenticator{actor: human}
	server.authn = auth
	filter := packagequery.ControlCoverageFilter{FrameworkID: owner.framework.ID, ProductID: owner.product.ID, ReleaseID: owner.release.ID}
	coverage, err := ledger.ControlCoverageReport(t.Context(), human, app.ControlCoverageReportInput(filter))
	if err != nil || len(coverage.Controls) != 3 || len(coverage.MissingEvidence) == 0 || len(coverage.AcceptedExceptions) != 1 {
		t.Fatal("coverage fixture lacks meaningful nested data", err)
	}
	cra, err := ledger.CRAReadinessReport(t.Context(), human, app.CRAReadinessReportInput{ProductID: owner.product.ID, ReleaseID: owner.release.ID})
	if err != nil {
		t.Fatal(err)
	}
	handling, err := ledger.CRAVulnerabilityHandlingReport(t.Context(), human, owner.product.ID, owner.release.ID)
	if err != nil || len(handling.Decisions) != 1 || handling.Decisions[0].ReviewedAt == nil || len(handling.AcceptedExceptions) != 1 {
		t.Fatal("handling fixture lacks decision/exception metadata", err)
	}
	update, err := ledger.SecurityUpdateEvidenceReport(t.Context(), human, owner.product.ID, owner.release.ID)
	if err != nil || len(update.FixedDecisions) != 1 || len(update.Incidents) != 1 || len(update.RemediationTasks) != 1 || update.RemediationTasks[0].DueAt == nil {
		t.Fatal("update fixture lacks fixed decisions/incident/task", err)
	}
	readiness, err := ledger.ReleaseReadinessReport(t.Context(), domain.Actor{TenantID: human.TenantID, KeyID: "fixture-owned-readiness-reader", Scopes: []string{"verify:read"}}, owner.release.ID)
	if err != nil {
		t.Fatal(err)
	}
	missing := []string{}
	for _, check := range readiness.Checks {
		missing = append(missing, check.Missing...)
	}
	sort.Strings(missing)
	wantMissing := map[string]any{"report_type": "missing_evidence", "template_version": "missing-evidence.v1.0.0", "release_id": owner.release.ID, "result": readiness.Result, "missing": missing, "assumptions": []string{"This report supports compliance readiness and is not a legal compliance conclusion."}, "limitations": []string{"Missing evidence is based only on evidence recorded in this Evydence instance."}}
	coordinates := "product_id=" + owner.product.ID + "&release_id=" + owner.release.ID
	requests := []struct {
		path string
		want any
	}{
		{"/v1/reports/missing-evidence?release_id=" + owner.release.ID, wantMissing},
		{"/v1/reports/control-coverage?framework_id=" + owner.framework.ID + "&" + coordinates, coverage},
		{"/v1/reports/cra-readiness?" + coordinates, cra},
		{"/v1/reports/cra-vulnerability-handling?" + coordinates, handling},
		{"/v1/reports/security-update-evidence?" + coordinates, update},
		{"/v1/release-bundles/" + owner.bundle.ID, owner.bundle},
		{"/v1/release-bundles/" + owner.bundle.ID + "/manifest", owner.bundle.Manifest},
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range requests {
		out := getRaw(t, server, "fixture-auth", request.path, 200)
		want, err := json.Marshal(map[string]any{"data": request.want, "meta": map[string]string{"api_version": "v1"}})
		if err != nil {
			t.Fatal(err)
		}
		assertTrustHTTPReplay(t, string(want), out.Body.String())
		for _, private := range []string{"private-triage", "internal_notes", foreign.product.ID, foreign.release.ID, foreign.bundle.ID} {
			if strings.Contains(out.Body.String(), private) {
				t.Fatal("package report leaked private/foreign data", request.path, private)
			}
		}
	}
	for _, grants := range [][]domain.ResourceGrant{nil, {{ResourceType: "product", ResourceID: foreign.product.ID, Scopes: []string{"*"}}}} {
		auth.actor.ResourceGrants = grants
		for _, request := range requests {
			getRaw(t, server, "fixture-auth", request.path, 403)
		}
	}
	auth.actor = human
	for _, request := range requests {
		foreignPath := strings.NewReplacer(owner.product.ID, foreign.product.ID, owner.release.ID, foreign.release.ID, owner.framework.ID, foreign.framework.ID, owner.bundle.ID, foreign.bundle.ID).Replace(request.path)
		getRaw(t, server, "fixture-auth", foreignPath, 404)
		if strings.Contains(request.path, "?") {
			getRaw(t, server, "fixture-auth", request.path+"&release_id="+foreign.release.ID, 400)
		}
	}
	base := catalogFixtureCommands{ledger: ledger}
	projectedCoverage, err := (packageCoverageFixture{base}).Coverage(t.Context(), human, filter)
	if err != nil {
		t.Fatal(err)
	}
	*projectedCoverage.AcceptedExceptions[0].ApprovedAt = projectedCoverage.AcceptedExceptions[0].ApprovedAt.AddDate(1, 0, 0)
	projectedCoverage.MissingEvidence[0], projectedCoverage.Limitations[0] = "modified", "modified"
	for index := range projectedCoverage.Controls {
		v := &projectedCoverage.Controls[index]
		v.Title = "modified"
		if len(v.LinkedEvidence) > 0 {
			v.LinkedEvidence[0].Notes = "modified"
		}
		if len(v.Missing) > 0 {
			v.Missing[0] = "modified"
		}
		if len(v.Limitations) > 0 {
			v.Limitations[0] = "modified"
		}
	}
	projectedHandling, err := (packageHandlingFixture{base}).Report(t.Context(), human, owner.product.ID, owner.release.ID)
	if err != nil {
		t.Fatal(err)
	}
	projectedHandling.Summary["findings_total"] = -1
	projectedHandling.EvidenceIDs[0], projectedHandling.Decisions[0].EvidenceIDs[0] = "modified", "modified"
	projectedHandling.Decisions[0].SupportingRefs[0].ID = "modified"
	*projectedHandling.Decisions[0].ReviewedAt = projectedHandling.Decisions[0].ReviewedAt.AddDate(1, 0, 0)
	*projectedHandling.Decisions[0].ReviewDueAt = projectedHandling.Decisions[0].ReviewDueAt.AddDate(1, 0, 0)
	projectedUpdate, err := (packageUpdateFixture{base}).Report(t.Context(), human, owner.product.ID, owner.release.ID)
	if err != nil {
		t.Fatal(err)
	}
	projectedUpdate.Summary["incidents_total"] = -1
	projectedUpdate.Incidents[0].Title = "modified"
	*projectedUpdate.RemediationTasks[0].DueAt = projectedUpdate.RemediationTasks[0].DueAt.AddDate(1, 0, 0)
	projectedBundle, err := (packageBundleReadFixture{base}).GetReleaseBundle(t.Context(), human, owner.bundle.ID)
	if err != nil {
		t.Fatal(err)
	}
	projectedBundle.Manifest["modified"] = true
	releaseManifest, ok := projectedBundle.Manifest["release"].(map[string]any)
	if !ok {
		t.Fatal("bundle fixture lacks nested release manifest")
	}
	releaseManifest["state"] = "modified"
	projectedBundle.SignatureRefs[0] = "modified"
	for _, request := range requests {
		out := getRaw(t, server, "fixture-auth", request.path, 200)
		want, err := json.Marshal(map[string]any{"data": request.want, "meta": map[string]string{"api_version": "v1"}})
		if err != nil {
			t.Fatal(err)
		}
		assertTrustHTTPReplay(t, string(want), out.Body.String())
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, check := range []func(context.Context) error{
		func(ctx context.Context) error {
			_, err := (packageCoverageFixture{base}).Coverage(ctx, human, filter)
			return err
		},
		func(ctx context.Context) error {
			_, err := (packageCoverageFixture{base}).CRAReadiness(ctx, human, owner.product.ID, owner.release.ID)
			return err
		},
		func(ctx context.Context) error {
			_, err := (packageHandlingFixture{base}).Report(ctx, human, owner.product.ID, owner.release.ID)
			return err
		},
		func(ctx context.Context) error {
			_, err := (packageUpdateFixture{base}).Report(ctx, human, owner.product.ID, owner.release.ID)
			return err
		},
		func(ctx context.Context) error {
			_, err := (packageBundleReadFixture{base}).GetReleaseBundle(ctx, human, owner.bundle.ID)
			return err
		},
		func(ctx context.Context) error {
			_, err := (packageMissingFixture{base}).Report(ctx, human, owner.release.ID)
			return err
		},
	} {
		if err := check(cancelled); !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled package report accepted", err)
		}
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("package reads/denials/metadata mutation wrote effects, including missing-evidence evaluation/audit", err)
	}
}
