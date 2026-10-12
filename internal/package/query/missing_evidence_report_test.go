package query

import (
	"context"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type readinessEvaluatorFake struct{ result riskdomain.PolicyEvaluation }

func (f readinessEvaluatorFake) Preview(context.Context, identitydomain.Actor, string) (riskdomain.PolicyEvaluation, error) {
	return f.result, nil
}

func TestMissingEvidenceReportPreservesPublicShapeAndSort(t *testing.T) {
	service, err := NewMissingEvidenceReport(readinessEvaluatorFake{result: riskdomain.PolicyEvaluation{
		TenantID: "ten_1", ReleaseID: "rel_1", Result: "failed", Checks: []riskdomain.PolicyCheck{
			{Missing: []string{"vulnerability_scan", "artifact"}}, {Missing: []string{"sbom"}},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "user_1"}
	report, err := service.Report(context.Background(), actor, "rel_1")
	if err != nil || report["report_type"] != "missing_evidence" || report["template_version"] != "missing-evidence.v1.0.0" || report["result"] != "failed" {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	missing, ok := report["missing"].([]string)
	if !ok || len(missing) != 3 || missing[0] != "artifact" || missing[1] != "sbom" || missing[2] != "vulnerability_scan" {
		t.Fatalf("missing=%#v", report["missing"])
	}
}
