package domain

import (
	"reflect"
	"testing"
	"time"

	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func TestCustomPolicyContextMappingPreservesEveryFieldAndOwnsSlices(t *testing.T) {
	p := riskdomain.CustomPolicy{ID: "policy", TenantID: "tenant", Name: "Name", Version: "version", Description: "description", Rules: []riskdomain.PolicyRule{{Name: "r", EvidenceType: "sbom", Severity: "label", Required: true}}, SchemaVersion: "schema", CreatedAt: time.Date(2026, 10, 3, 12, 0, 0, 123456000, time.UTC)}
	dto := CustomPolicyFromContext(p)
	if v := CustomPolicyToContext(dto); !reflect.DeepEqual(v, p) {
		t.Fatal("policy context round trip", v, p)
	}
	dto.Rules[0].Name = "changed"
	if p.Rules[0].Name != "r" {
		t.Fatal("rule slice aliased")
	}
	checks := []riskdomain.PolicyCheck{{Name: "r", Result: "failed", Severity: "label", Missing: []string{"sbom"}, Explanation: "explanation", Remediation: "remediation"}}
	e := CustomPolicyEvaluationFromContext(riskdomain.CustomPolicyEvaluation{ID: "evaluation", TenantID: "tenant", PolicyID: "policy", ReleaseID: "release", Result: "failed", Checks: checks, InputHash: "hash", SchemaVersion: "schema", CreatedAt: p.CreatedAt})
	want := CustomPolicyEvaluation{ID: "evaluation", TenantID: "tenant", PolicyID: "policy", ReleaseID: "release", Result: "failed", Checks: []PolicyCheck{{Name: "r", Result: "failed", Severity: "label", Missing: []string{"sbom"}, Explanation: "explanation", Remediation: "remediation"}}, InputHash: "hash", SchemaVersion: "schema", CreatedAt: p.CreatedAt}
	if !reflect.DeepEqual(e, want) {
		t.Fatal("evaluation field loss", e, want)
	}
	e.Checks[0].Missing[0] = "changed"
	if checks[0].Missing[0] != "sbom" {
		t.Fatal("missing slice aliased")
	}
	if CustomPolicyFromContext(riskdomain.CustomPolicy{}).Rules != nil || CustomPolicyToContext(CustomPolicy{}).Rules != nil || CustomPolicyChecksFromContext(nil) != nil {
		t.Fatal("nil containers changed")
	}
}
