package app

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestPreviewVEXDecisionEffectsPreservesMatchingAndAdvisoryCounts(t *testing.T) {
	for _, format := range []string{"openvex", "cyclonedx"} {
		for _, kind := range []string{"single", "multiple-products", "missing", "ambiguous", "empty-component", "duplicate-statement", "unscoped"} {
			t.Run(format+"/"+kind, func(t *testing.T) {
				statement := VEXStatement{Index: 2, Vulnerability: "CVE-TEST", Products: []string{"pkg:a", "pkg:b"}, Status: "fixed"}
				in := VEXDecisionPreviewInput{Format: format, TenantID: "tenant", ReleaseID: "release", Statements: []VEXStatement{statement}, Findings: []VEXPreviewFinding{{VEXFinding: VEXFinding{ID: "finding", ScanID: "scan", TenantID: "tenant", ReleaseID: "release", Vulnerability: "CVE-TEST", Component: "pkg:a"}, HasActiveDecision: true}}}
				want, replaced, failure := 1, 1, ""
				switch kind {
				case "multiple-products", "ambiguous", "empty-component", "unscoped":
					other := in.Findings[0]
					other.ID, other.ScanID, other.Component, other.HasActiveDecision = "second", "second-scan", "pkg:b", false
					in.Findings = append(in.Findings, other)
					want = 2
					if kind == "ambiguous" {
						in.Findings[1].Component = "pkg:a"
					}
					if kind == "empty-component" {
						in.Findings[1].Component = ""
					}
					if kind == "unscoped" {
						in.Statements[0].Products = nil
					}
					if kind != "multiple-products" {
						want, replaced, failure = 0, 0, "ambiguous_finding"
					}
				case "missing":
					in.Findings = nil
					want, replaced, failure = 0, 0, "finding_not_found"
				case "duplicate-statement":
					in.Statements = append(in.Statements, statement)
					in.Statements[1].Index = 3
				}
				before := append([]VEXPreviewFinding(nil), in.Findings...)
				out, err := PreviewVEXDecisionEffects(in)
				if err != nil || out.WouldCreate != want || out.WouldSupersede != replaced || !reflect.DeepEqual(in.Findings, before) {
					t.Fatal("preview counts or inputs changed", out, err)
				}
				if failure == "" && len(out.Failures) != 0 || failure != "" && (len(out.Failures) != 1 || out.Failures[0].Code != failure || out.Failures[0].StatementIndex != 2) {
					t.Fatal("mapping issue changed", out)
				}
				if kind == "duplicate-statement" && (len(out.Warnings) != 1 || !strings.Contains(out.Warnings[0], "Duplicate")) {
					t.Fatal("duplicate warning changed", out)
				}
			})
		}
	}
}

func TestPreviewVEXDecisionEffectsRejectsForeignOrInvalidProjections(t *testing.T) {
	for _, kind := range []string{"format", "foreign", "release", "missing-id", "duplicate-id", "status", "index"} {
		in := VEXDecisionPreviewInput{Format: "openvex", TenantID: "tenant", ReleaseID: "release", Statements: []VEXStatement{{Index: 1, Vulnerability: "CVE-TEST", Products: []string{"pkg:a"}, Status: "fixed"}}, Findings: []VEXPreviewFinding{{VEXFinding: VEXFinding{ID: "finding", ScanID: "scan", TenantID: "tenant", ReleaseID: "release", Vulnerability: "CVE-TEST", Component: "pkg:a"}}}}
		want := ErrValidation
		switch kind {
		case "format":
			in.Format = "unsupported"
		case "foreign":
			in.Findings[0].TenantID = "other"
			want = ErrNotFound
		case "release":
			in.Findings[0].ReleaseID = "other"
			want = ErrNotFound
		case "missing-id":
			in.Findings[0].ID = ""
		case "duplicate-id":
			in.Findings = append(in.Findings, in.Findings[0])
		case "status":
			in.Statements[0].Status = "unsupported"
		case "index":
			in.Statements[0].Index = 0
		}
		out, err := PreviewVEXDecisionEffects(in)
		if !errors.Is(err, want) || out.WouldCreate+out.WouldSupersede+len(out.Failures) != 0 {
			t.Fatal(kind, out, err)
		}
	}
}
