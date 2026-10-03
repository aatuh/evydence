package domain

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func TestVEXContextMappersPreserveWireFieldsAndDefensiveCopies(t *testing.T) {
	at := time.Date(2026, 10, 3, 12, 0, 0, 123456000, time.UTC)
	in := evidencedomain.VEXDocument{ID: "vex", TenantID: "tenant", EvidenceID: "evidence", ReleaseID: "release", ArtifactID: "artifact", Format: "openvex", Author: "author", Version: "1", StatementCount: 2, StatusSummary: map[string]int{"fixed": 1}, SchemaVersion: evidencedomain.VEXDocumentSchemaVersion, CreatedAt: at}
	v := VEXDocumentFromContext(in)
	expected := VEXDocument{ID: "vex", TenantID: "tenant", EvidenceID: "evidence", ReleaseID: "release", ArtifactID: "artifact", Format: "openvex", Author: "author", Version: "1", StatementCount: 2, StatusSummary: map[string]int{"fixed": 1}, SchemaVersion: evidencedomain.VEXDocumentSchemaVersion, CreatedAt: at}
	if !reflect.DeepEqual(v, expected) {
		t.Fatal("VEX public fields changed", v)
	}
	data, err := json.Marshal(v)
	if err != nil || !json.Valid(data) {
		t.Fatal(err)
	}
	v.StatusSummary["fixed"] = 99
	if in.StatusSummary["fixed"] != 1 {
		t.Fatal("VEX summary aliases input")
	}
	r := evidencedomain.VEXImportReport{ID: "report", TenantID: "tenant", VEXDocumentID: "vex", EvidenceID: "evidence", ReleaseID: "release", ArtifactID: "artifact", ParserVersion: "parser", Status: "accepted", StatementCount: 2, DecisionsCreated: 3, DecisionsSuperseded: 1, UnsupportedFields: []string{"field"}, Warnings: []string{"warning"}, InvalidStatements: []evidencedomain.VEXImportIssue{{StatementIndex: 2, Code: "invalid", Detail: "detail"}}, MappingFailures: []evidencedomain.VEXImportIssue{{StatementIndex: 1, Code: "mapping", Detail: "failure"}}, FailureCode: "safe_failure", FailureDetail: "Safe detail.", SchemaVersion: evidencedomain.VEXImportReportSchemaVersion, CreatedAt: at, UpdatedAt: at}
	report := VEXImportReportFromContext(r)
	want := VEXImportReport{ID: r.ID, TenantID: r.TenantID, VEXDocumentID: r.VEXDocumentID, EvidenceID: r.EvidenceID, ReleaseID: r.ReleaseID, ArtifactID: r.ArtifactID, ParserVersion: r.ParserVersion, Status: r.Status, StatementCount: r.StatementCount, DecisionsCreated: r.DecisionsCreated, DecisionsSuperseded: r.DecisionsSuperseded, UnsupportedFields: []string{"field"}, Warnings: []string{"warning"}, InvalidStatements: []VEXImportIssue{{StatementIndex: 2, Code: "invalid", Detail: "detail"}}, MappingFailures: []VEXImportIssue{{StatementIndex: 1, Code: "mapping", Detail: "failure"}}, FailureCode: r.FailureCode, FailureDetail: r.FailureDetail, SchemaVersion: r.SchemaVersion, CreatedAt: at, UpdatedAt: at}
	if !reflect.DeepEqual(report, want) {
		t.Fatal("report public fields changed", report)
	}
	report.UnsupportedFields[0], report.Warnings[0], report.InvalidStatements[0].Detail, report.MappingFailures[0].Code = "changed", "changed", "changed", "changed"
	if r.UnsupportedFields[0] != "field" || r.Warnings[0] != "warning" || r.InvalidStatements[0].Detail != "detail" || r.MappingFailures[0].Code != "mapping" {
		t.Fatal("report aliases input")
	}
	for _, empty := range []evidencedomain.VEXDocument{{}, {StatusSummary: map[string]int{}}} {
		if (VEXDocumentFromContext(empty).StatusSummary == nil) != (empty.StatusSummary == nil) {
			t.Fatal("nil/empty VEX summary changed")
		}
	}
	zero := VEXImportReportFromContext(evidencedomain.VEXImportReport{})
	if zero.Warnings != nil || zero.UnsupportedFields != nil || zero.InvalidStatements == nil || zero.MappingFailures == nil {
		t.Fatal("report compatibility container shapes changed", zero)
	}
}
