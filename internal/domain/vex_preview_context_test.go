package domain

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func TestVEXPreviewContextMapperPreservesWireFieldsAndDefensiveCopies(t *testing.T) {
	at := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	in := evidencedomain.VEXImportPreview{TenantID: "tenant", ReleaseID: "release", ArtifactID: "artifact", Format: "cyclonedx", ParserVersion: "parser", Advisory: true, StatementCount: 3, StatusSummary: map[string]int{"fixed": 2}, DecisionsWouldCreate: 1, DecisionsWouldSupersede: 1, Warnings: []string{"warning"}, InvalidStatements: []evidencedomain.VEXImportIssue{{StatementIndex: 3, Code: "invalid", Detail: "detail"}}, MappingFailures: []evidencedomain.VEXImportIssue{{StatementIndex: 2, Code: "mapping", Detail: "detail"}}, Assumptions: []string{"assumption"}, Limitations: []string{"limitation"}, SchemaVersion: evidencedomain.VEXImportPreviewSchemaVersion, GeneratedAt: at}
	want := VEXImportPreview{TenantID: in.TenantID, ReleaseID: in.ReleaseID, ArtifactID: in.ArtifactID, Format: in.Format, ParserVersion: in.ParserVersion, Advisory: true, StatementCount: 3, StatusSummary: map[string]int{"fixed": 2}, DecisionsWouldCreate: 1, DecisionsWouldSupersede: 1, Warnings: []string{"warning"}, InvalidStatements: []VEXImportIssue{{StatementIndex: 3, Code: "invalid", Detail: "detail"}}, MappingFailures: []VEXImportIssue{{StatementIndex: 2, Code: "mapping", Detail: "detail"}}, Assumptions: []string{"assumption"}, Limitations: []string{"limitation"}, SchemaVersion: in.SchemaVersion, GeneratedAt: at}
	out := VEXImportPreviewFromContext(in)
	if !reflect.DeepEqual(out, want) {
		t.Fatal("preview fields changed", out)
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := json.Marshal(want)
	if err != nil || string(encoded) != string(expected) {
		t.Fatal("preview wire shape changed", string(encoded), err)
	}
	out.StatusSummary["fixed"], out.Warnings[0], out.Assumptions[0], out.Limitations[0], out.InvalidStatements[0].Code, out.MappingFailures[0].Detail = 99, "changed", "changed", "changed", "changed", "changed"
	if in.StatusSummary["fixed"] != 2 || in.Warnings[0] != "warning" || in.Assumptions[0] != "assumption" || in.Limitations[0] != "limitation" || in.InvalidStatements[0].Code != "invalid" || in.MappingFailures[0].Detail != "detail" {
		t.Fatal("preview aliases context model")
	}
}
