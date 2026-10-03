package domain

import (
	"reflect"
	"testing"
	"time"

	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func TestSecurityDocumentContextDTOsPreserveEveryFieldAndCopySummary(t *testing.T) {
	v := evidencedomain.SecurityScan{ID: "scan", TenantID: "tenant", ProductID: "product", ReleaseID: "release", ArtifactID: "artifact", Category: "secret_scan", Format: "generic", Scanner: "scanner", TargetRef: "target", EvidenceID: "evidence", PayloadRef: "object://payload", PayloadHash: "sha256:hash", FindingCount: 1, Summary: map[string]int{"critical": 1}, Redacted: true, Quarantined: true, SchemaVersion: "version", CreatedAt: time.Date(2026, 10, 3, 1, 2, 3, 0, time.UTC)}
	out := SecurityScanFromContext(v)
	assertFields := func(source, dto any) {
		t.Helper()
		a, b := reflect.ValueOf(source), reflect.ValueOf(dto)
		for i := 0; i < a.NumField(); i++ {
			name := a.Type().Field(i).Name
			field := b.FieldByName(name)
			if !field.IsValid() || !reflect.DeepEqual(a.Field(i).Interface(), field.Interface()) {
				t.Fatal("field loss", name, source, dto)
			}
		}
	}
	assertFields(v, out)
	out.Summary["critical"] = 2
	if v.Summary["critical"] != 1 {
		t.Fatal("summary aliases context")
	}
	d := evidencedomain.ManualSecurityDocument{ID: "doc", TenantID: "tenant", ProductID: "product", ReleaseID: "release", DocumentType: "security_review", Title: "Review", Sensitivity: "restricted", EvidenceID: "evidence", PayloadRef: "object://payload", PayloadHash: "sha256:hash", SchemaVersion: "version", CreatedAt: v.CreatedAt}
	assertFields(d, ManualSecurityDocumentFromContext(d))
}
