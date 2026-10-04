package app

import (
	"errors"
	"strings"
	"testing"
)

func TestAnomalyReportReturnedSlicesCannotMutateStoredRecord(t *testing.T) {
	l := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	a, release, _ := setupReleaseRiskFixture(t, l)
	v, err := l.GenerateAnomalyReport(t.Context(), a, AnomalyReportInput{SubjectType: "release", SubjectID: release.ID})
	if err != nil || len(v.Signals) == 0 {
		t.Fatal("expected deterministic missing-evidence signals", err)
	}
	v.Signals[0].Detail = "changed"
	v.Assumptions[0] = "changed"
	v.Limitations[0] = "changed"
	stored := l.anomalyReports[v.ID]
	if stored.Signals[0].Detail == "changed" || stored.Assumptions[0] == "changed" || stored.Limitations[0] == "changed" {
		t.Fatal("caller mutated immutable anomaly record")
	}
}

func TestAnomalyReportRawInputBoundsPrecedeTrimming(t *testing.T) {
	l := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	a, release, _ := setupReleaseRiskFixture(t, l)
	before, audit := len(l.anomalyReports), len(l.chain[a.TenantID])
	for _, in := range []AnomalyReportInput{
		{SubjectType: strings.Repeat(" ", 129) + "release", SubjectID: release.ID},
		{SubjectType: "release", SubjectID: strings.Repeat(" ", 1025) + release.ID},
		{SubjectType: "release", SubjectID: "bad\x00"},
		{SubjectType: "release", SubjectID: string([]byte{255})},
	} {
		v, err := l.GenerateAnomalyReport(t.Context(), a, in)
		if !errors.Is(err, ErrValidation) || v.ID != "" || len(l.anomalyReports) != before || len(l.chain[a.TenantID]) != audit {
			t.Fatal("invalid raw anomaly input published effects", v.ID, err)
		}
	}
}
