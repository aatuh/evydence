package app

import (
	"errors"
	"testing"
)

func TestPDFReportRejectsMismatchedRootsBeforeEffects(t *testing.T) {
	l := newLegacyLedgerFixture(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	a, release, _ := setupReleaseRiskFixture(t, l)
	other, err := l.CreateProduct(t.Context(), a, "Other", "other")
	if err != nil {
		t.Fatal(err)
	}
	reports, audit := len(l.pdfReports), len(l.chain[a.TenantID])
	v, err := l.CreatePDFReportPackage(t.Context(), a, CreatePDFReportPackageInput{ReportType: "release_readiness", ProductID: other.ID, ReleaseID: release.ID, Title: "Readiness"})
	if !errors.Is(err, ErrNotFound) || v.ID != "" || len(l.pdfReports) != reports || len(l.chain[a.TenantID]) != audit {
		t.Fatal("mismatched PDF roots published effects", v.ID, err)
	}
}

func TestPDFReportRejectsRawTitleControlCharactersBeforeEffects(t *testing.T) {
	l := newLegacyLedgerFixture(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	a, release, _ := setupReleaseRiskFixture(t, l)
	reports, audit := len(l.pdfReports), len(l.chain[a.TenantID])
	for _, title := range []string{"Title\n2 0 obj << /OpenAction 3 0 R >> endobj", "Title\r%%EOF", "Title\x00", "\nTitle"} {
		v, err := l.CreatePDFReportPackage(t.Context(), a, CreatePDFReportPackageInput{ReportType: "release_readiness", ReleaseID: release.ID, Title: title})
		if !errors.Is(err, ErrValidation) || v.ID != "" || len(l.pdfReports) != reports || len(l.chain[a.TenantID]) != audit {
			t.Fatal("raw title escaped the single-line PDF comment", v.ID, err)
		}
	}
}

func TestPDFReportResponseCannotMutateStoredLimitations(t *testing.T) {
	l := newLegacyLedgerFixture(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	a, release, _ := setupReleaseRiskFixture(t, l)
	v, err := l.CreatePDFReportPackage(t.Context(), a, CreatePDFReportPackageInput{ReportType: "release_readiness", ReleaseID: release.ID, Title: "Readiness"})
	if err != nil {
		t.Fatal(err)
	}
	v.Limitations[0] = "changed"
	if l.pdfReports[v.ID].Limitations[0] == "changed" {
		t.Fatal("caller mutated immutable PDF limitations")
	}
}
