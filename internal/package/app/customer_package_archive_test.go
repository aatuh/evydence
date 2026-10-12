package app

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func TestCustomerPackageRecordRendererPreservesFrozenNumbersEscapesHTMLAndUsesFixedZIPEntries(t *testing.T) {
	const count = "9007199254740993"
	const unsafeTitle = "<script>alert('display-only')</script>"
	pkg := packagedomain.CustomerSecurityPackage{ID: "package", TenantID: "tenant", ProductID: "product", ReleaseID: "release", RedactionProfileID: "profile", Title: unsafeTitle, State: "generated", ManifestHash: "sha256:" + strings.Repeat("a", 64), DistributionWatermark: "Scoped review copy", SchemaVersion: packagedomain.CustomerPackageSchemaVersion, CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), Manifest: map[string]any{
		"vex_documents":      []any{map[string]any{"id": "vex", "format": "OpenVEX", "statement_count": json.Number(count)}},
		"object_lock_proofs": []any{map[string]any{"id": "retention", "status": "recorded", "mode": "GOVERNANCE", "retention_days": json.Number("365")}},
		"api_contracts":      map[string]any{"openapi_contracts": []any{map[string]any{"id": "contract", "version": "1", "hash": "recorded", "path_count": json.Number("11"), "operation_count": json.Number("42")}}},
	}}
	before, err := json.Marshal(pkg)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := RenderCustomerPackageArchive(pkg)
	if err != nil || archive.PackageID != pkg.ID || archive.MediaType != "application/zip" || archive.Filename != "evydence-customer-package-package.zip" || archive.Hash != fmt.Sprintf("sha256:%x", sha256.Sum256(archive.Bytes)) || archive.Size != int64(len(archive.Bytes)) {
		t.Fatal("record renderer changed archive contract", err)
	}
	files := customerArchiveTestFiles(t, archive.Bytes)
	report := files["report.html"]
	for _, value := range []string{count, "365", "11", "42"} {
		if !strings.Contains(report, "<td>"+value+"</td>") {
			t.Fatal("recorded JSON number omitted from static HTML", value)
		}
	}
	if !strings.Contains(files["manifest.json"], count) || strings.Contains(report, "<script") || !strings.Contains(report, "&lt;script&gt;") || !strings.Contains(report, "default-src 'none'") || !strings.Contains(report, "form-action 'none'") {
		t.Fatal("record renderer lost number precision or HTML safety")
	}
	zr, err := zip.NewReader(bytes.NewReader(archive.Bytes), archive.Size)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"manifest.json": true, "package.json": true, "verification.json": true, "README.txt": true, "WATERMARK.txt": true, "report.html": true}
	if len(zr.File) != len(allowed) {
		t.Fatal("archive entry set changed")
	}
	for _, f := range zr.File {
		if !allowed[f.Name] || f.Method != zip.Store || f.UncompressedSize64 > MaxCustomerPackageFileBytes {
			t.Fatal("archive name, compression or entry budget changed", f.Name)
		}
		delete(allowed, f.Name)
	}
	again, err := RenderCustomerPackageArchive(pkg)
	if err != nil || !reflect.DeepEqual(archive, again) {
		t.Fatal("record renderer is not deterministic", err)
	}
	after, err := json.Marshal(pkg)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("record renderer mutated frozen inputs", err)
	}
	pkg.Manifest["api_key"] = "must-not-export-canary"
	if value, err := RenderCustomerPackageArchive(pkg); !errors.Is(err, ErrValidation) || !reflect.DeepEqual(value, CustomerPackageArchive{}) {
		t.Fatal("sensitive record returned partial archive", err)
	}
}

func customerArchiveTestFiles(t *testing.T, body []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string]string, len(zr.File))
	for _, file := range zr.File {
		r, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, readErr := io.ReadAll(r)
		closeErr := r.Close()
		if readErr != nil || closeErr != nil {
			t.Fatal("archive entry read failed", readErr, closeErr)
		}
		files[file.Name] = string(content)
	}
	return files
}
