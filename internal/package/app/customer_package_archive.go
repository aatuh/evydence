package app

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"strconv"
	"strings"
	"time"

	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	"github.com/aatuh/evydence/internal/platform/redaction"
)

type CustomerPackageArchive struct {
	PackageID string
	Filename  string
	MediaType string
	Bytes     []byte
	Hash      string
	Size      int64
}

const (
	MaxCustomerPackageFileBytes     = 10 << 20
	MaxCustomerPackageArchiveBytes  = 32 << 20
	MaxCustomerPackageExpandedBytes = 40 << 20
	customerDecisionExportFile      = "vulnerability-decisions.json"
	customerDecisionExportVersion   = "customer-vulnerability-decisions.v1.0.0"
)

func customerPackageArchive(pkg packagedomain.CustomerSecurityPackage) (CustomerPackageArchive, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	var expandedSize int64
	decisionExport := customerPackageDecisionExport(pkg)
	metadata := map[string]any{
		"id":                   pkg.ID,
		"product_id":           pkg.ProductID,
		"release_id":           pkg.ReleaseID,
		"redaction_profile_id": pkg.RedactionProfileID,
		"title":                pkg.Title,
		"state":                pkg.State,
		"manifest_hash":        pkg.ManifestHash,
		"html_report_file":     "report.html",
		"expires_at":           pkg.ExpiresAt.UTC().Format(time.RFC3339),
		"schema_version":       pkg.SchemaVersion,
		"created_at":           pkg.CreatedAt.UTC().Format(time.RFC3339),
	}
	if decisionExport != nil {
		metadata["decision_export_file"] = customerDecisionExportFile
	}
	if pkg.DistributionWatermark != "" {
		metadata["distribution_watermark"] = pkg.DistributionWatermark
	}
	verification := map[string]any{
		"package_id":        pkg.ID,
		"manifest_hash":     pkg.ManifestHash,
		"manifest_file":     "manifest.json",
		"metadata_file":     "package.json",
		"html_report_file":  "report.html",
		"hash_algorithm":    "sha256",
		"verification_note": "Verify the package manifest hash against the Evydence API or a signed bundle before relying on contents.",
		"limitations": []string{
			"Archive contents are scoped and redacted.",
			"Raw tenant evidence payload bytes are not included.",
			"This package supports technical evidence review and does not prove legal compliance, certification, or release security status.",
		},
	}
	if decisionExport != nil {
		verification["decision_export_file"] = customerDecisionExportFile
	}
	readme := "Evydence customer security package\n\n" +
		"This ZIP contains a scoped package manifest, package metadata, verification guidance, and customer-safe decision export when present.\n" +
		"It intentionally excludes raw tenant evidence payload bytes and bearer tokens.\n" +
		"Use the manifest hash with Evydence verification records or signed bundles before relying on package contents.\n"
	for _, entry := range []struct {
		name string
		body any
	}{
		{name: "manifest.json", body: pkg.Manifest},
		{name: "package.json", body: metadata},
		{name: "verification.json", body: verification},
	} {
		body, err := marshalCustomerPackageJSON(entry.body)
		if err != nil {
			_ = zw.Close()
			return CustomerPackageArchive{}, fmt.Errorf("serialize customer package %s: %w", entry.name, err)
		}
		body = append(body, '\n')
		if err := addCustomerPackageZIPFile(zw, &expandedSize, entry.name, body); err != nil {
			_ = zw.Close()
			return CustomerPackageArchive{}, err
		}
	}
	if decisionExport != nil {
		body, err := marshalCustomerPackageJSON(decisionExport)
		if err != nil {
			_ = zw.Close()
			return CustomerPackageArchive{}, err
		}
		body = append(body, '\n')
		if err := addCustomerPackageZIPFile(zw, &expandedSize, customerDecisionExportFile, body); err != nil {
			_ = zw.Close()
			return CustomerPackageArchive{}, err
		}
	}
	if err := addCustomerPackageZIPFile(zw, &expandedSize, "README.txt", []byte(readme)); err != nil {
		_ = zw.Close()
		return CustomerPackageArchive{}, err
	}
	if pkg.DistributionWatermark != "" {
		if err := addCustomerPackageZIPFile(zw, &expandedSize, "WATERMARK.txt", []byte(pkg.DistributionWatermark+"\n")); err != nil {
			_ = zw.Close()
			return CustomerPackageArchive{}, err
		}
	}
	report := customerPackageHTMLReport(pkg, metadata, verification)
	if len(report) > MaxGeneratedReportBytes {
		_ = zw.Close()
		return CustomerPackageArchive{}, ErrValidation
	}
	if err := addCustomerPackageZIPFile(zw, &expandedSize, "report.html", report); err != nil {
		_ = zw.Close()
		return CustomerPackageArchive{}, err
	}
	if err := zw.Close(); err != nil {
		return CustomerPackageArchive{}, err
	}
	body := buf.Bytes()
	if len(body) > MaxCustomerPackageArchiveBytes {
		return CustomerPackageArchive{}, ErrValidation
	}
	sum := sha256.Sum256(body)
	return CustomerPackageArchive{PackageID: pkg.ID, Filename: "evydence-customer-package-" + pkg.ID + ".zip", MediaType: "application/zip", Bytes: body, Hash: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(body))}, nil
}

// RenderCustomerPackageArchive renders an already authorized, redacted frozen
// record. Package/portal access commands own authorization and access auditing;
// this bounded renderer performs no storage lookup, token handling or mutation.
func RenderCustomerPackageArchive(pkg packagedomain.CustomerSecurityPackage) (CustomerPackageArchive, error) {
	return customerPackageArchive(pkg)
}

func customerPackageDecisionExport(pkg packagedomain.CustomerSecurityPackage) map[string]any {
	decisions := packageHTMLRecords(pkg.Manifest["vulnerability_decisions"])
	if len(decisions) == 0 {
		return nil
	}
	return map[string]any{
		"schema_version":       customerDecisionExportVersion,
		"package_id":           pkg.ID,
		"product_id":           pkg.ProductID,
		"release_id":           pkg.ReleaseID,
		"source_manifest_hash": pkg.ManifestHash,
		"decision_count":       len(decisions),
		"decisions":            decisions,
		"assumptions": []string{
			"This file contains only active vulnerability decisions included by the package redaction profile.",
			"Supporting links are Evydence record type/id pairs scoped by the package manifest.",
		},
		"limitations": []string{
			"This export supports technical evidence review and compliance readiness only; it is not legal compliance proof, certification, complete SBOM proof, authoritative vulnerability coverage, or a secure-release guarantee.",
			"Decision accuracy depends on tenant-supplied scanner, VEX, SBOM, exception, waiver, approval, and review evidence.",
		},
		"generated_at": pkg.CreatedAt.UTC().Format(time.RFC3339),
	}
}

func customerPackageHTMLReport(pkg packagedomain.CustomerSecurityPackage, metadata, verification map[string]any) []byte {
	manifest := pkg.Manifest
	product := packageHTMLMap(manifest["product"])
	release := packageHTMLMap(manifest["release"])
	readiness := packageHTMLMap(manifest["readiness_summary"])
	apiContracts := packageHTMLMap(manifest["api_contracts"])
	vexDocuments := packageHTMLRecords(manifest["vex_documents"])
	decisions := packageHTMLRecords(manifest["vulnerability_decisions"])
	answerLibrary := packageHTMLRecords(manifest["answer_library"])
	objectLockProofs := packageHTMLRecords(manifest["object_lock_proofs"])
	limitations := packageHTMLStrings(manifest["limitations"])
	nonClaims := packageHTMLStrings(manifest["non_claims"])

	var b strings.Builder
	b.WriteString("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'\"><title>")
	b.WriteString(packageHTMLEscape(pkg.Title))
	b.WriteString("</title><style>body{font-family:Arial,sans-serif;margin:2rem;line-height:1.5;color:#17202a;background:#fff}main{max-width:980px}h1,h2{line-height:1.2}table{border-collapse:collapse;width:100%;margin:0.75rem 0 1.5rem}th,td{border:1px solid #ccd3db;padding:0.45rem;text-align:left;vertical-align:top}th{background:#f3f6f8}.muted{color:#59636e}.notice{border-left:4px solid #5b6f82;background:#f6f8fa;padding:0.75rem 1rem}.badge{display:inline-block;border:1px solid #ccd3db;padding:0.1rem 0.45rem;border-radius:4px}</style></head><body><main>")
	b.WriteString("<h1>")
	b.WriteString(packageHTMLEscape(pkg.Title))
	b.WriteString("</h1><p class=\"notice\">This static report is generated from the redacted customer package manifest. It supports technical evidence review and compliance readiness only; it is not legal compliance proof, certification, complete SBOM proof, an authoritative vulnerability result, regulator acceptance, or a secure-release guarantee.</p>")
	if watermark := packageHTMLString(metadata["distribution_watermark"]); watermark != "" {
		b.WriteString("<p class=\"notice\"><strong>Distribution watermark:</strong> ")
		b.WriteString(packageHTMLEscape(watermark))
		b.WriteString("</p>")
	}

	b.WriteString("<h2>Release Summary</h2><table><tbody>")
	packageHTMLRow(&b, "Package ID", pkg.ID)
	packageHTMLRow(&b, "Product", packageHTMLFirst(product, "name", "id"))
	packageHTMLRow(&b, "Release", packageHTMLFirst(release, "version", "id"))
	packageHTMLRow(&b, "Package State", pkg.State)
	packageHTMLRow(&b, "Readiness", packageHTMLString(readiness["result"]))
	packageHTMLRow(&b, "Manifest Hash", packageHTMLString(metadata["manifest_hash"]))
	b.WriteString("</tbody></table>")

	b.WriteString("<h2>VEX And Vulnerability Decisions</h2>")
	if len(vexDocuments) == 0 && len(decisions) == 0 {
		b.WriteString("<p class=\"muted\">No customer-visible VEX documents or vulnerability decisions are included by this package profile.</p>")
	} else {
		if len(vexDocuments) > 0 {
			b.WriteString("<h3>VEX Documents</h3><table><thead><tr><th>ID</th><th>Format</th><th>Statements</th><th>Status Summary</th></tr></thead><tbody>")
			for _, record := range vexDocuments {
				b.WriteString("<tr><td>" + packageHTMLEscape(packageHTMLString(record["id"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["format"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["statement_count"])) + "</td><td>" + packageHTMLEscape(packageHTMLJSON(record["status_summary"])) + "</td></tr>")
			}
			b.WriteString("</tbody></table>")
		}
		if len(decisions) > 0 {
			b.WriteString("<h3>Vulnerability Decisions</h3><table><thead><tr><th>Vulnerability</th><th>Component</th><th>SBOM</th><th>Status</th><th>Impact Statement</th><th>Reviewed</th><th>Review Due</th><th>Supporting Links</th><th>Source</th></tr></thead><tbody>")
			for _, record := range decisions {
				b.WriteString("<tr><td>" + packageHTMLEscape(packageHTMLString(record["vulnerability"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["component"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["sbom_id"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["status"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["impact_statement"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["reviewed_at"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["review_due_at"])) + "</td><td>" + packageHTMLEscape(packageHTMLJSON(record["supporting_refs"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["source"])) + "</td></tr>")
			}
			b.WriteString("</tbody></table>")
		}
	}

	b.WriteString("<h2>Questionnaire Answer Library</h2>")
	if len(answerLibrary) == 0 {
		b.WriteString("<p class=\"muted\">No customer-visible questionnaire answer library entries are included by this package profile.</p>")
	} else {
		b.WriteString("<table><thead><tr><th>Question</th><th>Evidence Type</th><th>Answer</th><th>Evidence IDs</th></tr></thead><tbody>")
		for _, record := range answerLibrary {
			b.WriteString("<tr><td>" + packageHTMLEscape(packageHTMLString(record["question_id"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["evidence_type"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["answer"])) + "</td><td>" + packageHTMLEscape(packageHTMLJSON(record["evidence_ids"])) + "</td></tr>")
		}
		b.WriteString("</tbody></table>")
	}

	b.WriteString("<h2>Object-Lock Proofs</h2>")
	if len(objectLockProofs) == 0 {
		b.WriteString("<p class=\"muted\">No customer-visible object-lock proof records are included by this package profile.</p>")
	} else {
		b.WriteString("<table><thead><tr><th>ID</th><th>Status</th><th>Mode</th><th>Retention Days</th><th>Verification Hash</th></tr></thead><tbody>")
		for _, record := range objectLockProofs {
			b.WriteString("<tr><td>" + packageHTMLEscape(packageHTMLString(record["id"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["status"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["mode"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["retention_days"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["verification_hash"])) + "</td></tr>")
		}
		b.WriteString("</tbody></table>")
	}

	b.WriteString("<h2>API Contract Evidence</h2>")
	contractRecords := packageHTMLRecords(apiContracts["openapi_contracts"])
	diffRecords := packageHTMLRecords(apiContracts["contract_diffs"])
	if len(contractRecords) == 0 && len(diffRecords) == 0 {
		b.WriteString("<p class=\"muted\">No customer-visible OpenAPI contract evidence is included by this package profile.</p>")
	} else {
		if len(contractRecords) > 0 {
			b.WriteString("<h3>OpenAPI Contracts</h3><table><thead><tr><th>ID</th><th>Version</th><th>Hash</th><th>Paths</th><th>Operations</th></tr></thead><tbody>")
			for _, record := range contractRecords {
				b.WriteString("<tr><td>" + packageHTMLEscape(packageHTMLString(record["id"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["version"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["hash"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["path_count"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["operation_count"])) + "</td></tr>")
			}
			b.WriteString("</tbody></table>")
		}
		if len(diffRecords) > 0 {
			b.WriteString("<h3>Contract Diffs</h3><table><thead><tr><th>ID</th><th>Result</th><th>Breaking Changes</th><th>Non-breaking Changes</th></tr></thead><tbody>")
			for _, record := range diffRecords {
				b.WriteString("<tr><td>" + packageHTMLEscape(packageHTMLString(record["id"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(record["result"])) + "</td><td>" + packageHTMLEscape(packageHTMLJSON(record["breaking_changes"])) + "</td><td>" + packageHTMLEscape(packageHTMLJSON(record["non_breaking_changes"])) + "</td></tr>")
			}
			b.WriteString("</tbody></table>")
		}
	}

	b.WriteString("<h2>Readiness</h2>")
	packageHTMLReadiness(&b, readiness)
	b.WriteString("<h2>Verification</h2><table><tbody>")
	packageHTMLRow(&b, "Manifest File", packageHTMLString(verification["manifest_file"]))
	packageHTMLRow(&b, "Manifest Hash", packageHTMLString(verification["manifest_hash"]))
	packageHTMLRow(&b, "Decision Export", packageHTMLString(verification["decision_export_file"]))
	packageHTMLRow(&b, "Hash Algorithm", packageHTMLString(verification["hash_algorithm"]))
	packageHTMLRow(&b, "Verification Note", packageHTMLString(verification["verification_note"]))
	b.WriteString("</tbody></table>")
	b.WriteString("<h2>Limitations</h2>")
	packageHTMLList(&b, limitations)
	b.WriteString("<h2>Non-Claims</h2>")
	packageHTMLList(&b, nonClaims)
	b.WriteString("</main></body></html>")
	return []byte(b.String())
}

func packageHTMLReadiness(b *strings.Builder, readiness map[string]any) {
	result := packageHTMLString(readiness["result"])
	if result == "" {
		b.WriteString("<p class=\"muted\">No release readiness summary is included in this package.</p>")
		return
	}
	b.WriteString("<p>Result: <span class=\"badge\">" + packageHTMLEscape(result) + "</span></p>")
	checks := packageHTMLRecords(readiness["checks"])
	if len(checks) > 0 {
		b.WriteString("<table><thead><tr><th>Check</th><th>Result</th><th>Severity</th><th>Missing</th><th>Explanation</th></tr></thead><tbody>")
		for _, check := range checks {
			b.WriteString("<tr><td>" + packageHTMLEscape(packageHTMLString(check["name"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(check["result"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(check["severity"])) + "</td><td>" + packageHTMLEscape(packageHTMLJSON(check["missing"])) + "</td><td>" + packageHTMLEscape(packageHTMLString(check["explanation"])) + "</td></tr>")
		}
		b.WriteString("</tbody></table>")
	}
	if gaps := packageHTMLStrings(readiness["gaps"]); len(gaps) > 0 {
		b.WriteString("<h3>Gaps</h3>")
		packageHTMLList(b, gaps)
	}
}

func packageHTMLRow(b *strings.Builder, label, value string) {
	b.WriteString("<tr><th>")
	b.WriteString(packageHTMLEscape(label))
	b.WriteString("</th><td>")
	b.WriteString(packageHTMLEscape(value))
	b.WriteString("</td></tr>")
}

func packageHTMLList(b *strings.Builder, items []string) {
	if len(items) == 0 {
		b.WriteString("<p class=\"muted\">None included.</p>")
		return
	}
	b.WriteString("<ul>")
	for _, item := range items {
		b.WriteString("<li>")
		b.WriteString(packageHTMLEscape(item))
		b.WriteString("</li>")
	}
	b.WriteString("</ul>")
}

func packageHTMLMap(value any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	if record, ok := value.(map[string]any); ok {
		return record
	}
	return map[string]any{}
}

func packageHTMLRecords(value any) []map[string]any {
	switch records := value.(type) {
	case []map[string]any:
		return records
	case []any:
		out := make([]map[string]any, 0, len(records))
		for _, record := range records {
			if mapped, ok := record.(map[string]any); ok {
				out = append(out, mapped)
			}
		}
		return out
	default:
		return nil
	}
}

func packageHTMLStrings(value any) []string {
	switch records := value.(type) {
	case []string:
		return append([]string(nil), records...)
	case []any:
		out := make([]string, 0, len(records))
		for _, record := range records {
			if s := packageHTMLString(record); s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func packageHTMLFirst(record map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := packageHTMLString(record[key]); value != "" {
			return value
		}
	}
	return ""
}

func packageHTMLString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func packageHTMLJSON(value any) string {
	if value == nil {
		return ""
	}
	body, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(body)
}

func packageHTMLEscape(value string) string {
	return html.EscapeString(value)
}

func addCustomerPackageZIPFile(zw *zip.Writer, expandedSize *int64, name string, body []byte) error {
	if expandedSize == nil || len(body) > MaxCustomerPackageFileBytes || *expandedSize > MaxCustomerPackageExpandedBytes-int64(len(body)) {
		return ErrValidation
	}
	*expandedSize += int64(len(body))
	return addZIPFile(zw, name, body)
}

func addZIPFile(zw *zip.Writer, name string, body []byte) error {
	// Customer packages are generated with stored entries. This keeps their
	// advertised uncompressed bytes equal to on-disk bytes and guarantees the
	// generated package cannot trip the verifier's compression-ratio defense.
	header := &zip.FileHeader{Name: name, Method: zip.Store}
	header.SetMode(0o644)
	header.Modified = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	writer, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = writer.Write(body)
	return err
}

// marshalCustomerPackageJSON is the final output boundary for customer
// artifacts. The profile builders must already have removed sensitive fields;
// this guard rejects rather than silently mutates the immutable manifest.
func marshalCustomerPackageJSON(value any) ([]byte, error) {
	if _, changed := redaction.RemoveSensitive(value); changed {
		path, _ := redaction.FirstSensitivePath(value)
		return nil, fmt.Errorf("%w: customer package contains sensitive field %s", ErrValidation, path)
	}
	return json.MarshalIndent(value, "", "  ")
}
