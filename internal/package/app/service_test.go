package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

var errPackageTestFailure = errors.New("package test failure")

func TestCreateRedactionProfileUsesOwnedPresetAndCommitsAtomically(t *testing.T) {
	state := newPackageTestState()
	service := newPackageTestService(t, state)

	profile, err := service.CreateRedactionProfile(context.Background(), packageTestActor(), CreateRedactionProfileInput{Preset: "customer_safe"})
	if err != nil {
		t.Fatalf("create profile: %v", err)
	}
	if profile.ID != "rp_1" || profile.Name != "customer_safe" || !containsString(profile.ExcludedFields, "private_key") || !containsString(profile.ExcludedFields, "token") {
		t.Fatalf("unsafe or unexpected profile: %#v", profile)
	}
	if state.profiles[profile.ID].TenantID != "ten_1" || len(state.audit) != 1 {
		t.Fatalf("profile transaction not published: profiles=%#v audit=%#v", state.profiles, state.audit)
	}

	state.auditErr = errPackageTestFailure
	if _, err := service.CreateRedactionProfile(context.Background(), packageTestActor(), CreateRedactionProfileInput{Name: "custom", AllowedTypes: []string{"sbom"}}); !errors.Is(err, errPackageTestFailure) {
		t.Fatalf("audit failure = %v", err)
	}
	if _, exists := state.profiles["rp_2"]; exists {
		t.Fatal("failed profile transaction was published")
	}
}

func TestCreateRedactionProfileRejectsUnsafeOrIncompleteAllowlist(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input CreateRedactionProfileInput
	}{
		{"unknown preset", CreateRedactionProfileInput{Preset: "unreviewed"}},
		{"preset with override", CreateRedactionProfileInput{Preset: "customer_safe", AllowedTypes: []string{"secret"}}},
		{"missing name", CreateRedactionProfileInput{AllowedTypes: []string{"sbom"}}},
		{"empty allowlist", CreateRedactionProfileInput{Name: "customer"}},
		{"blank evidence type", CreateRedactionProfileInput{Name: "customer", AllowedTypes: []string{" "}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			state := newPackageTestState()
			service := newPackageTestService(t, state)
			if _, err := service.CreateRedactionProfile(context.Background(), packageTestActor(), tt.input); !errors.Is(err, ErrValidation) {
				t.Fatalf("profile error = %v", err)
			}
			if len(state.profiles) != 0 || len(state.audit) != 0 {
				t.Fatalf("invalid profile persisted: profiles=%#v audit=%#v", state.profiles, state.audit)
			}
		})
	}
}

func TestCreateCustomerSecurityPackageUsesOneCommittedSnapshotAndHardRedaction(t *testing.T) {
	state := newPackageTestState()
	state.profiles["rp_1"] = packagedomain.RedactionProfile{
		ID: "rp_1", TenantID: "ten_1", Name: "customer", AllowedTypes: []string{"sbom", "vulnerability_decision"},
		ExcludedFields: []string{"internal_notes"}, SchemaVersion: packagedomain.RedactionProfileSchemaVersion,
	}
	state.snapshot = PackageSnapshot{
		SnapshotVersion: "snapshot.v1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1",
		Tenant:       map[string]any{"id": "ten_1", "name": "Tenant", "token": "must-not-leak"},
		Organization: map[string]any{"records": []any{}}, Product: map[string]any{"id": "prod_1"}, Release: map[string]any{"id": "rel_1"},
		Evidence:             []EvidenceReference{{ID: "ev_2", Type: "vulnerability_scan"}, {ID: "ev_1", Type: "sbom"}},
		Artifacts:            []map[string]any{{"id": "art_1", "digest": "sha256:abc", "private_key": "must-not-leak"}},
		ReadinessChecks:      []packagedomain.PolicyCheckSnapshot{{Name: "release_requires_sbom", Result: "passed"}},
		VerificationMaterial: map[string]any{"hash_algorithm": "sha256", "payload_ref": "must-not-leak"},
		SBOMs:                []map[string]any{{"id": "sbom_1", "payload_ref": "must-not-leak"}},
		Decisions:            []map[string]any{{"id": "vd_1", "status": "fixed", "internal_notes": "must-not-leak"}},
		VulnerabilityScans:   []map[string]any{{"id": "scan_1"}},
	}
	service := newPackageTestService(t, state)

	pkg, err := service.CreateCustomerSecurityPackage(context.Background(), packageTestActor(), CreateCustomerPackageInput{
		ProductID: "prod_1", ReleaseID: "rel_1", RedactionProfileID: "rp_1", Title: "Review", ExpiresAt: packageTestNow().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create package: %v", err)
	}
	if state.snapshotReads != 1 || pkg.ManifestHash != "hash:manifest" || pkg.Manifest["snapshot_version"] != "snapshot.v1" {
		t.Fatalf("snapshot/hash mismatch: reads=%d package=%#v", state.snapshotReads, pkg)
	}
	if !reflect.DeepEqual(pkg.Manifest["evidence_ids"], []string{"ev_1"}) {
		t.Fatalf("profile-filtered evidence = %#v", pkg.Manifest["evidence_ids"])
	}
	if _, exists := pkg.Manifest["vulnerability_scans"]; exists {
		t.Fatal("disallowed snapshot section was included")
	}
	assertNoSensitivePackageKeys(t, pkg.Manifest)
	if state.packages[pkg.ID].ManifestHash != pkg.ManifestHash || len(state.audit) != 1 {
		t.Fatalf("package transaction not published: packages=%#v audit=%#v", state.packages, state.audit)
	}
}

func TestCreateCustomerSecurityPackageRejectsMismatchedOrIncompleteSnapshot(t *testing.T) {
	state := newPackageTestState()
	state.profiles["rp_1"] = packagedomain.RedactionProfile{ID: "rp_1", TenantID: "ten_1", Name: "customer", AllowedTypes: []string{"sbom"}, SchemaVersion: packagedomain.RedactionProfileSchemaVersion}
	state.snapshot = PackageSnapshot{SnapshotVersion: "snapshot.v1", TenantID: "ten_2", ProductID: "prod_1", ReleaseID: "rel_1", Product: map[string]any{"id": "prod_1"}, Release: map[string]any{"id": "rel_1"}}
	service := newPackageTestService(t, state)

	_, err := service.CreateCustomerSecurityPackage(context.Background(), packageTestActor(), CreateCustomerPackageInput{ProductID: "prod_1", ReleaseID: "rel_1", RedactionProfileID: "rp_1", Title: "Review", ExpiresAt: packageTestNow().Add(time.Hour)})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("mismatched snapshot error = %v", err)
	}
	if len(state.packages) != 0 {
		t.Fatalf("mismatched snapshot persisted: %#v", state.packages)
	}
}

func TestCreateCustomerSecurityPackageIncludesOnlyAllowlistedSectionsAndSanitizesNestedFields(t *testing.T) {
	state := newPackageTestState()
	state.profiles["rp_1"] = packagedomain.RedactionProfile{ID: "rp_1", TenantID: "ten_1", Name: "customer", AllowedTypes: []string{
		"artifact", "sbom", "vulnerability_scan", "vex", "openapi_contract", "vulnerability_decision", "approval", "exception", "waiver", "answer_library", "object_lock_proof", "build",
	}, ExcludedFields: []string{"internal_comment"}, SchemaVersion: packagedomain.RedactionProfileSchemaVersion}
	state.snapshot = PackageSnapshot{
		SnapshotVersion: "snapshot.v1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1",
		Tenant: map[string]any{"id": "ten_1"}, Product: map[string]any{"id": "prod_1"}, Release: map[string]any{"id": "rel_1"},
		Evidence:  []EvidenceReference{{ID: "ev_1", Type: "artifact"}, {ID: "ev_2", Type: "sbom"}, {ID: "ev_hidden", Type: "private_note"}},
		Artifacts: []map[string]any{{"id": "art_1", "nested": map[string]any{"token": "never-share", "digest": "sha256:abc"}}},
		SBOMs:     []map[string]any{{"id": "sbom_1"}}, VulnerabilityScans: []map[string]any{{"id": "scan_1"}},
		VEXDocuments: []map[string]any{{"id": "vex_1"}}, APIContracts: map[string]any{"id": "api_1"},
		Decisions: []map[string]any{{"id": "vd_1", "internal_notes": "never-share"}}, Approvals: []map[string]any{{"id": "apr_1"}},
		Exceptions: []map[string]any{{"id": "ex_1"}}, Waivers: []map[string]any{{"id": "wv_1"}},
		AnswerLibrary:    []map[string]any{{"id": "answer_1", "internal_comment": "never-share"}},
		ObjectLockProofs: []map[string]any{{"id": "proof_1"}}, Provenance: map[string]any{"id": "build_1"},
		ReadinessChecks: []packagedomain.PolicyCheckSnapshot{{Name: "release_requires_sbom", Result: "failed", Missing: []string{"sbom"}}},
	}
	service := newPackageTestService(t, state)
	pkg, err := service.CreateCustomerSecurityPackage(context.Background(), packageTestActor(), CreateCustomerPackageInput{
		ProductID: "prod_1", ReleaseID: "rel_1", RedactionProfileID: "rp_1", Title: "Customer review", ExpiresAt: packageTestNow().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create customer package: %v", err)
	}
	for _, key := range []string{"sboms", "vulnerability_scans", "vex_documents", "api_contracts", "vulnerability_decisions", "approvals", "exceptions", "waivers", "answer_library", "object_lock_proofs", "provenance", "customer_safe_gaps", "customer_decision_export"} {
		if _, exists := pkg.Manifest[key]; !exists {
			t.Fatalf("allowlisted section %q absent: %#v", key, pkg.Manifest)
		}
	}
	if !reflect.DeepEqual(pkg.Manifest["evidence_ids"], []string{"ev_1", "ev_2"}) {
		t.Fatalf("evidence allowlist = %#v", pkg.Manifest["evidence_ids"])
	}
	assertNoSensitivePackageKeys(t, pkg.Manifest)
	if strings.Contains(fmt.Sprint(pkg.Manifest), "never-share") {
		t.Fatal("secret-bearing nested metadata reached customer manifest")
	}
	if len(state.audit) != 1 || state.packages[pkg.ID].ManifestHash != pkg.ManifestHash {
		t.Fatalf("package/audit not committed atomically: packages=%#v audit=%#v", state.packages, state.audit)
	}
}

func TestCustomerSafeGapsExposeOnlyEvidenceAllowedByRedactionProfile(t *testing.T) {
	profile := packagedomain.RedactionProfile{AllowedTypes: []string{"artifact", "sbom"}}
	checks := []packagedomain.PolicyCheckSnapshot{
		{Name: "required", Result: "failed", Severity: "high", Missing: []string{
			"vulnerability_scan", "signed_release_bundle", "passed_build", "build_attestation",
			"vulnerability_decision", "unknown_internal_type", "sbom", "artifact_digest", "artifact",
		}},
		{Name: "already_present", Result: "passed", Missing: []string{"artifact"}},
	}

	gaps := customerSafeGaps(checks, profile)
	if len(gaps) != 3 {
		t.Fatalf("customer-safe gaps = %#v, want only artifact and SBOM gaps", gaps)
	}
	ids := []string{gaps[0]["id"].(string), gaps[1]["id"].(string), gaps[2]["id"].(string)}
	if !reflect.DeepEqual(ids, []string{"gap_required_artifact", "gap_required_artifact_digest", "gap_required_sbom"}) {
		t.Fatalf("unexpected visible gap IDs/order: %#v", ids)
	}
	for _, gap := range gaps {
		if gap["customer_visible"] != true || gap["category"] != "missing_evidence" || len(gap["limitations"].([]string)) == 0 {
			t.Fatalf("gap lacks customer-safe framing: %#v", gap)
		}
	}
}

func TestCreateReleaseBundleSignsOneCommittedSnapshotAndCommitsAtomically(t *testing.T) {
	state := newPackageTestState()
	state.releaseBundleSnapshot = ReleaseBundleSnapshot{
		SnapshotVersion: ReleaseBundleSnapshotVersion, TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1",
		ReleaseVersion: "1.2.3", ReleaseState: "frozen", EvidenceIDs: []string{"ev_2", "ev_1"},
		ChainSequence: 7, ChainHeadHash: "sha256:head", ObjectLockProofs: []map[string]any{{"id": "proof_1"}},
	}
	service := newPackageTestService(t, state)

	bundle, err := service.CreateReleaseBundle(context.Background(), packageTestActor(), "rel_1")
	if err != nil {
		t.Fatalf("create release bundle: %v", err)
	}
	if state.releaseBundleSnapshotReads != 1 || bundle.ID != "rb_1" || bundle.State.String() != packagedomain.BundleStateGeneratedValue || !reflect.DeepEqual(bundle.Manifest["evidence_ids"], []string{"ev_1", "ev_2"}) {
		t.Fatalf("bundle/snapshot mismatch: reads=%d bundle=%#v", state.releaseBundleSnapshotReads, bundle)
	}
	if state.lastSigningRequest.SubjectType != "release_bundle" || state.lastSigningRequest.SubjectID != bundle.ID || state.lastSigningRequest.PayloadHash != bundle.ManifestHash {
		t.Fatalf("signing request = %#v", state.lastSigningRequest)
	}
	if _, ok := state.releaseBundles[bundle.ID]; !ok || len(state.signatures) != 1 || len(state.audit) != 1 || len(state.outbox) != 1 {
		t.Fatalf("atomic effects missing: bundles=%#v signatures=%#v audit=%#v outbox=%#v", state.releaseBundles, state.signatures, state.audit, state.outbox)
	}

	state.auditErr = errPackageTestFailure
	if _, err := service.CreateReleaseBundle(context.Background(), packageTestActor(), "rel_1"); !errors.Is(err, errPackageTestFailure) {
		t.Fatalf("audit failure = %v", err)
	}
	if len(state.releaseBundles) != 1 || len(state.signatures) != 1 || len(state.outbox) != 1 {
		t.Fatalf("failed bundle transaction was published: bundles=%#v signatures=%#v outbox=%#v", state.releaseBundles, state.signatures, state.outbox)
	}
}

func TestCreateReleaseBundleRejectsForeignOrInvalidSigningResult(t *testing.T) {
	state := newPackageTestState()
	state.releaseBundleSnapshot = ReleaseBundleSnapshot{SnapshotVersion: ReleaseBundleSnapshotVersion, TenantID: "ten_2", ProductID: "prod_2", ReleaseID: "rel_1"}
	service := newPackageTestService(t, state)
	if _, err := service.CreateReleaseBundle(context.Background(), packageTestActor(), "rel_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign snapshot error = %v", err)
	}

	state.releaseBundleSnapshot = ReleaseBundleSnapshot{SnapshotVersion: ReleaseBundleSnapshotVersion, TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", ReleaseVersion: "1.0.0", ReleaseState: "frozen"}
	state.signingTenant = "ten_2"
	if _, err := service.CreateReleaseBundle(context.Background(), packageTestActor(), "rel_1"); !errors.Is(err, ErrConflict) {
		t.Fatalf("foreign signature error = %v", err)
	}
	if len(state.releaseBundles) != 0 || len(state.signatures) != 0 {
		t.Fatalf("invalid signature persisted: bundles=%#v signatures=%#v", state.releaseBundles, state.signatures)
	}
}

func TestExportAndImportEvidenceBundleUseFocusedSnapshotAndAtomicRepositories(t *testing.T) {
	state := newPackageTestState()
	state.evidenceBundleSnapshot = EvidenceBundleSnapshot{
		SnapshotVersion: EvidenceBundleSnapshotVersion, TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1",
		Evidence: []EvidenceBundleEvidence{
			{ID: "ev_2", Resources: application.ResourceReferences{ProductID: "prod_1", ReleaseID: "rel_1"}},
			{ID: "ev_1", Resources: application.ResourceReferences{ProductID: "prod_1", ReleaseID: "rel_1"}},
		},
		AuditChainHead: "sha256:head", ObjectLockProofs: []map[string]any{{"id": "orp_1", "status": "verified"}},
	}
	service := newPackageTestService(t, state)

	bundle, err := service.ExportEvidenceBundle(context.Background(), packageTestActor(), "rel_1", []string{"ev_2", "ev_1"})
	if err != nil {
		t.Fatalf("export evidence bundle: %v", err)
	}
	if state.evidenceBundleSnapshotReads != 1 || !reflect.DeepEqual(bundle.EvidenceIDs, []string{"ev_1", "ev_2"}) {
		t.Fatalf("snapshot reads=%d bundle=%#v", state.evidenceBundleSnapshotReads, bundle)
	}
	if state.lastSigningRequest.SubjectType != "evidence_bundle" || state.lastSigningRequest.SubjectID != bundle.ID || state.lastSigningRequest.PayloadHash != bundle.ManifestHash {
		t.Fatalf("signing request=%#v", state.lastSigningRequest)
	}
	if state.evidenceBundles[bundle.ID].ID == "" || len(state.signatures) != 1 || len(state.audit) != 1 {
		t.Fatalf("export effects bundles=%#v signatures=%#v audit=%#v", state.evidenceBundles, state.signatures, state.audit)
	}

	imported, err := service.ImportEvidenceBundle(context.Background(), packageTestActor(), bundle)
	if err != nil {
		t.Fatalf("import evidence bundle: %v", err)
	}
	if imported.ImportedCount != 2 || state.bundleImports[imported.ID].ID == "" || len(state.audit) != 2 {
		t.Fatalf("import=%#v persisted=%#v audit=%#v", imported, state.bundleImports, state.audit)
	}

	state.auditErr = errPackageTestFailure
	if _, err := service.ImportEvidenceBundle(context.Background(), packageTestActor(), bundle); !errors.Is(err, errPackageTestFailure) {
		t.Fatalf("failed import error=%v", err)
	}
	if len(state.bundleImports) != 1 {
		t.Fatalf("failed import published: %#v", state.bundleImports)
	}
}

func TestExportEvidenceBundleRejectsForeignSnapshotAndRechecksResourceAuthorization(t *testing.T) {
	state := newPackageTestState()
	state.evidenceBundleSnapshot = EvidenceBundleSnapshot{
		SnapshotVersion: EvidenceBundleSnapshotVersion, TenantID: "ten_2", ReleaseID: "",
		Evidence: []EvidenceBundleEvidence{{ID: "ev_1", Resources: application.ResourceReferences{ProductID: "prod_1"}}},
	}
	service := newPackageTestService(t, state)
	if _, err := service.ExportEvidenceBundle(context.Background(), packageTestActor(), "", []string{"ev_1"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign snapshot error = %v", err)
	}
	if len(state.evidenceBundles) != 0 || len(state.signatures) != 0 || len(state.audit) != 0 {
		t.Fatal("foreign snapshot created package effects")
	}

	state.evidenceBundleSnapshot.TenantID = "ten_1"
	state.authorize = func(request application.AuthorizationRequest) error {
		if request.Resources.ProductID == "prod_1" {
			return ErrForbidden
		}
		return nil
	}
	if _, err := service.ExportEvidenceBundle(context.Background(), packageTestActor(), "", []string{"ev_1"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("denied resource error = %v", err)
	}
	if len(state.evidenceBundles) != 0 || len(state.signatures) != 0 || len(state.audit) != 0 {
		t.Fatal("denied resource created package effects")
	}

	checks := 0
	state.authorize = func(request application.AuthorizationRequest) error {
		if request.Resources.ProductID == "prod_1" {
			checks++
			if checks == 2 {
				return ErrForbidden
			}
		}
		return nil
	}
	if _, err := service.ExportEvidenceBundle(context.Background(), packageTestActor(), "", []string{"ev_1"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("transaction recheck error = %v", err)
	}
	if checks != 2 || len(state.evidenceBundles) != 0 || len(state.signatures) != 0 || len(state.audit) != 0 {
		t.Fatalf("authorization recheck checks=%d bundles=%d signatures=%d audit=%d", checks, len(state.evidenceBundles), len(state.signatures), len(state.audit))
	}
}

func TestExportEvidenceBundleRejectsInconsistentSnapshotAndMissingRequestedEvidence(t *testing.T) {
	base := EvidenceBundleSnapshot{SnapshotVersion: EvidenceBundleSnapshotVersion, TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", Evidence: []EvidenceBundleEvidence{{ID: "ev_1", Resources: application.ResourceReferences{ReleaseID: "rel_1"}}}}
	for _, tt := range []struct {
		name   string
		mutate func(*EvidenceBundleSnapshot)
		ids    []string
		want   error
	}{
		{"unsupported version", func(s *EvidenceBundleSnapshot) { s.SnapshotVersion = "future" }, nil, ErrConflict},
		{"missing product", func(s *EvidenceBundleSnapshot) { s.ProductID = "" }, nil, ErrConflict},
		{"empty evidence ID", func(s *EvidenceBundleSnapshot) { s.Evidence[0].ID = " " }, nil, ErrConflict},
		{"duplicate evidence ID", func(s *EvidenceBundleSnapshot) { s.Evidence = append(s.Evidence, s.Evidence[0]) }, nil, ErrConflict},
		{"cross-release evidence", func(s *EvidenceBundleSnapshot) { s.Evidence[0].Resources.ReleaseID = "rel_2" }, nil, ErrConflict},
		{"missing requested ID", func(*EvidenceBundleSnapshot) {}, []string{"ev_missing"}, ErrNotFound},
	} {
		t.Run(tt.name, func(t *testing.T) {
			state := newPackageTestState()
			state.evidenceBundleSnapshot = cloneEvidenceBundleSnapshot(base)
			tt.mutate(&state.evidenceBundleSnapshot)
			service := newPackageTestService(t, state)
			if _, err := service.ExportEvidenceBundle(context.Background(), packageTestActor(), "rel_1", tt.ids); !errors.Is(err, tt.want) {
				t.Fatalf("export error = %v, want %v", err, tt.want)
			}
			if len(state.evidenceBundles) != 0 || len(state.signatures) != 0 || len(state.audit) != 0 {
				t.Fatalf("invalid export published state: bundles=%#v signatures=%#v audit=%#v", state.evidenceBundles, state.signatures, state.audit)
			}
		})
	}
}

func TestImportEvidenceBundleRejectsTamperedManifestAndOuterEvidence(t *testing.T) {
	base := packagedomain.EvidenceBundle{EvidenceIDs: []string{"ev_1"}, ManifestHash: "hash:manifest", Manifest: map[string]any{"bundle_version": packagedomain.EvidenceBundleSchemaVersion, "evidence_ids": []string{"ev_1"}}}
	for _, tt := range []struct {
		name   string
		mutate func(*packagedomain.EvidenceBundle)
	}{
		{"missing hash", func(b *packagedomain.EvidenceBundle) { b.ManifestHash = "" }},
		{"unsupported version", func(b *packagedomain.EvidenceBundle) { b.Manifest["bundle_version"] = "future" }},
		{"invalid ID type", func(b *packagedomain.EvidenceBundle) { b.Manifest["evidence_ids"] = []any{17} }},
		{"blank manifest ID", func(b *packagedomain.EvidenceBundle) { b.Manifest["evidence_ids"] = []string{" "} }},
		{"duplicate manifest ID", func(b *packagedomain.EvidenceBundle) { b.Manifest["evidence_ids"] = []string{"ev_1", "ev_1"} }},
		{"outer IDs differ", func(b *packagedomain.EvidenceBundle) { b.EvidenceIDs = []string{"ev_2"} }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			state := newPackageTestState()
			bundle := cloneEvidenceBundle(base)
			tt.mutate(&bundle)
			service := newPackageTestService(t, state)
			if _, err := service.ImportEvidenceBundle(context.Background(), packageTestActor(), bundle); !errors.Is(err, ErrValidation) {
				t.Fatalf("import error = %v", err)
			}
			if len(state.bundleImports) != 0 || len(state.audit) != 0 {
				t.Fatalf("tampered import persisted: imports=%#v audit=%#v", state.bundleImports, state.audit)
			}
		})
	}
}

func TestCustomReportTemplateAndRenderingUseFocusedAtomicRepositories(t *testing.T) {
	state := newPackageTestState()
	service := newPackageTestService(t, state)

	template, err := service.CreateCustomReportTemplate(context.Background(), packageTestActor(), CreateReportTemplateInput{
		Name: "Review", Version: "1", ReportType: "evidence", AllowedFields: []string{"subject_id", "generated_at"},
		Template: `{{template "untrusted" .}}`,
	})
	if err != nil {
		t.Fatalf("create template: %v", err)
	}
	if template.ID == "" || state.templates[template.ID].ID != template.ID || len(state.audit) != 1 {
		t.Fatalf("template effects: template=%#v persisted=%#v audit=%#v", template, state.templates, state.audit)
	}
	rendered, err := service.RenderCustomReport(context.Background(), packageTestActor(), RenderReportInput{
		TemplateID: template.ID, SubjectType: "release", SubjectID: "rel_1",
	})
	if err != nil {
		t.Fatalf("render report: %v", err)
	}
	if rendered.Output["subject_id"] != "rel_1" || rendered.Output["generated_at"] == "" || rendered.Output["template"] != nil || rendered.Hash == "" {
		t.Fatalf("rendered report = %#v", rendered)
	}
	if state.renderedReports[rendered.ID].ID != rendered.ID || len(state.audit) != 2 {
		t.Fatalf("render effects: reports=%#v audit=%#v", state.renderedReports, state.audit)
	}

	state.auditErr = errPackageTestFailure
	if _, err := service.RenderCustomReport(context.Background(), packageTestActor(), RenderReportInput{TemplateID: template.ID, SubjectType: "release", SubjectID: "rel_1"}); !errors.Is(err, errPackageTestFailure) {
		t.Fatalf("audit failure = %v", err)
	}
	if len(state.renderedReports) != 1 {
		t.Fatalf("failed render was published: %#v", state.renderedReports)
	}
}

func TestRenderCustomReportRejectsForeignTemplate(t *testing.T) {
	state := newPackageTestState()
	state.templates["rptpl_foreign"] = packagedomain.CustomReportTemplate{
		ID: "rptpl_foreign", TenantID: "ten_2", AllowedFields: []string{"subject_id"},
	}
	service := newPackageTestService(t, state)
	if _, err := service.RenderCustomReport(context.Background(), packageTestActor(), RenderReportInput{TemplateID: "rptpl_foreign", SubjectType: "release", SubjectID: "rel_1"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign template error = %v", err)
	}
	if len(state.renderedReports) != 0 || len(state.audit) != 0 {
		t.Fatal("foreign template created report effects")
	}
}

func TestCRAReadinessHTMLPackageUsesCommittedSnapshotAndAtomicWrite(t *testing.T) {
	state := newPackageTestState()
	state.craHTMLSnapshot = CRAReadinessHTMLSnapshot{
		SnapshotVersion: CRAReadinessHTMLSnapshotVersion, TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1",
		Result: "needs <review>", Limitations: []string{"Independent <review> required."},
	}
	service := newPackageTestService(t, state)
	report, err := service.CRAReadinessHTMLPackage(context.Background(), packageTestActor(), "prod_1", "rel_1")
	if err != nil {
		t.Fatalf("create CRA HTML report: %v", err)
	}
	if state.craHTMLSnapshotReads != 1 || !strings.Contains(report.HTML, "needs &lt;review&gt;") || strings.Contains(report.HTML, "<review>") {
		t.Fatalf("unsafe or inconsistent HTML: reads=%d report=%#v", state.craHTMLSnapshotReads, report)
	}
	if state.htmlReports[report.ID].ID != report.ID || len(state.audit) != 1 {
		t.Fatalf("HTML effects: reports=%#v audit=%#v", state.htmlReports, state.audit)
	}

	state.auditErr = errPackageTestFailure
	if _, err := service.CRAReadinessHTMLPackage(context.Background(), packageTestActor(), "prod_1", "rel_1"); !errors.Is(err, errPackageTestFailure) {
		t.Fatalf("audit failure = %v", err)
	}
	if len(state.htmlReports) != 1 {
		t.Fatalf("failed HTML report was published: %#v", state.htmlReports)
	}
}

func TestCRAReadinessHTMLPackageRejectsForeignSnapshot(t *testing.T) {
	state := newPackageTestState()
	state.craHTMLSnapshot = CRAReadinessHTMLSnapshot{
		SnapshotVersion: CRAReadinessHTMLSnapshotVersion, TenantID: "ten_2", ProductID: "prod_1", ReleaseID: "rel_1", Result: "passed",
	}
	service := newPackageTestService(t, state)
	if _, err := service.CRAReadinessHTMLPackage(context.Background(), packageTestActor(), "prod_1", "rel_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign snapshot error = %v", err)
	}
	if len(state.htmlReports) != 0 || len(state.audit) != 0 {
		t.Fatal("foreign snapshot created report effects")
	}
}

func TestCRAReadinessHTMLPackageRejectsMalformedCommittedSnapshot(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*CRAReadinessHTMLSnapshot)
	}{
		{"unsupported version", func(s *CRAReadinessHTMLSnapshot) { s.SnapshotVersion = "future" }},
		{"blank result", func(s *CRAReadinessHTMLSnapshot) { s.Result = " " }},
		{"oversized result", func(s *CRAReadinessHTMLSnapshot) { s.Result = strings.Repeat("x", MaxGeneratedReportBytes+1) }},
		{"oversized limitation", func(s *CRAReadinessHTMLSnapshot) {
			s.Limitations = []string{strings.Repeat("x", MaxGeneratedReportBytes+1)}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			state := newPackageTestState()
			state.craHTMLSnapshot = CRAReadinessHTMLSnapshot{SnapshotVersion: CRAReadinessHTMLSnapshotVersion, TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", Result: "passed"}
			tt.mutate(&state.craHTMLSnapshot)
			service := newPackageTestService(t, state)
			if _, err := service.CRAReadinessHTMLPackage(context.Background(), packageTestActor(), "prod_1", "rel_1"); !errors.Is(err, ErrConflict) && !errors.Is(err, ErrValidation) {
				t.Fatalf("malformed HTML snapshot error = %v", err)
			}
			if len(state.htmlReports) != 0 || len(state.audit) != 0 {
				t.Fatalf("invalid HTML snapshot persisted: reports=%#v audit=%#v", state.htmlReports, state.audit)
			}
		})
	}
}

func TestAccessCustomerSecurityPackageAuthorizesAndUpdatesAtomically(t *testing.T) {
	state := newPackageTestState()
	state.packages["csp_1"] = packagedomain.CustomerSecurityPackage{
		ID: "csp_1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", Title: "Review",
		State: "generated", Manifest: map[string]any{"id": "csp_1"}, ManifestHash: "sha256:manifest",
		ExpiresAt: packageTestNow().Add(time.Hour), SchemaVersion: packagedomain.CustomerPackageSchemaVersion,
	}
	service := newPackageTestService(t, state)

	pkg, err := service.AccessCustomerSecurityPackage(context.Background(), packageTestActor(), "csp_1")
	if err != nil {
		t.Fatalf("access package: %v", err)
	}
	if pkg.AccessCount != 1 || state.packages[pkg.ID].AccessCount != 1 || len(state.audit) != 1 {
		t.Fatalf("access effects: package=%#v persisted=%#v audit=%#v", pkg, state.packages[pkg.ID], state.audit)
	}

	state.auditErr = errPackageTestFailure
	if _, err := service.AccessCustomerSecurityPackage(context.Background(), packageTestActor(), "csp_1"); !errors.Is(err, errPackageTestFailure) {
		t.Fatalf("audit failure = %v", err)
	}
	if state.packages["csp_1"].AccessCount != 1 {
		t.Fatalf("failed access published: %#v", state.packages["csp_1"])
	}
}

func TestAccessCustomerSecurityPackageRejectsExpiredOrForeignPackage(t *testing.T) {
	state := newPackageTestState()
	state.packages["expired"] = packagedomain.CustomerSecurityPackage{ID: "expired", TenantID: "ten_1", ProductID: "prod_1", State: "generated", SchemaVersion: packagedomain.CustomerPackageSchemaVersion, ExpiresAt: packageTestNow()}
	state.packages["foreign"] = packagedomain.CustomerSecurityPackage{ID: "foreign", TenantID: "ten_2", ProductID: "prod_2", State: "generated", SchemaVersion: packagedomain.CustomerPackageSchemaVersion, ExpiresAt: packageTestNow().Add(time.Hour)}
	service := newPackageTestService(t, state)
	if _, err := service.AccessCustomerSecurityPackage(context.Background(), packageTestActor(), "expired"); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired error = %v", err)
	}
	if _, err := service.AccessCustomerSecurityPackage(context.Background(), packageTestActor(), "foreign"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign error = %v", err)
	}
}

func newPackageTestService(t *testing.T, state *packageTestState) *Service {
	t.Helper()
	service, err := NewService(Config{
		Reader: state, Transactions: state, Authorizer: packageTestAuthorizer{state: state}, Canonicalizer: packageTestCanonicalizer{},
		Signer: state, Clock: application.ClockFunc(packageTestNow), IDs: application.IDGeneratorFunc(state.nextID),
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return service
}

func packageTestNow() time.Time { return time.Date(2026, 9, 4, 13, 0, 0, 0, time.UTC) }

func packageTestActor() identitydomain.Actor {
	return identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", KeyID: "key_1", Scopes: []string{"package:write", "package:read"}}
}

type packageTestAuthorizer struct{ state *packageTestState }

func (a packageTestAuthorizer) Authorize(_ context.Context, _ identitydomain.Actor, request application.AuthorizationRequest) error {
	if a.state.authorize != nil {
		return a.state.authorize(request)
	}
	return nil
}

type packageTestCanonicalizer struct{}

func (packageTestCanonicalizer) HashPackageManifest(context.Context, map[string]any) (string, error) {
	return "hash:manifest", nil
}
func (packageTestCanonicalizer) HashPackageBytes(context.Context, []byte) (string, error) {
	return "hash:html", nil
}

type packageTestState struct {
	profiles                    map[string]packagedomain.RedactionProfile
	packages                    map[string]packagedomain.CustomerSecurityPackage
	releaseBundles              map[string]packagedomain.ReleaseBundle
	signatures                  map[string]PackageSignature
	snapshot                    PackageSnapshot
	snapshotReads               int
	releaseBundleSnapshot       ReleaseBundleSnapshot
	releaseBundleSnapshotReads  int
	evidenceBundleSnapshot      EvidenceBundleSnapshot
	evidenceBundleSnapshotReads int
	lastSigningRequest          PackageSigningRequest
	signingTenant               string
	readinessReport             ReadinessReportSnapshot
	readinessReportReads        int
	evidenceBundles             map[string]packagedomain.EvidenceBundle
	bundleImports               map[string]packagedomain.EvidenceBundleImport
	templates                   map[string]packagedomain.CustomReportTemplate
	renderedReports             map[string]packagedomain.RenderedCustomReport
	htmlReports                 map[string]packagedomain.HTMLReportPackage
	craHTMLSnapshot             CRAReadinessHTMLSnapshot
	craHTMLSnapshotReads        int
	executeCalls                int
	audit                       []application.AuditEvent
	outbox                      []application.OutboxEvent
	auditErr                    error
	authorize                   func(application.AuthorizationRequest) error
	ids                         map[string]int
}

func newPackageTestState() *packageTestState {
	return &packageTestState{
		profiles: map[string]packagedomain.RedactionProfile{}, packages: map[string]packagedomain.CustomerSecurityPackage{},
		releaseBundles: map[string]packagedomain.ReleaseBundle{}, signatures: map[string]PackageSignature{},
		evidenceBundles: map[string]packagedomain.EvidenceBundle{}, bundleImports: map[string]packagedomain.EvidenceBundleImport{},
		templates: map[string]packagedomain.CustomReportTemplate{}, renderedReports: map[string]packagedomain.RenderedCustomReport{},
		htmlReports: map[string]packagedomain.HTMLReportPackage{}, ids: map[string]int{},
	}
}

func (s *packageTestState) nextID(prefix string) string {
	s.ids[prefix]++
	return prefix + "_" + strconv.Itoa(s.ids[prefix])
}

func (s *packageTestState) GetRedactionProfile(_ context.Context, tenantID, id string) (packagedomain.RedactionProfile, error) {
	value, ok := s.profiles[id]
	if !ok || value.TenantID != tenantID {
		return packagedomain.RedactionProfile{}, ErrNotFound
	}
	return cloneRedactionProfile(value), nil
}
func (s *packageTestState) GetCustomReportTemplate(_ context.Context, tenantID, id string) (packagedomain.CustomReportTemplate, error) {
	value, ok := s.templates[id]
	if !ok || value.TenantID != tenantID {
		return packagedomain.CustomReportTemplate{}, ErrNotFound
	}
	return cloneCustomReportTemplate(value), nil
}
func (s *packageTestState) ReadCommittedPackageSnapshot(context.Context, string, string, string) (PackageSnapshot, error) {
	s.snapshotReads++
	return clonePackageSnapshot(s.snapshot), nil
}
func (s *packageTestState) ReadCommittedReleaseBundleSnapshot(context.Context, string, string) (ReleaseBundleSnapshot, error) {
	s.releaseBundleSnapshotReads++
	return cloneReleaseBundleSnapshot(s.releaseBundleSnapshot), nil
}
func (s *packageTestState) ReadCommittedEvidenceBundleSnapshot(context.Context, string, string) (EvidenceBundleSnapshot, error) {
	s.evidenceBundleSnapshotReads++
	return cloneEvidenceBundleSnapshot(s.evidenceBundleSnapshot), nil
}
func (s *packageTestState) ReadCommittedCRAReadinessHTMLSnapshot(context.Context, string, string, string) (CRAReadinessHTMLSnapshot, error) {
	s.craHTMLSnapshotReads++
	return cloneCRAReadinessHTMLSnapshot(s.craHTMLSnapshot), nil
}
func (s *packageTestState) SignPackage(_ context.Context, request PackageSigningRequest) (PackageSignature, error) {
	s.lastSigningRequest = request
	tenantID := s.signingTenant
	if tenantID == "" {
		tenantID = request.TenantID
	}
	return PackageSignature{
		ID: s.nextID("sig"), TenantID: tenantID, SubjectType: request.SubjectType, SubjectID: request.SubjectID,
		KeyID: "sk_1", Algorithm: "Ed25519", Value: "signature", CreatedAt: request.CreatedAt,
	}, nil
}
func (s *packageTestState) ReadCommittedReadinessReportSnapshot(context.Context, string, string) (ReadinessReportSnapshot, error) {
	s.readinessReportReads++
	return cloneReadinessReportSnapshot(s.readinessReport), nil
}
func (s *packageTestState) GetCustomerSecurityPackage(_ context.Context, tenantID, id string) (packagedomain.CustomerSecurityPackage, error) {
	value, ok := s.packages[id]
	if !ok || value.TenantID != tenantID {
		return packagedomain.CustomerSecurityPackage{}, ErrNotFound
	}
	return cloneCustomerSecurityPackage(value), nil
}
func (s *packageTestState) Execute(ctx context.Context, command TransactionCommand) error {
	s.executeCalls++
	working := &packageTestState{
		profiles: map[string]packagedomain.RedactionProfile{}, packages: map[string]packagedomain.CustomerSecurityPackage{},
		releaseBundles: map[string]packagedomain.ReleaseBundle{}, signatures: map[string]PackageSignature{},
		snapshot: clonePackageSnapshot(s.snapshot), releaseBundleSnapshot: cloneReleaseBundleSnapshot(s.releaseBundleSnapshot),
		evidenceBundleSnapshot: cloneEvidenceBundleSnapshot(s.evidenceBundleSnapshot),
		readinessReport:        cloneReadinessReportSnapshot(s.readinessReport), audit: append([]application.AuditEvent(nil), s.audit...),
		outbox: append([]application.OutboxEvent(nil), s.outbox...), auditErr: s.auditErr, ids: s.ids,
		authorize:       s.authorize,
		evidenceBundles: map[string]packagedomain.EvidenceBundle{}, bundleImports: map[string]packagedomain.EvidenceBundleImport{},
		templates: map[string]packagedomain.CustomReportTemplate{}, renderedReports: map[string]packagedomain.RenderedCustomReport{},
		htmlReports: map[string]packagedomain.HTMLReportPackage{}, craHTMLSnapshot: cloneCRAReadinessHTMLSnapshot(s.craHTMLSnapshot),
	}
	for key, value := range s.profiles {
		working.profiles[key] = cloneRedactionProfile(value)
	}
	for key, value := range s.packages {
		working.packages[key] = cloneCustomerSecurityPackage(value)
	}
	for key, value := range s.releaseBundles {
		working.releaseBundles[key] = cloneReleaseBundle(value)
	}
	for key, value := range s.signatures {
		working.signatures[key] = value
	}
	for key, value := range s.evidenceBundles {
		working.evidenceBundles[key] = cloneEvidenceBundle(value)
	}
	for key, value := range s.bundleImports {
		working.bundleImports[key] = value
	}
	for key, value := range s.templates {
		working.templates[key] = cloneCustomReportTemplate(value)
	}
	for key, value := range s.renderedReports {
		working.renderedReports[key] = cloneRenderedCustomReport(value)
	}
	for key, value := range s.htmlReports {
		working.htmlReports[key] = value
	}
	if err := command(ctx, packageTestTransaction{state: working}); err != nil {
		return err
	}
	s.profiles, s.packages, s.releaseBundles, s.signatures, s.evidenceBundles, s.bundleImports = working.profiles, working.packages, working.releaseBundles, working.signatures, working.evidenceBundles, working.bundleImports
	s.templates, s.renderedReports, s.htmlReports, s.audit, s.outbox = working.templates, working.renderedReports, working.htmlReports, working.audit, working.outbox
	return nil
}
func (s *packageTestState) InsertRedactionProfile(_ context.Context, value packagedomain.RedactionProfile) error {
	s.profiles[value.ID] = cloneRedactionProfile(value)
	return nil
}
func (s *packageTestState) InsertCustomerSecurityPackage(_ context.Context, value packagedomain.CustomerSecurityPackage) error {
	s.packages[value.ID] = cloneCustomerSecurityPackage(value)
	return nil
}
func (s *packageTestState) InsertReleaseBundle(_ context.Context, value packagedomain.ReleaseBundle) error {
	s.releaseBundles[value.ID] = cloneReleaseBundle(value)
	return nil
}
func (s *packageTestState) InsertPackageSignature(_ context.Context, value PackageSignature) error {
	s.signatures[value.ID] = value
	return nil
}
func (s *packageTestState) InsertEvidenceBundle(_ context.Context, value packagedomain.EvidenceBundle) error {
	s.evidenceBundles[value.ID] = cloneEvidenceBundle(value)
	return nil
}
func (s *packageTestState) InsertEvidenceBundleImport(_ context.Context, value packagedomain.EvidenceBundleImport) error {
	s.bundleImports[value.ID] = value
	return nil
}
func (s *packageTestState) InsertCustomReportTemplate(_ context.Context, value packagedomain.CustomReportTemplate) error {
	s.templates[value.ID] = cloneCustomReportTemplate(value)
	return nil
}
func (s *packageTestState) InsertRenderedCustomReport(_ context.Context, value packagedomain.RenderedCustomReport) error {
	s.renderedReports[value.ID] = cloneRenderedCustomReport(value)
	return nil
}
func (s *packageTestState) InsertHTMLReportPackage(_ context.Context, value packagedomain.HTMLReportPackage) error {
	s.htmlReports[value.ID] = value
	return nil
}
func (s *packageTestState) GetCustomerSecurityPackageForUpdate(ctx context.Context, tenantID, id string) (packagedomain.CustomerSecurityPackage, error) {
	return s.GetCustomerSecurityPackage(ctx, tenantID, id)
}
func (s *packageTestState) UpdateCustomerSecurityPackageAccess(_ context.Context, previous, next packagedomain.CustomerSecurityPackage) error {
	current, ok := s.packages[previous.ID]
	if !ok || !reflect.DeepEqual(current, previous) || next.AccessCount != previous.AccessCount+1 {
		return ErrConflict
	}
	s.packages[next.ID] = cloneCustomerSecurityPackage(next)
	return nil
}
func (s *packageTestState) AppendAudit(_ context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	if s.auditErr != nil {
		return application.AuditReceipt{}, s.auditErr
	}
	s.audit = append(s.audit, event)
	return application.AuditReceipt{ID: event.ID}, nil
}
func (s *packageTestState) EnqueueOutbox(_ context.Context, event application.OutboxEvent) error {
	s.outbox = append(s.outbox, event)
	return nil
}

type packageTestTransaction struct{ state *packageTestState }

func (t packageTestTransaction) Packages() Repository                   { return t.state }
func (t packageTestTransaction) Signatures() PackageSignatureRepository { return t.state }
func (t packageTestTransaction) Authorization() application.Authorizer {
	return packageTestAuthorizer(t)
}
func (t packageTestTransaction) Audit() application.AuditAppender   { return t.state }
func (t packageTestTransaction) Outbox() application.OutboxEnqueuer { return t.state }

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func assertNoSensitivePackageKeys(t *testing.T, value any) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if hardExcludedPackageFields[key] {
				t.Fatalf("sensitive field %q leaked in %#v", key, typed)
			}
			assertNoSensitivePackageKeys(t, child)
		}
	case []map[string]any:
		for _, child := range typed {
			assertNoSensitivePackageKeys(t, child)
		}
	case []any:
		for _, child := range typed {
			assertNoSensitivePackageKeys(t, child)
		}
	}
}
