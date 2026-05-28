package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestWaiverApprovalAndCustomerPackageFlow(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	item, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ProductID: release.ProductID, ReleaseID: release.ID, Type: "security_review", Title: "Review", PayloadHash: sampleDigest("review")})
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	waiver, err := ledger.CreateWaiver(ctx, actor, CreateWaiverInput{ScopeType: "release", ScopeID: release.ID, Owner: "security", Risk: "accepted temporarily", Reason: "vendor patch pending", ExpiresAt: fixedNow().Add(24 * time.Hour)})
	if err != nil {
		t.Fatalf("waiver: %v", err)
	}
	if _, err := ledger.ApproveWaiver(ctx, actor, waiver.ID); err != nil {
		t.Fatalf("approve waiver: %v", err)
	}
	approval, err := ledger.CreateApprovalRecord(ctx, actor, CreateApprovalInput{SubjectType: "waiver", SubjectID: waiver.ID, Decision: "approved", Reason: "risk accepted", EvidenceID: item.ID})
	if err != nil {
		t.Fatalf("approval: %v", err)
	}
	if approval.SubjectID != waiver.ID {
		t.Fatalf("approval subject = %s, want waiver", approval.SubjectID)
	}
	profile, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{Name: "customer", AllowedTypes: []string{"security_review"}})
	if err != nil {
		t.Fatalf("redaction profile: %v", err)
	}
	pkg, err := ledger.CreateCustomerSecurityPackage(ctx, actor, CreateCustomerPackageInput{ProductID: release.ProductID, ReleaseID: release.ID, RedactionProfileID: profile.ID, Title: "Customer package", ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("package: %v", err)
	}
	accessed, err := ledger.AccessCustomerSecurityPackage(ctx, actor, pkg.ID)
	if err != nil {
		t.Fatalf("access package: %v", err)
	}
	if accessed.AccessCount != 1 {
		t.Fatalf("access count = %d, want 1", accessed.AccessCount)
	}
	report, err := ledger.SecurityReviewPackageReport(ctx, actor, pkg.ID)
	if err != nil {
		t.Fatalf("security review package report: %v", err)
	}
	if len(report.EvidenceIDs) != 1 || report.EvidenceIDs[0] != item.ID {
		t.Fatalf("report evidence ids = %#v, want package evidence", report.EvidenceIDs)
	}
	archive, err := ledger.ExportCustomerSecurityPackageArchive(ctx, actor, pkg.ID)
	if err != nil {
		t.Fatalf("export package archive: %v", err)
	}
	if archive.MediaType != "application/zip" || archive.Hash != hashBytes(archive.Bytes) || archive.Size != int64(len(archive.Bytes)) {
		t.Fatalf("archive metadata invalid: %#v", archive)
	}
	files := packageArchiveFiles(t, archive.Bytes)
	for _, name := range []string{"manifest.json", "package.json", "verification.json", "README.txt"} {
		if files[name] == "" {
			t.Fatalf("archive missing %s: %#v", name, files)
		}
	}
	archiveText := strings.Join([]string{files["manifest.json"], files["package.json"], files["verification.json"], files["README.txt"]}, "\n")
	if !strings.Contains(archiveText, item.ID) {
		t.Fatalf("archive manifest missing package evidence id: %s", archiveText)
	}
	if strings.Contains(archiveText, `"tenant_id"`) || strings.Contains(archiveText, "legally compliant") || strings.Contains(archiveText, "certified secure") {
		t.Fatalf("archive leaked tenant internals or prohibited claims: %s", archiveText)
	}
	_, portalSecret, err := ledger.CreateCustomerPortalAccess(ctx, actor, CreateCustomerPortalAccessInput{PackageID: pkg.ID, CustomerName: "Customer", ExpiresAt: fixedNow().Add(time.Hour)})
	if err != nil {
		t.Fatalf("portal access: %v", err)
	}
	portalArchive, err := ledger.ExportCustomerPortalPackageArchive(ctx, portalSecret)
	if err != nil {
		t.Fatalf("portal export archive: %v", err)
	}
	if strings.Contains(strings.Join(mapValues(packageArchiveFiles(t, portalArchive.Bytes)), "\n"), portalSecret) {
		t.Fatalf("portal archive leaked access token")
	}
	_, _, secretB, err := ledger.BootstrapTenant(ctx, "Tenant B", "admin-b", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap B: %v", err)
	}
	actorB, err := ledger.Authenticate(ctx, secretB)
	if err != nil {
		t.Fatalf("auth B: %v", err)
	}
	if _, err := ledger.AccessCustomerSecurityPackage(ctx, actorB, pkg.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant package err=%v, want not found", err)
	}
	if _, err := ledger.ExportCustomerSecurityPackageArchive(ctx, actorB, pkg.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant package archive err=%v, want not found", err)
	}
}

func packageArchiveFiles(t *testing.T, body []byte) map[string]string {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("read archive: %v", err)
	}
	files := map[string]string{}
	for _, file := range reader.File {
		rc, err := file.Open()
		if err != nil {
			t.Fatalf("open %s: %v", file.Name, err)
		}
		content, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("read %s: %v", file.Name, err)
		}
		files[file.Name] = string(content)
	}
	return files
}

func mapValues(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

func TestTemplatesReportsEvidenceBundleAndCRAHTML(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	if _, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ProductID: release.ProductID, ReleaseID: release.ID, Type: "sbom", Title: "SBOM", PayloadHash: sampleDigest("sbom")}); err != nil {
		t.Fatalf("evidence: %v", err)
	}
	packs, err := ledger.ListControlFrameworkTemplatePacks(ctx, actor)
	if err != nil {
		t.Fatalf("template packs: %v", err)
	}
	if len(packs) == 0 {
		t.Fatal("expected built-in packs")
	}
	framework, err := ledger.InstallControlFrameworkTemplatePack(ctx, actor, "evydence-cra-readiness")
	if err != nil {
		t.Fatalf("install pack: %v", err)
	}
	if framework.Slug != "evydence-cra-readiness" {
		t.Fatalf("framework slug = %s", framework.Slug)
	}
	htmlPkg, err := ledger.CRAReadinessHTMLPackage(ctx, actor, release.ProductID, release.ID)
	if err != nil {
		t.Fatalf("CRA HTML: %v", err)
	}
	if htmlPkg.Hash == "" || htmlPkg.HTML == "" {
		t.Fatalf("html package = %#v", htmlPkg)
	}
	tpl, err := ledger.CreateCustomReportTemplate(ctx, actor, CreateReportTemplateInput{Name: "simple", Version: "1", ReportType: "evidence", AllowedFields: []string{"subject_type", "subject_id"}, Template: "json"})
	if err != nil {
		t.Fatalf("report template: %v", err)
	}
	rendered, err := ledger.RenderCustomReport(ctx, actor, RenderReportInput{TemplateID: tpl.ID, SubjectType: "release", SubjectID: release.ID})
	if err != nil {
		t.Fatalf("render report: %v", err)
	}
	if rendered.Output["subject_id"] != release.ID || rendered.Hash == "" {
		t.Fatalf("rendered report = %#v", rendered)
	}
	bundle, err := ledger.ExportEvidenceBundle(ctx, actor, release.ID, nil)
	if err != nil {
		t.Fatalf("export bundle: %v", err)
	}
	if bundle.ManifestHash == "" || len(bundle.EvidenceIDs) == 0 {
		t.Fatalf("bundle = %#v", bundle)
	}
	imported, err := ledger.ImportEvidenceBundle(ctx, actor, bundle)
	if err != nil {
		t.Fatalf("import bundle: %v", err)
	}
	if imported.ImportedCount != len(bundle.EvidenceIDs) {
		t.Fatalf("imported count = %d want %d", imported.ImportedCount, len(bundle.EvidenceIDs))
	}
}

func TestDSSETrustRootVerification(t *testing.T) {
	objectStore := newTestObjectStore()
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, ObjectStore: objectStore})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	project, err := ledger.CreateProject(ctx, actor, release.ProductID, "api")
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	build, err := ledger.CreateBuildRun(ctx, actor, CreateBuildRunInput{ProjectID: project.ID, ReleaseID: release.ID, Provider: "generic_ci", CommitSHA: "0123456789abcdef0123456789abcdef01234567", Status: "passed", StartedAt: fixedNow(), Outputs: []domain.BuildOutput{{ArtifactID: artifact.ID, Digest: artifact.Digest}}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	statement := map[string]any{"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://slsa.dev/provenance/v1", "subject": []map[string]any{{"name": "api.tar.gz", "digest": map[string]string{"sha256": artifact.Digest[len("sha256:"):]}}}, "predicate": map[string]any{"builder": map[string]string{"id": "builder"}, "buildType": "test", "materials": []any{}}}
	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	sig := ed25519.Sign(priv, payload)
	envelope, err := json.Marshal(map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": base64.StdEncoding.EncodeToString(payload), "signatures": []map[string]string{{"keyid": "root-1", "sig": base64.StdEncoding.EncodeToString(sig)}}})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	att, err := ledger.UploadBuildAttestation(ctx, actor, build.ID, envelope)
	if err != nil {
		t.Fatalf("attestation: %v", err)
	}
	if _, err := ledger.CreateDSSETrustRoot(ctx, actor, CreateDSSETrustRootInput{Name: "root", KeyID: "root-1", Algorithm: "Ed25519", PublicKey: base64.StdEncoding.EncodeToString(pub)}); err != nil {
		t.Fatalf("trust root: %v", err)
	}
	vr, err := ledger.VerifyDSSEAttestationSignature(ctx, actor, att.ID)
	if err != nil {
		t.Fatalf("verify dsse: %v", err)
	}
	if vr.Result != "passed" {
		t.Fatalf("verification result = %s", vr.Result)
	}
}

type testObjectStore struct {
	objects map[string]Object
}

func newTestObjectStore() *testObjectStore {
	return &testObjectStore{objects: map[string]Object{}}
}

func (s *testObjectStore) Put(_ context.Context, object Object) error {
	s.objects[object.Key] = object
	return nil
}

func (s *testObjectStore) Get(_ context.Context, key string) (Object, error) {
	object, ok := s.objects[key]
	if !ok {
		return Object{}, ErrNotFound
	}
	return object, nil
}
