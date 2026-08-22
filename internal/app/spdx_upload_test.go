package app

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

const validSPDXUpload = `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"example","documentNamespace":"https://example.test/spdx","dataLicense":"CC0-1.0","creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: test"]},"packages":[{"SPDXID":"SPDXRef-Package","name":"api","versionInfo":"1.0.0","licenseDeclared":"MIT","checksums":[{"algorithm":"SHA256","checksumValue":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:generic/api@1.0.0"}]}],"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-Package"}],"x-legal-extension":"retain"}`

func TestValidatedSPDXUploadPersistsReportAndStableIdentity(t *testing.T) {
	ctx := context.Background()
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	product, err := ledger.CreateProduct(ctx, actor, "API", "api")
	if err != nil {
		t.Fatal(err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := ledger.RegisterArtifact(ctx, actor, "api.tar", "application/gzip", sampleDigest("artifact"), 42)
	if err != nil {
		t.Fatal(err)
	}
	sbom, err := ledger.UploadSPDXSBOM(ctx, actor, release.ID, artifact.ID, []byte(validSPDXUpload))
	if err != nil {
		t.Fatal(err)
	}
	if sbom.SpecVersion != "SPDX-2.3" || len(sbom.Components) != 1 || sbom.Components[0].Identity != "purl:pkg:generic/api@1.0.0" {
		t.Fatalf("sbom=%#v", sbom)
	}
	evidence, err := ledger.GetEvidence(ctx, actor, sbom.EvidenceID)
	if err != nil {
		t.Fatal(err)
	}
	report, ok := evidence.Metadata["import_report"].(map[string]any)
	if !ok || evidence.Metadata["parser_version"] != ParserVersionSPDXJSON || report["parser_version"] != ParserVersionSPDXJSON || evidence.Metadata["relationship_count"] != 1 {
		t.Fatalf("metadata=%#v", evidence.Metadata)
	}
}

func TestValidatedSPDXUploadRejectsForeignTargetBeforeOpeningPayload(t *testing.T) {
	ctx := context.Background()
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	_, _, ownerSecret, err := ledger.BootstrapTenant(ctx, "Owner", "owner", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := ledger.Authenticate(ctx, ownerSecret)
	if err != nil {
		t.Fatal(err)
	}
	product, err := ledger.CreateProduct(ctx, owner, "API", "api")
	if err != nil {
		t.Fatal(err)
	}
	release, err := ledger.CreateRelease(ctx, owner, product.ID, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	_, _, otherSecret, err := ledger.BootstrapTenant(ctx, "Other", "other", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := ledger.Authenticate(ctx, otherSecret)
	if err != nil {
		t.Fatal(err)
	}
	source := BytesPayloadSource([]byte(validSPDXUpload))
	openCount := 0
	open := source.Open
	source.Open = func() (io.ReadCloser, error) { openCount++; return open() }
	if _, err := ledger.UploadSPDXSBOMPayload(ctx, other, release.ID, "", source); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err=%v, want not found", err)
	}
	if openCount != 0 {
		t.Fatalf("payload opened %d times before foreign-target rejection", openCount)
	}
}

func TestSBOMDiffDoesNotMergePURLlessSPDXAndCycloneDXComponents(t *testing.T) {
	base := []domain.SBOMComponent{{Identity: "spdx:SPDXRef-Package", Name: "api", Version: "1.0.0"}}
	target := []domain.SBOMComponent{{Identity: "cyclonedx:pkg-ref", Name: "api", Version: "1.0.0"}}
	added, removed, unchanged := diffComponents(base, target)
	if len(added) != 1 || len(removed) != 1 || unchanged != 0 {
		t.Fatalf("added=%#v removed=%#v unchanged=%d", added, removed, unchanged)
	}
	if strings.TrimSpace(added[0].Identity) == "" || strings.TrimSpace(removed[0].Identity) == "" {
		t.Fatal("component identities were not retained")
	}
}

func TestValidatedSPDXUploadUsesUnitOfWorkAndWorkerOwnedProjection(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	ledger.workerOwnedParsers = true
	product, err := ledger.CreateProduct(ctx, actor, "UOW SPDX", "uow-spdx")
	if err != nil {
		t.Fatal(err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := ledger.RegisterArtifact(ctx, actor, "uow.tar", "application/gzip", sampleDigest("uow-spdx"), 42)
	if err != nil {
		t.Fatal(err)
	}
	sbom, err := ledger.UploadSPDXSBOM(ctx, actor, release.ID, artifact.ID, []byte(validSPDXUpload))
	if err != nil {
		t.Fatal(err)
	}
	if sbom.ComponentCount != 1 || len(sbom.Components) != 1 {
		t.Fatalf("returned sbom=%#v", sbom)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	persisted := snapshot.SBOMs[sbom.ID]
	if persisted.ComponentCount != 0 || len(persisted.Components) != 0 || len(snapshot.OutboxJobs) == 0 {
		t.Fatalf("worker-owned durable state=%#v jobs=%#v", persisted, snapshot.OutboxJobs)
	}
	var job OutboxJob
	for _, candidate := range snapshot.OutboxJobs {
		if candidate.SubjectID == sbom.ID {
			job = candidate
			break
		}
	}
	if job.Kind != "parse_sbom" || job.Payload["parser_version"] != ParserVersionSPDXJSON {
		t.Fatalf("outbox job=%#v", job)
	}
}
