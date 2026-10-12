package app

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func memoryControlEvidenceFixture(t *testing.T) (*memoryUnitOfWork, riskapp.ControlEvidenceReader, riskapp.ControlEvidenceArtifactGrantReader) {
	t.Helper()
	tx, _ := memoryControlsQueryFixture(t)
	reader, ok := tx.Repositories().Controls.(riskapp.ControlEvidenceReader)
	if !ok {
		t.Fatal("memory controls lack focused link reads")
	}
	grants, ok := tx.Repositories().Controls.(riskapp.ControlEvidenceArtifactGrantReader)
	if !ok {
		t.Fatal("memory controls lack current artifact grants")
	}
	return tx, reader, grants
}

func TestMemoryControlEvidenceReadsCheckCurrentParentsAndBoundDuplicate(t *testing.T) {
	tx, reader, _ := memoryControlEvidenceFixture(t)
	if err := reader.LockControlEvidenceTenant(t.Context(), "tenant"); err != nil {
		t.Fatal(err)
	}
	if ok, err := reader.ControlEvidenceControlExists(t.Context(), "tenant", "tenant-control"); err != nil || !ok {
		t.Fatal("current control absent", err)
	}
	for _, tc := range []struct{ kind, id string }{{"evidence", "tenant-evidence"}, {"evidence_item", "tenant-evidence"}, {"product", "tenant-product"}, {"release", "tenant-release"}, {"vulnerability_scan", "tenant-scan"}, {"finding", "tenant-finding"}, {"vulnerability_finding", "tenant-finding"}, {"exception", "tenant-exception"}} {
		v, err := reader.ReadControlEvidenceSubject(t.Context(), "tenant", riskapp.ControlEvidenceSubjectKey{SubjectType: tc.kind, SubjectID: tc.id, ProductID: "tenant-product"})
		if err != nil || v.TenantID != "tenant" || v.SubjectID != tc.id || v.SubjectType != tc.kind || v.ProductID != "tenant-product" {
			t.Fatal("current subject/provenance lost", tc.kind, err)
		}
	}
	key := riskapp.ControlEvidenceLinkKey{ControlID: "tenant-control", EvidenceType: "build", SubjectType: "evidence", SubjectID: "tenant-evidence", ProductID: "tenant-product", ReleaseID: "tenant-release"}
	link := domain.ControlEvidence{ID: "link", TenantID: "tenant", ControlID: key.ControlID, EvidenceType: key.EvidenceType, SubjectType: key.SubjectType, SubjectID: key.SubjectID, ProductID: key.ProductID, ReleaseID: key.ReleaseID, Confidence: "high", Notes: strings.Repeat("n", 65536), SchemaVersion: riskdomain.ControlEvidenceSchemaVersion, CreatedAt: fixedNow()}
	tx.state.ControlEvidence[link.ID] = link
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	if v, found, err := reader.ReadControlEvidenceLink(t.Context(), "tenant", key); err != nil || !found || v != riskdomain.ControlEvidence(link) {
		t.Fatal("natural key lost complete bounded duplicate", err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("link read changed state")
	}
	link.Notes += "x"
	tx.state.ControlEvidence[link.ID] = link
	if v, found, err := reader.ReadControlEvidenceLink(t.Context(), "tenant", key); !errors.Is(err, ErrValidation) || found || v != (riskdomain.ControlEvidence{}) {
		t.Fatal("overflow exposed duplicate metadata", err)
	}
	for _, bad := range []riskapp.ControlEvidenceSubjectKey{{SubjectType: "evidence", SubjectID: "foreign-evidence"}, {SubjectType: "vulnerability_scan", SubjectID: "tenant-scan", ProductID: "foreign-product"}, {SubjectType: "unknown", SubjectID: "tenant-evidence"}} {
		if v, err := reader.ReadControlEvidenceSubject(t.Context(), "tenant", bad); !errors.Is(err, ErrNotFound) || v != (riskapp.ControlEvidenceSubjectCoordinates{}) {
			t.Fatal("foreign/mismatched/unknown subject accepted", err)
		}
	}
	e := tx.state.Evidence["tenant-evidence"]
	e.Type = "security_review"
	tx.state.Evidence[e.ID] = e
	if _, err := reader.ReadControlEvidenceSubject(t.Context(), "tenant", riskapp.ControlEvidenceSubjectKey{SubjectType: "vulnerability_scan", SubjectID: "tenant-scan"}); !errors.Is(err, ErrNotFound) {
		t.Fatal("parser source type mismatch accepted", err)
	}
	e = before.Evidence[e.ID]
	tx.state.Evidence[e.ID] = e
	scan := tx.state.VulnerabilityScans["tenant-scan"]
	scan.ID = "other-scan"
	tx.state.VulnerabilityScans[scan.ID] = scan
	if _, err := reader.ReadControlEvidenceSubject(t.Context(), "tenant", riskapp.ControlEvidenceSubjectKey{SubjectType: "finding", SubjectID: "tenant-finding"}); !errors.Is(err, ErrConflict) {
		t.Fatal("ambiguous finding coordinate accepted", err)
	}
	f := tx.state.ControlFrameworks["tenant-framework"]
	f.TenantID = "foreign"
	tx.state.ControlFrameworks[f.ID] = f
	if found, err := reader.ControlEvidenceControlExists(t.Context(), "tenant", "tenant-control"); err != nil || found {
		t.Fatal("foreign framework conferred link authority", err)
	}
}

func TestMemoryControlEvidenceArtifactGrantsFilterAssociationsBeforeChoosingOne(t *testing.T) {
	tx, reader, grants := memoryControlEvidenceFixture(t)
	tx.state.Artifacts["artifact"] = domain.Artifact{ID: "artifact", TenantID: "tenant", Digest: "sha256:recorded"}
	for _, name := range []string{"private", "allowed"} {
		tx.state.Products[name] = domain.Product{ID: name, TenantID: "tenant"}
		tx.state.Evidence[name] = domain.EvidenceItem{ID: name, TenantID: "tenant", ProductID: name, SubjectRefs: []domain.SubjectRef{{Type: "artifact", ID: "artifact"}}}
	}
	key := riskapp.ControlEvidenceSubjectKey{SubjectType: "artifact", SubjectID: "artifact", ProductID: "allowed"}
	if v, err := reader.ReadControlEvidenceSubject(t.Context(), "tenant", key); err != nil || v.ProductID != "allowed" {
		t.Fatal("artifact coordinate filter chose wrong association", err)
	}
	request := riskapp.ControlEvidenceArtifactGrantRequest{TenantID: "tenant", ArtifactID: "artifact", AllowedProductIDs: []string{"allowed"}}
	if visible, err := grants.ControlEvidenceArtifactVisible(t.Context(), request); err != nil || !visible {
		t.Fatal("arbitrary association hid valid artifact grant", err)
	}
	request.ProductID = "private"
	if visible, err := grants.ControlEvidenceArtifactVisible(t.Context(), request); err != nil || visible {
		t.Fatal("supplied scope bypassed association grant", err)
	}
	request.ProductID, request.ArtifactID = "", "foreign-artifact"
	if visible, err := grants.ControlEvidenceArtifactVisible(t.Context(), request); err != nil || visible {
		t.Fatal("foreign artifact grant accepted", err)
	}
	delete(tx.state.Evidence, "allowed")
	request.ArtifactID = "artifact"
	if visible, err := grants.ControlEvidenceArtifactVisible(t.Context(), request); err != nil || visible {
		t.Fatal("deleted current association retained grant", err)
	}
}

func TestMemoryControlEvidenceParsedSubjectsKeepTheirNativeParentCoordinates(t *testing.T) {
	tx, reader, _ := memoryControlEvidenceFixture(t)
	tx.state.Projects["project"] = domain.Project{ID: "project", TenantID: "tenant", ProductID: "tenant-product"}
	tx.state.BuildRuns["build"] = domain.BuildRun{ID: "build", TenantID: "tenant", ProjectID: "project", ReleaseID: "tenant-release", CreatedAt: fixedNow()}
	for _, kind := range []string{"sbom", "vex", "build_attestation", "openapi_contract"} {
		id := kind + "-evidence"
		tx.state.Evidence[id] = domain.EvidenceItem{ID: id, TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", Type: kind}
	}
	tx.state.Artifacts["artifact"] = domain.Artifact{ID: "artifact", TenantID: "tenant"}
	tx.state.SBOMs["sbom"] = domain.SBOM{ID: "sbom", TenantID: "tenant", EvidenceID: "sbom-evidence", ReleaseID: "tenant-release", ArtifactID: "artifact"}
	tx.state.VEXDocuments["vex"] = domain.VEXDocument{ID: "vex", TenantID: "tenant", EvidenceID: "vex-evidence", ReleaseID: "tenant-release", ArtifactID: "artifact"}
	tx.state.BuildAttestations["attestation"] = domain.BuildAttestation{ID: "attestation", TenantID: "tenant", EvidenceID: "build_attestation-evidence", BuildID: "build"}
	tx.state.OpenAPIContracts["contract"] = domain.OpenAPIContract{ID: "contract", TenantID: "tenant", EvidenceID: "openapi_contract-evidence", ProductID: "tenant-product", ReleaseID: "tenant-release"}
	tx.state.ReleaseBundles["bundle"] = domain.ReleaseBundle{ID: "bundle", TenantID: "tenant", ReleaseID: "tenant-release"}
	tx.state.Decisions["decision"] = domain.VulnerabilityDecision{ID: "decision", TenantID: "tenant", FindingID: "tenant-finding", ScanID: "tenant-scan", ReleaseID: "tenant-release"}
	for _, tc := range []struct{ kind, id, project string }{{"sbom", "sbom", ""}, {"vex", "vex", ""}, {"build", "build", "project"}, {"build_attestation", "attestation", "project"}, {"openapi_contract", "contract", ""}, {"release_bundle", "bundle", ""}, {"vulnerability_decision", "decision", ""}} {
		key := riskapp.ControlEvidenceSubjectKey{SubjectType: tc.kind, SubjectID: tc.id}
		v, err := reader.ReadControlEvidenceSubject(t.Context(), "tenant", key)
		if err != nil || v.ProductID != "tenant-product" || v.ProjectID != tc.project || v.ReleaseID != "tenant-release" {
			t.Fatal("parsed subject lost native owner/project/release", tc.kind, v, err)
		}
	}
	delete(tx.state.Artifacts, "artifact")
	for _, kind := range []string{"sbom", "vex"} {
		if _, err := reader.ReadControlEvidenceSubject(t.Context(), "tenant", riskapp.ControlEvidenceSubjectKey{SubjectType: kind, SubjectID: kind}); !errors.Is(err, ErrNotFound) {
			t.Fatal("missing parser artifact parent accepted", kind, err)
		}
	}
	e := tx.state.Evidence["build_attestation-evidence"]
	e.ProjectID = "foreign-project"
	tx.state.Evidence[e.ID] = e
	if _, err := reader.ReadControlEvidenceSubject(t.Context(), "tenant", riskapp.ControlEvidenceSubjectKey{SubjectType: "build_attestation", SubjectID: "attestation"}); !errors.Is(err, ErrNotFound) {
		t.Fatal("attestation accepted foreign current evidence project", err)
	}
	v := tx.state.Decisions["decision"]
	v.FindingID = "missing"
	tx.state.Decisions[v.ID] = v
	if _, err := reader.ReadControlEvidenceSubject(t.Context(), "tenant", riskapp.ControlEvidenceSubjectKey{SubjectType: "vulnerability_decision", SubjectID: v.ID}); !errors.Is(err, ErrNotFound) {
		t.Fatal("decision without current finding accepted", err)
	}
}
