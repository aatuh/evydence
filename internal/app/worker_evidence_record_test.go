package app

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func assertSelectedWorkerRecordContract[T any](t *testing.T, item domain.EvidenceItem, value T, invalid ...func(*T)) {
	t.Helper()
	if err := ValidateWorkerEvidenceRecord(item, value); err != nil {
		t.Fatal("valid selected worker record rejected", err)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"id", "tenant_id", "evidence_id"} {
		var fields map[string]any
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		fields[field] = "foreign-or-malformed"
		if field == "id" {
			fields[field] = " malformed "
		}
		changed, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		var bad T
		if err := json.Unmarshal(changed, &bad); err != nil {
			t.Fatal(err)
		}
		if err := ValidateWorkerEvidenceRecord(item, bad); !errors.Is(err, ErrConflict) {
			t.Fatal("selected worker record accepted invalid identity or ownership", field, err)
		}
	}
	for _, mutate := range invalid {
		bad := value
		mutate(&bad)
		if err := ValidateWorkerEvidenceRecord(item, bad); !errors.Is(err, ErrConflict) {
			t.Fatal("selected worker record accepted an invalid parsed shape or relationship", err)
		}
	}
}

func TestSelectedWorkerRecordValidatorsRemainIndependentOfLegacyMerge(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	item := domain.EvidenceItem{ID: "evidence", TenantID: "tenant", ReleaseID: "release"}
	t.Run("sbom", func(t *testing.T) {
		item := item
		item.Type = "sbom"
		item.SubjectRefs = []domain.SubjectRef{{Type: "artifact", ID: "artifact"}}
		value := domain.SBOM{ID: "sbom", TenantID: "tenant", EvidenceID: "evidence", ReleaseID: "release", ArtifactID: "artifact", Format: "cyclonedx", SpecVersion: "1.6", ComponentCount: 1, Components: []domain.SBOMComponent{{Name: "component"}}, CreatedAt: now}
		assertSelectedWorkerRecordContract(t, item, value,
			func(v *domain.SBOM) { v.ComponentCount = -1 },
			func(v *domain.SBOM) { v.ComponentCount = 2 },
			func(v *domain.SBOM) { v.SpecVersion = "" },
			func(v *domain.SBOM) { v.Format = "" },
			func(v *domain.SBOM) { v.CreatedAt = time.Time{} },
			func(v *domain.SBOM) { v.ReleaseID = "foreign" },
			func(v *domain.SBOM) { v.ArtifactID = "foreign" })
		value.SpecVersion, value.ComponentCount, value.Components = "", 0, nil
		if err := ValidateWorkerEvidenceRecord(item, value); err != nil {
			t.Fatal("queued SBOM acceptance changed", err)
		}
	})
	t.Run("scan", func(t *testing.T) {
		item := item
		item.Type = "vulnerability_scan"
		value := domain.VulnerabilityScan{ID: "scan", TenantID: "tenant", EvidenceID: "evidence", ReleaseID: "release", Scanner: "scanner", Adapter: "adapter", AdapterVersion: "1", SourceSchema: "schema", TargetRef: "target", Findings: []domain.VulnerabilityFinding{{ID: "finding", Vulnerability: "CVE-example"}}, CreatedAt: now}
		assertSelectedWorkerRecordContract(t, item, value,
			func(v *domain.VulnerabilityScan) { v.AdapterVersion = "" },
			func(v *domain.VulnerabilityScan) { v.Findings = append(v.Findings, v.Findings[0]) },
			func(v *domain.VulnerabilityScan) { v.Findings = []domain.VulnerabilityFinding{{ID: "finding"}} },
			func(v *domain.VulnerabilityScan) {
				v.Findings = []domain.VulnerabilityFinding{{Vulnerability: "CVE-example"}}
			},
			func(v *domain.VulnerabilityScan) { v.CreatedAt = time.Time{} },
			func(v *domain.VulnerabilityScan) { v.ReleaseID = "foreign" })
		value.Scanner, value.Adapter, value.AdapterVersion, value.SourceSchema, value.TargetRef, value.Findings = "", "", "", "", "", nil
		if err := ValidateWorkerEvidenceRecord(item, value); err != nil {
			t.Fatal("queued scan acceptance changed", err)
		}
	})
	t.Run("contract", func(t *testing.T) {
		item := item
		item.Type, item.ProductID = "openapi_contract", "product"
		value := domain.OpenAPIContract{ID: "contract", TenantID: "tenant", EvidenceID: "evidence", ProductID: "product", ReleaseID: "release", Version: "1", Hash: "hash", PathCount: 1, CreatedAt: now}
		assertSelectedWorkerRecordContract(t, item, value,
			func(v *domain.OpenAPIContract) { v.ProductID = "foreign" },
			func(v *domain.OpenAPIContract) { v.ReleaseID = "foreign" },
			func(v *domain.OpenAPIContract) { v.Version = "" },
			func(v *domain.OpenAPIContract) { v.Hash = "" },
			func(v *domain.OpenAPIContract) { v.PathCount = -1 },
			func(v *domain.OpenAPIContract) { v.CreatedAt = time.Time{} })
	})
	t.Run("vex", func(t *testing.T) {
		item := item
		item.Type = "vex"
		item.SubjectRefs = []domain.SubjectRef{{Type: "artifact", ID: "artifact"}}
		value := domain.VEXDocument{ID: "vex", TenantID: "tenant", EvidenceID: "evidence", ReleaseID: "release", ArtifactID: "artifact", Format: "openvex", SchemaVersion: "vex.v1", StatementCount: 1, CreatedAt: now}
		assertSelectedWorkerRecordContract(t, item, value,
			func(v *domain.VEXDocument) { v.ReleaseID = "foreign" },
			func(v *domain.VEXDocument) { v.ArtifactID = "foreign" },
			func(v *domain.VEXDocument) { v.Format = "" },
			func(v *domain.VEXDocument) { v.SchemaVersion = "" },
			func(v *domain.VEXDocument) { v.StatementCount = -1 },
			func(v *domain.VEXDocument) { v.CreatedAt = time.Time{} })
	})
	t.Run("attestation", func(t *testing.T) {
		item := item
		item.Type, item.BuildID = "build_attestation", "build"
		value := domain.BuildAttestation{ID: "attestation", TenantID: "tenant", EvidenceID: "evidence", BuildID: "build", SchemaVersion: "attestation.v1", PayloadSize: 1, PayloadType: "application/vnd.in-toto+json", PredicateType: "provenance", VerificationStatus: "structurally_valid", CreatedAt: now}
		assertSelectedWorkerRecordContract(t, item, value,
			func(v *domain.BuildAttestation) { v.BuildID = "foreign" },
			func(v *domain.BuildAttestation) { v.SchemaVersion = "" },
			func(v *domain.BuildAttestation) { v.PayloadSize = -1 },
			func(v *domain.BuildAttestation) { v.MaterialsCount = -1 },
			func(v *domain.BuildAttestation) { v.SignatureCount = -1 },
			func(v *domain.BuildAttestation) { v.PayloadType = "" },
			func(v *domain.BuildAttestation) { v.PredicateType = "" },
			func(v *domain.BuildAttestation) { v.VerificationStatus = "trusted" },
			func(v *domain.BuildAttestation) { v.CreatedAt = time.Time{} })
		value.VerificationStatus, value.PayloadType, value.PredicateType = "accepted", "", ""
		if err := ValidateWorkerEvidenceRecord(item, value); err != nil {
			t.Fatal("queued attestation acceptance changed", err)
		}
	})
	item.Type = "sbom"
	if err := ValidateWorkerEvidenceRecord(item, domain.Artifact{}); !errors.Is(err, ErrConflict) {
		t.Fatal("unsupported parsed record was accepted", err)
	}
}

func TestWorkerEvidenceRecordRejectsInvalidSelectedProjections(t *testing.T) {
	item := domain.EvidenceItem{ID: "evidence", TenantID: "tenant", ReleaseID: "release", Type: "sbom", SubjectRefs: []domain.SubjectRef{{Type: "artifact", ID: "artifact"}}}
	value := domain.SBOM{ID: "sbom", TenantID: "tenant", EvidenceID: "evidence", ReleaseID: "release", ArtifactID: "artifact", Format: "cyclonedx", SpecVersion: "1.6", ComponentCount: 1, Components: []domain.SBOMComponent{{Name: "component"}}, CreatedAt: time.Now()}
	if err := ValidateWorkerEvidenceRecord(item, value); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*domain.SBOM){
		func(v *domain.SBOM) { v.ID = " malformed " },
		func(v *domain.SBOM) { v.TenantID = "foreign" }, func(v *domain.SBOM) { v.EvidenceID = "other" }, func(v *domain.SBOM) { v.ReleaseID = "other" },
		func(v *domain.SBOM) { v.ArtifactID = "other" }, func(v *domain.SBOM) { v.ComponentCount = 2 }, func(v *domain.SBOM) { v.Format = "" },
	} {
		bad := value
		mutate(&bad)
		if err := ValidateWorkerEvidenceRecord(item, bad); err == nil {
			t.Fatal("invalid projection accepted", bad)
		}
	}
}
