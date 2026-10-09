package app

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func memoryCustomerEvidenceFixture(t *testing.T) *memoryUnitOfWork {
	t.Helper()
	tx := memoryCustomerCatalogFixture(t)
	s := &tx.state
	for _, kind := range []string{"sbom", "vulnerability_scan", "vex", "openapi_contract"} {
		e := s.Evidence["selected"]
		e.ID, e.Type = kind+"-source", kind
		e.SubjectRefs = nil
		if kind == "sbom" || kind == "vex" {
			e.SubjectRefs = []domain.SubjectRef{{Type: "artifact", ID: "artifact-evidence"}}
		}
		s.Evidence[e.ID] = e
	}
	s.SBOMs["sbom"] = domain.SBOM{ID: "sbom", TenantID: "tenant", EvidenceID: "sbom-source", ReleaseID: "tenant-release", ArtifactID: "artifact-evidence", Format: "CycloneDX", SpecVersion: "1.6", ComponentCount: 1, Components: []domain.SBOMComponent{{Name: "private-component-marker"}}, CreatedAt: fixedNow()}
	s.VulnerabilityScans["scan"] = domain.VulnerabilityScan{ID: "scan", TenantID: "tenant", EvidenceID: "vulnerability_scan-source", ReleaseID: "tenant-release", Scanner: "Trivy", TargetRef: "sha256:target", Summary: map[string]int{"critical": 1}, Findings: []domain.VulnerabilityFinding{{ID: "private-finding-marker", Vulnerability: "CVE-fixture"}}, CreatedAt: fixedNow()}
	s.VEXDocuments["vex"] = domain.VEXDocument{ID: "vex", TenantID: "tenant", EvidenceID: "vex-source", ReleaseID: "tenant-release", ArtifactID: "artifact-evidence", Format: "OpenVEX", Version: "1", StatementCount: 1, StatusSummary: map[string]int{"not_affected": 1}, SchemaVersion: "vex.v1", Author: "private-author-marker", CreatedAt: fixedNow()}
	c := domain.OpenAPIContract{ID: "contract", TenantID: "tenant", EvidenceID: "openapi_contract-source", ProductID: "tenant-product", ReleaseID: "tenant-release", Version: "3.1.0", Hash: "sha256:contract", PathCount: 1, Operations: []domain.OpenAPIOperation{{Path: " /z ", Method: " post ", OperationID: "create", RequiredRequestFields: []string{"title"}, ResponseStatuses: []string{"201"}}, {Path: "/a", Method: "get"}}, CreatedAt: fixedNow()}
	s.OpenAPIContracts[c.ID] = c
	c.ID, c.ReleaseID = "base-contract", "other-release"
	e := s.Evidence["openapi_contract-source"]
	e.ID, e.ReleaseID = "base-contract-source", "other-release"
	s.Evidence[e.ID] = e
	c.EvidenceID = e.ID
	s.OpenAPIContracts[c.ID] = c
	s.ContractDiffs["diff"] = domain.ContractDiff{ID: "diff", TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", BaseContractID: "base-contract", TargetContractID: "contract", Result: "breaking", BreakingChanges: []string{"removed GET /old"}, NonBreakingChanges: []string{"added GET /a"}, SchemaVersion: "contract-diff.v1", CreatedAt: fixedNow()}
	return tx
}

func TestMemoryCustomerPackageEvidencePreservesPublicSummariesAndDetachesCollections(t *testing.T) {
	tx := memoryCustomerEvidenceFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	budget := &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	v, err := readMemoryCustomerPackageEvidence(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", budget)
	if err != nil || len(v.SBOMs) != 1 || len(v.Scans) != 1 || len(v.VEX) != 1 {
		t.Fatal("parsed public sections missing or unowned rows selected", v, err)
	}
	if v.SBOMs[0]["component_count"] != 1 || v.Scans[0]["finding_count"] != 1 || v.VEX[0]["statement_count"] != 1 || !reflect.DeepEqual(v.Scans[0]["summary"], map[string]int{"critical": 1}) || !reflect.DeepEqual(v.VEX[0]["status_summary"], map[string]int{"not_affected": 1}) {
		t.Fatal("public parsed counts changed", v)
	}
	contracts := v.Contracts["openapi_contracts"].([]map[string]any)
	diffs := v.Contracts["contract_diffs"].([]map[string]any)
	if len(contracts) != 1 || contracts[0]["id"] != "contract" || len(diffs) != 1 || diffs[0]["base_contract_id"] != "base-contract" || len(v.Contracts["limitations"].([]string)) != 3 {
		t.Fatal("contract/diff selection or limitations changed", v.Contracts)
	}
	ops := contracts[0]["operations"].([]map[string]any)
	if len(ops) != 2 || ops[0]["label"] != "GET /a" || ops[1]["label"] != "POST /z" || ops[1]["operation_id"] != "create" || contracts[0]["operation_count"] != 2 {
		t.Fatal("shared operation normalization changed", ops)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, hidden := range []string{"private-", "foreign", "bad-sbom", "payload_ref", "components", "findings"} {
		if strings.Contains(string(raw), hidden) {
			t.Fatal("raw/private/out-of-scope evidence projected", hidden)
		}
	}
	v.Scans[0]["summary"].(map[string]int)["critical"] = 42
	v.VEX[0]["status_summary"].(map[string]int)["not_affected"] = 42
	ops[1]["required_request_fields"].([]string)[0] = "changed"
	diffs[0]["breaking_changes"].([]string)[0] = "changed"
	if !reflect.DeepEqual(tx.state, before) || budget.remainingBytes >= packageapp.MaxCustomerPackageManifestBytes {
		t.Fatal("read/caller mutation changed storage or no shared budget charged")
	}
}

func TestMemoryCustomerPackageEvidenceRejectsIncoherentSourcesAndOversizeBeforePartialPublication(t *testing.T) {
	for _, change := range []struct {
		name string
		edit func(*MemoryUnitOfWorkSnapshot)
	}{
		{"source kind", func(s *MemoryUnitOfWorkSnapshot) {
			e := s.Evidence["sbom-source"]
			e.Type = "document"
			s.Evidence[e.ID] = e
		}},
		{"source release", func(s *MemoryUnitOfWorkSnapshot) {
			e := s.Evidence["sbom-source"]
			e.ReleaseID = "other-release"
			s.Evidence[e.ID] = e
		}},
		{"source project", func(s *MemoryUnitOfWorkSnapshot) {
			e := s.Evidence["sbom-source"]
			e.ProjectID = "sibling-project"
			s.Evidence[e.ID] = e
		}},
		{"artifact tenant", func(s *MemoryUnitOfWorkSnapshot) {
			d := s.SBOMs["sbom"]
			d.ArtifactID = "artifact-foreign"
			s.SBOMs[d.ID] = d
		}},
		{"artifact binding", func(s *MemoryUnitOfWorkSnapshot) {
			e := s.Evidence["sbom-source"]
			e.SubjectRefs = []domain.SubjectRef{{Type: "artifact", ID: "artifact-vex"}}
			s.Evidence[e.ID] = e
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			tx := memoryCustomerEvidenceFixture(t)
			change.edit(&tx.state)
			v, err := readMemoryCustomerPackageEvidence(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
			if err != nil || len(v.SBOMs) != 0 {
				t.Fatal("incoherent parsed row selected", v.SBOMs, err)
			}
		})
	}
	for _, change := range []struct {
		name string
		edit func(*MemoryUnitOfWorkSnapshot)
	}{
		{"negative count", func(s *MemoryUnitOfWorkSnapshot) { d := s.SBOMs["sbom"]; d.ComponentCount = -1; s.SBOMs[d.ID] = d }},
		{"negative summary", func(s *MemoryUnitOfWorkSnapshot) {
			d := s.VulnerabilityScans["scan"]
			d.Summary = map[string]int{"critical": -1}
			s.VulnerabilityScans[d.ID] = d
		}},
		{"operation count", func(s *MemoryUnitOfWorkSnapshot) {
			c := s.OpenAPIContracts["contract"]
			c.Operations = make([]domain.OpenAPIOperation, 4097)
			s.OpenAPIContracts[c.ID] = c
		}},
		{"operation text", func(s *MemoryUnitOfWorkSnapshot) {
			c := s.OpenAPIContracts["contract"]
			c.Operations[0].Path = strings.Repeat("x", packageapp.MaxCustomerPackageManifestBytes+1)
			s.OpenAPIContracts[c.ID] = c
		}},
		{"required field count", func(s *MemoryUnitOfWorkSnapshot) {
			c := s.OpenAPIContracts["contract"]
			c.Operations[0].RequiredRequestFields = make([]string, 4097)
			s.OpenAPIContracts[c.ID] = c
		}},
		{"diff text", func(s *MemoryUnitOfWorkSnapshot) {
			d := s.ContractDiffs["diff"]
			d.BreakingChanges = []string{strings.Repeat("x", packageapp.MaxCustomerPackageManifestBytes+1)}
			s.ContractDiffs[d.ID] = d
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			tx := memoryCustomerEvidenceFixture(t)
			change.edit(&tx.state)
			budget := &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
			v, err := readMemoryCustomerPackageEvidence(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", budget)
			if !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, memoryCustomerPackageEvidence{}) || budget.remainingBytes != packageapp.MaxCustomerPackageManifestBytes {
				t.Fatal("invalid metadata returned partial section or spent budget", err)
			}
		})
	}
	tx := memoryCustomerEvidenceFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := readMemoryCustomerPackageEvidence(ctx, &tx.state, "tenant", "tenant-product", "tenant-release", &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, memoryCustomerPackageEvidence{}) {
		t.Fatal("cancelled evidence section returned", err)
	}
}
