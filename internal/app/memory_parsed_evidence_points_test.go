package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

type memoryParsedPointReader interface {
	evidencequery.SBOMPointReader
	evidencequery.VulnerabilityScanPointReader
	evidencequery.OpenAPIContractPointReader
}

func memoryParsedPointFixture(t *testing.T) (*memoryUnitOfWork, memoryParsedPointReader) {
	t.Helper()
	tx, _ := memoryReadinessQueryFixture(t)
	reader, ok := tx.Repositories().Evidence.(memoryParsedPointReader)
	if !ok {
		t.Fatal("memory Evidence repository lacks native parsed-evidence point readers")
	}
	for _, kind := range []string{"sbom", "vulnerability_scan", "openapi_contract"} {
		e := domain.EvidenceItem{ID: kind + "-source", TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", Type: kind, Metadata: map[string]any{"private": strings.Repeat("private", 10000)}}
		if kind == "sbom" {
			e.SubjectRefs = []domain.SubjectRef{{Type: "artifact", ID: "artifact"}, {Type: "artifact", ID: "artifact"}}
		}
		tx.state.Evidence[e.ID] = e
	}
	tx.state.SBOMs["sbom"] = domain.SBOM{ID: "sbom", TenantID: "tenant", EvidenceID: "sbom-source", ReleaseID: "tenant-release", ArtifactID: "artifact", Format: "CycloneDX", SpecVersion: "1.6", ComponentCount: 1, Components: []domain.SBOMComponent{{Identity: "component-1", Name: "api", Version: "1", PURL: "pkg:generic/api@1"}}, CreatedAt: fixedNow()}
	tx.state.VulnerabilityScans["scan"] = domain.VulnerabilityScan{ID: "scan", TenantID: "tenant", EvidenceID: "vulnerability_scan-source", ReleaseID: "tenant-release", Scanner: "generic", Adapter: "generic", AdapterVersion: "scanner.v1", SourceSchema: "generic.v1", TargetRef: "pkg:generic/api@1", Summary: map[string]int{"high": 1}, Findings: []domain.VulnerabilityFinding{{ID: "finding", Vulnerability: "CVE-fixture", Component: "api", Severity: "high", State: "open", SeveritySource: "scanner", FixVersion: "2", Identity: domain.VulnerabilityIdentity{CVE: "CVE-fixture", GHSA: "GHSA-fixture", OSV: "OSV-fixture", VendorAdvisory: "vendor-fixture", PURL: "pkg:generic/api@1", CPE: "cpe-fixture"}}}, CreatedAt: fixedNow()}
	tx.state.OpenAPIContracts["contract"] = domain.OpenAPIContract{ID: "contract", TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", Version: "1", Hash: "sha256:" + strings.Repeat("a", 64), PathCount: 1, EvidenceID: "openapi_contract-source", Operations: []domain.OpenAPIOperation{{Path: "/items", Method: "POST", OperationID: "createItem", Deprecated: true, RequestBodyRequired: true, RequiredRequestFields: []string{"name"}, ResponseStatuses: []string{"201", "400"}}}, CreatedAt: fixedNow()}
	return tx, reader
}

func TestMemoryParsedPointsReturnCompleteDetachedCurrentMetadata(t *testing.T) {
	tx, reader := memoryParsedPointFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	sbom, err := reader.GetSBOMPoint(t.Context(), "tenant", " sbom ")
	wantSBOM := evidencequery.SBOMPoint{ProductID: "tenant-product", SBOM: evidencedomain.SBOM{ID: "sbom", TenantID: "tenant", EvidenceID: "sbom-source", ReleaseID: "tenant-release", ArtifactID: "artifact", Format: "CycloneDX", SpecVersion: "1.6", ComponentCount: 1, Components: []evidencedomain.SBOMComponent{{Identity: "component-1", Name: "api", Version: "1", PURL: "pkg:generic/api@1"}}, CreatedAt: fixedNow()}}
	if err != nil || !reflect.DeepEqual(sbom, wantSBOM) {
		t.Fatal("SBOM point lost recorded metadata or parent", sbom, err)
	}
	scan, err := reader.GetVulnerabilityScanPoint(t.Context(), "tenant", "scan")
	wantScan := evidencequery.VulnerabilityScanPoint{ProductID: "tenant-product", Scan: evidencedomain.VulnerabilityScan{ID: "scan", TenantID: "tenant", EvidenceID: "vulnerability_scan-source", ReleaseID: "tenant-release", Scanner: "generic", Adapter: "generic", AdapterVersion: "scanner.v1", SourceSchema: "generic.v1", TargetRef: "pkg:generic/api@1", Summary: map[string]int{"high": 1}, Findings: []evidencedomain.VulnerabilityFinding{{ID: "finding", Vulnerability: "CVE-fixture", Component: "api", Severity: "high", State: "open", SeveritySource: "scanner", FixVersion: "2", Identity: evidencedomain.VulnerabilityIdentity{CVE: "CVE-fixture", GHSA: "GHSA-fixture", OSV: "OSV-fixture", VendorAdvisory: "vendor-fixture", PURL: "pkg:generic/api@1", CPE: "cpe-fixture"}}}, CreatedAt: fixedNow()}}
	if err != nil || !reflect.DeepEqual(scan, wantScan) {
		t.Fatal("scan point lost recorded identity or adapter metadata", scan, err)
	}
	contract, err := reader.GetOpenAPIContractPoint(t.Context(), "tenant", "contract")
	wantContract := evidencequery.OpenAPIContractPoint{Contract: evidencedomain.OpenAPIContract{ID: "contract", TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", Version: "1", Hash: "sha256:" + strings.Repeat("a", 64), PathCount: 1, EvidenceID: "openapi_contract-source", Operations: []evidencedomain.OpenAPIOperation{{Path: "/items", Method: "POST", OperationID: "createItem", Deprecated: true, RequestBodyRequired: true, RequiredRequestFields: []string{"name"}, ResponseStatuses: []string{"201", "400"}}}, CreatedAt: fixedNow()}}
	if err != nil || !reflect.DeepEqual(contract, wantContract) {
		t.Fatal("contract point lost recorded operation fields", contract, err)
	}
	sbom.SBOM.Components[0].Name = "changed"
	scan.Scan.Summary["high"], scan.Scan.Findings[0].Identity.CVE = -1, "changed"
	contract.Contract.Operations[0].RequiredRequestFields[0], contract.Contract.Operations[0].ResponseStatuses[0] = "changed", "changed"
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("parsed point reads or caller mutations changed current rows")
	}
}

func memoryParsedPointCases(r memoryParsedPointReader) []struct {
	kind, id string
	zero     any
	read     func(context.Context, string, string) (any, error)
} {
	return []struct {
		kind, id string
		zero     any
		read     func(context.Context, string, string) (any, error)
	}{
		{"sbom", "sbom", evidencequery.SBOMPoint{}, func(ctx context.Context, tenant, id string) (any, error) { return r.GetSBOMPoint(ctx, tenant, id) }},
		{"vulnerability_scan", "scan", evidencequery.VulnerabilityScanPoint{}, func(ctx context.Context, tenant, id string) (any, error) {
			return r.GetVulnerabilityScanPoint(ctx, tenant, id)
		}},
		{"openapi_contract", "contract", evidencequery.OpenAPIContractPoint{}, func(ctx context.Context, tenant, id string) (any, error) {
			return r.GetOpenAPIContractPoint(ctx, tenant, id)
		}},
	}
}

func TestMemoryParsedPointsRejectForeignOrIncoherentParentsAndCleanUpFailures(t *testing.T) {
	for _, change := range []string{"foreign-source", "wrong-kind", "wrong-release", "foreign-product", "foreign-build"} {
		t.Run(change, func(t *testing.T) {
			tx, reader := memoryParsedPointFixture(t)
			for _, point := range memoryParsedPointCases(reader) {
				source := tx.state.Evidence[point.kind+"-source"]
				switch change {
				case "foreign-source":
					source.TenantID = "foreign"
				case "wrong-kind":
					source.Type = "manual"
				case "wrong-release":
					source.ReleaseID = "foreign-release"
				case "foreign-product":
					source.ProductID = "foreign-product"
				case "foreign-build":
					source.BuildID = "missing-build"
				}
				tx.state.Evidence[source.ID] = source
				if value, err := point.read(t.Context(), "tenant", point.id); !errors.Is(err, evidencequery.ErrNotFound) || !reflect.DeepEqual(value, point.zero) {
					t.Fatal("incoherent parsed point exposed metadata", point.kind, value, err)
				}
			}
		})
	}
	tx, reader := memoryParsedPointFixture(t)
	for _, point := range memoryParsedPointCases(reader) {
		for _, coordinates := range [][2]string{{"foreign", point.id}, {"tenant", "missing"}, {"tenant", ""}} {
			if value, err := point.read(t.Context(), coordinates[0], coordinates[1]); !errors.Is(err, evidencequery.ErrNotFound) || !reflect.DeepEqual(value, point.zero) {
				t.Fatal("foreign or missing parsed point exposed data", point.kind, value, err)
			}
		}
		var absent context.Context
		if _, err := point.read(absent, "tenant", point.id); !errors.Is(err, evidencequery.ErrValidation) {
			t.Fatal("nil parsed point context accepted", point.kind, err)
		}
		base, cancel := context.WithCancel(t.Context())
		during := &memoryBundleCancelAfterSelection{Context: base, cancel: cancel}
		value, err := point.read(during, "tenant", point.id)
		cancel()
		if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(value, point.zero) {
			t.Fatal("post-selection cancellation returned parsed data", point.kind, value, err)
		}
		if _, err := point.read(t.Context(), "tenant", point.id); err != nil {
			t.Fatal("canceled parsed read retained transaction lock", point.kind, err)
		}
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, point := range memoryParsedPointCases(reader) {
		if value, err := point.read(t.Context(), "tenant", point.id); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(value, point.zero) {
			t.Fatal("closed transaction returned parsed data", point.kind, value, err)
		}
	}
}

func TestMemoryParsedPointsEnforceArtifactBindingsAndProjectionCompletion(t *testing.T) {
	for _, mode := range []string{"foreign-artifact", "different-artifact", "extra-artifact"} {
		t.Run(mode, func(t *testing.T) {
			tx, reader := memoryParsedPointFixture(t)
			e := tx.state.Evidence["sbom-source"]
			switch mode {
			case "foreign-artifact":
				a := tx.state.Artifacts["artifact"]
				a.TenantID = "foreign"
				tx.state.Artifacts[a.ID] = a
			case "different-artifact":
				e.SubjectRefs = []domain.SubjectRef{{Type: "artifact", ID: "other"}}
			case "extra-artifact":
				e.SubjectRefs = append(e.SubjectRefs, domain.SubjectRef{Type: "artifact", ID: "other"})
			}
			tx.state.Evidence[e.ID] = e
			if value, err := reader.GetSBOMPoint(t.Context(), "tenant", "sbom"); !errors.Is(err, evidencequery.ErrNotFound) || !reflect.DeepEqual(value, evidencequery.SBOMPoint{}) {
				t.Fatal("SBOM point accepted an incoherent artifact source", value, err)
			}
		})
	}
	tx, reader := memoryParsedPointFixture(t)
	e := tx.state.Evidence["vulnerability_scan-source"]
	e.SubjectRefs = []domain.SubjectRef{{Type: "artifact", ID: "artifact"}}
	tx.state.Evidence[e.ID] = e
	if value, err := reader.GetVulnerabilityScanPoint(t.Context(), "tenant", "scan"); !errors.Is(err, evidencequery.ErrNotFound) || !reflect.DeepEqual(value, evidencequery.VulnerabilityScanPoint{}) {
		t.Fatal("scan source assigned unsupported artifact authority", value, err)
	}
	e.SubjectRefs = nil
	tx.state.Evidence[e.ID] = e
	for _, pending := range []bool{false, true} {
		v := tx.state.VulnerabilityScans["scan"]
		v.Findings, v.Summary = []domain.VulnerabilityFinding{}, map[string]int{}
		if pending {
			v.Findings, v.Summary = nil, nil
			v.Scanner, v.Adapter, v.AdapterVersion, v.SourceSchema, v.TargetRef = "", "", "", "", ""
		}
		tx.state.VulnerabilityScans[v.ID] = v
		value, err := reader.GetVulnerabilityScanPoint(t.Context(), "tenant", v.ID)
		if err != nil || len(value.Scan.Findings) != 0 || (value.Scan.Findings == nil) != pending || (value.Scan.Summary == nil) != pending || (value.Scan.Scanner == "") != pending {
			t.Fatal("parsed point collapsed pending and completed-empty scans", value, err)
		}
	}
	c := tx.state.OpenAPIContracts["contract"]
	c.PathCount, c.Operations = 0, []domain.OpenAPIOperation{}
	tx.state.OpenAPIContracts[c.ID] = c
	if value, err := reader.GetOpenAPIContractPoint(t.Context(), "tenant", c.ID); err != nil || value.Contract.Operations == nil || len(value.Contract.Operations) != 0 {
		t.Fatal("completed empty contract projection rejected", value, err)
	}
	c.Operations = nil
	tx.state.OpenAPIContracts[c.ID] = c
	if value, err := reader.GetOpenAPIContractPoint(t.Context(), "tenant", c.ID); !errors.Is(err, evidencequery.ErrConflict) || !reflect.DeepEqual(value, evidencequery.OpenAPIContractPoint{}) {
		t.Fatal("unfinished contract returned plausible parsed metadata", value, err)
	}
}

func TestMemoryParsedPointsRejectOversizedSelectedJSONWithoutPartialData(t *testing.T) {
	const limit = 32 << 20
	if !memoryParsedJSONFits(strings.Repeat("x", limit-2)) || memoryParsedJSONFits(strings.Repeat("x", limit-1)) {
		t.Fatal("selected JSON budget lost its exact byte boundary")
	}
	tx, reader := memoryParsedPointFixture(t)
	scan := tx.state.VulnerabilityScans["scan"]
	scan.Findings[0].Vulnerability = strings.Repeat("x", limit)
	tx.state.VulnerabilityScans[scan.ID] = scan
	if value, err := reader.GetVulnerabilityScanPoint(t.Context(), "tenant", scan.ID); !errors.Is(err, evidencequery.ErrConflict) || !reflect.DeepEqual(value, evidencequery.VulnerabilityScanPoint{}) {
		t.Fatal("oversized scan returned truncated or partial metadata", err)
	}
	contract := tx.state.OpenAPIContracts["contract"]
	contract.Operations[0].Path = strings.Repeat("x", limit)
	tx.state.OpenAPIContracts[contract.ID] = contract
	if value, err := reader.GetOpenAPIContractPoint(t.Context(), "tenant", contract.ID); !errors.Is(err, evidencequery.ErrConflict) || !reflect.DeepEqual(value, evidencequery.OpenAPIContractPoint{}) {
		t.Fatal("oversized contract returned truncated or partial metadata", err)
	}
}
