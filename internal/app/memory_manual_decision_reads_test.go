package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func memoryManualDecisionReadFixture(t *testing.T) (*memoryUnitOfWork, riskapp.VulnerabilityDecisionReader) {
	t.Helper()
	tx, _ := memoryParsedPointFixture(t)
	reader, ok := tx.Repositories().Decisions.(riskapp.VulnerabilityDecisionReader)
	if !ok {
		t.Fatal("memory Decision repository lacks focused manual-decision reads")
	}
	tx.state.Evidence["vex-source"] = domain.EvidenceItem{ID: "vex-source", TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", Type: "vex", Metadata: map[string]any{"private": strings.Repeat("private", 100000)}}
	tx.state.VEXDocuments["vex"] = domain.VEXDocument{ID: "vex", TenantID: "tenant", EvidenceID: "vex-source", ReleaseID: "tenant-release", StatusSummary: map[string]int{"private": 1}}
	tx.state.Decisions = map[string]domain.VulnerabilityDecision{"head": {ID: "head", TenantID: "tenant", FindingID: "finding", ScanID: "scan", ReleaseID: "tenant-release", Status: "affected", InternalNotes: strings.Repeat("private", 100000)}}
	return tx, reader
}

func TestMemoryManualDecisionReadersReturnCurrentCoordinatesWithoutPrivateDocuments(t *testing.T) {
	tx, reader := memoryManualDecisionReadFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	finding, err := reader.ReadDecisionFinding(t.Context(), "tenant", "finding")
	want := riskapp.FindingReference{ID: "finding", TenantID: "tenant", ScanID: "scan", ProductID: "tenant-product", ReleaseID: "tenant-release", Vulnerability: "CVE-fixture", Component: "api", Severity: "high", State: "open", SBOMID: "sbom", SBOMComponentPURL: "pkg:generic/api@1", SBOMComponentName: "api"}
	if err != nil || finding != want {
		t.Fatal("manual finding reader lost current source, parent or SBOM coordinates", finding, err)
	}
	evidence, err := reader.ReadDecisionEvidence(t.Context(), "tenant", "sbom-source")
	if err != nil || evidence != (riskapp.DecisionEvidenceReference{ID: "sbom-source", TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release"}) {
		t.Fatal("manual evidence reader lost owned coordinates", evidence, err)
	}
	vex, err := reader.ReadDecisionVEX(t.Context(), "tenant", "vex")
	if err != nil || vex != (riskapp.DecisionVEXReference{ID: "vex", TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", EvidenceID: "vex-source"}) {
		t.Fatal("manual VEX reader lost owned source coordinates", vex, err)
	}
	heads, err := reader.ReadActiveDecisionHeads(t.Context(), "tenant", "finding", 129)
	status, _ := riskdomain.ParseDecisionStatus("affected")
	if err != nil || !reflect.DeepEqual(heads, []riskapp.ActiveDecisionHead{{ID: "head", TenantID: "tenant", FindingID: "finding", ScanID: "scan", ReleaseID: "tenant-release", Status: status}}) {
		t.Fatal("manual head reader lost minimal current identity", heads, err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("manual reference reads modified repository data")
	}
}

func TestMemoryManualDecisionFindingRejectsBrokenAndAmbiguousSourcesAndBoundsSelectedText(t *testing.T) {
	tx, reader := memoryManualDecisionReadFixture(t)
	scan := tx.state.VulnerabilityScans["scan"]
	copy := scan
	copy.ID = "another-scan"
	tx.state.VulnerabilityScans[copy.ID] = copy
	if v, err := reader.ReadDecisionFinding(t.Context(), "tenant", "finding"); !errors.Is(err, ErrConflict) || v != (riskapp.FindingReference{}) {
		t.Fatal("manual reader accepted an ambiguous owned finding", err)
	}
	delete(tx.state.VulnerabilityScans, copy.ID)
	scan.Findings[0].Vulnerability = strings.Repeat("x", 1025)
	tx.state.VulnerabilityScans[scan.ID] = scan
	if v, err := reader.ReadDecisionFinding(t.Context(), "tenant", "finding"); !errors.Is(err, ErrValidation) || v != (riskapp.FindingReference{}) {
		t.Fatal("manual reader returned oversized selected finding text", err)
	}
	source := tx.state.Evidence[scan.EvidenceID]
	source.TenantID = "foreign"
	tx.state.Evidence[source.ID] = source
	if _, err := reader.ReadDecisionFinding(t.Context(), "tenant", "finding"); !errors.Is(err, ErrNotFound) {
		t.Fatal("manual reader accepted a foreign source", err)
	}
}

func TestMemoryManualDecisionSBOMSelectionPrioritizesPURLAndStableChronology(t *testing.T) {
	tx, reader := memoryManualDecisionReadFixture(t)
	scan := tx.state.VulnerabilityScans["scan"]
	scan.Findings[0].Component = "pkg:generic/api@1"
	tx.state.VulnerabilityScans[scan.ID] = scan
	old := tx.state.SBOMs["sbom"]
	old.ID, old.CreatedAt = "a-old-name", old.CreatedAt.AddDate(-1, 0, 0)
	old.Components = []domain.SBOMComponent{{Name: "pkg:generic/api@1", PURL: "other"}}
	tx.state.SBOMs[old.ID] = old
	if v, err := reader.ReadDecisionFinding(t.Context(), "tenant", "finding"); err != nil || v.SBOMID != "sbom" || v.SBOMComponentPURL != "pkg:generic/api@1" {
		t.Fatal("manual SBOM selection preferred older name over PURL", v, err)
	}
	old.Components = []domain.SBOMComponent{{Name: "old match", PURL: "pkg:generic/api@1"}}
	tx.state.SBOMs[old.ID] = old
	if v, err := reader.ReadDecisionFinding(t.Context(), "tenant", "finding"); err != nil || v.SBOMID != old.ID || v.SBOMComponentName != "old match" {
		t.Fatal("manual SBOM selection lost stable chronology", v, err)
	}
	old.Components[0].Name = strings.Repeat("n", 65537)
	tx.state.SBOMs[old.ID] = old
	if _, err := reader.ReadDecisionFinding(t.Context(), "tenant", "finding"); !errors.Is(err, ErrValidation) {
		t.Fatal("manual SBOM selection returned oversized selected metadata", err)
	}
}

func TestMemoryManualDecisionHeadsBoundOnlyCurrentIdentityAndRespectRequestedWindow(t *testing.T) {
	tx, reader := memoryManualDecisionReadFixture(t)
	d := tx.state.Decisions["head"]
	tx.state.Decisions = map[string]domain.VulnerabilityDecision{}
	for i := range 130 {
		v := d
		v.ID = fmt.Sprintf("head-%03d", i)
		tx.state.Decisions[v.ID] = v
	}
	v := d
	v.ID, v.SupersededBy, v.Status = "a-historical", "head-000", "invalid"
	tx.state.Decisions[v.ID] = v
	if heads, err := reader.ReadActiveDecisionHeads(t.Context(), "tenant", "finding", 129); err != nil || len(heads) != 129 || heads[0].ID != "head-000" || heads[128].ID != "head-128" {
		t.Fatal("manual head reader lost overflow sentinel or selected history", err)
	}
	v = tx.state.Decisions["head-129"]
	v.Status = "invalid"
	tx.state.Decisions[v.ID] = v
	if heads, err := reader.ReadActiveDecisionHeads(t.Context(), "tenant", "finding", 1); err != nil || len(heads) != 1 || heads[0].ID != "head-000" {
		t.Fatal("manual reader inspected heads outside requested window", err)
	}
	v = tx.state.Decisions["head-000"]
	v.Status = "invalid"
	tx.state.Decisions[v.ID] = v
	if heads, err := reader.ReadActiveDecisionHeads(t.Context(), "tenant", "finding", 1); !errors.Is(err, ErrConflict) || heads != nil {
		t.Fatal("manual reader accepted malformed selected head status", err)
	}
	for _, limit := range []int{0, 130} {
		if _, err := reader.ReadActiveDecisionHeads(t.Context(), "tenant", "finding", limit); !errors.Is(err, ErrValidation) {
			t.Fatal("manual reader accepted invalid head limit", err)
		}
	}
}

func TestMemoryManualDecisionReferenceReadersRejectForeignOwnershipAndInvalidContexts(t *testing.T) {
	tx, reader := memoryManualDecisionReadFixture(t)
	for _, read := range []func(context.Context, string) error{
		func(ctx context.Context, tenant string) error {
			_, err := reader.ReadDecisionFinding(ctx, tenant, "finding")
			return err
		},
		func(ctx context.Context, tenant string) error {
			_, err := reader.ReadDecisionEvidence(ctx, tenant, "sbom-source")
			return err
		},
		func(ctx context.Context, tenant string) error {
			_, err := reader.ReadDecisionVEX(ctx, tenant, "vex")
			return err
		},
	} {
		if err := read(t.Context(), "foreign"); !errors.Is(err, ErrNotFound) {
			t.Fatal("manual reader accepted foreign ownership", err)
		}
		var absent context.Context
		if err := read(absent, "tenant"); !errors.Is(err, ErrValidation) {
			t.Fatal("manual reader accepted nil context", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := read(ctx, "tenant"); !errors.Is(err, context.Canceled) {
			t.Fatal("manual reader ignored cancellation", err)
		}
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadDecisionEvidence(t.Context(), "tenant", "sbom-source"); !errors.Is(err, ErrConflict) {
		t.Fatal("manual reader used a closed transaction", err)
	}
}

func TestMemoryManualDecisionVEXReaderChecksSourceParentAgreementWithoutDocumentParsing(t *testing.T) {
	tx, reader := memoryManualDecisionReadFixture(t)
	v := tx.state.VEXDocuments["vex"]
	v.StatusSummary = nil
	v.Author = strings.Repeat("private", 200000)
	tx.state.VEXDocuments[v.ID] = v
	if _, err := reader.ReadDecisionVEX(t.Context(), "tenant", "vex"); err != nil {
		t.Fatal("manual VEX coordinate reader inspected private document metadata", err)
	}
	v.ArtifactID = "missing"
	tx.state.VEXDocuments[v.ID] = v
	if _, err := reader.ReadDecisionVEX(t.Context(), "tenant", "vex"); !errors.Is(err, ErrNotFound) {
		t.Fatal("manual VEX coordinates accepted missing artifact parent", err)
	}
	v.ArtifactID, v.ReleaseID = "", "another-release"
	tx.state.VEXDocuments[v.ID] = v
	if _, err := reader.ReadDecisionVEX(t.Context(), "tenant", "vex"); !errors.Is(err, ErrNotFound) {
		t.Fatal("manual VEX coordinates accepted contradictory source release", err)
	}
	v.ReleaseID, v.EvidenceID = "tenant-release", strings.Repeat("x", 1025)
	tx.state.VEXDocuments[v.ID] = v
	if _, err := reader.ReadDecisionVEX(t.Context(), "tenant", "vex"); !errors.Is(err, ErrValidation) {
		t.Fatal("manual VEX reader did not bound selected source identity", err)
	}
}
