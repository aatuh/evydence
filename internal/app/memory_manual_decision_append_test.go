package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type memoryManualDecisionStorage interface {
	riskapp.VulnerabilityDecisionReader
	AppendVulnerabilityDecision(context.Context, riskdomain.VulnerabilityDecision, []riskapp.ActiveDecisionHead) error
}

func TestMemoryManualDecisionAppendChecksHeadCeilingAndCanonicalPredecessor(t *testing.T) {
	for _, count := range []int{0, 128, 129} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			tx, storage, value, _ := memoryManualDecisionAppendFixture(t)
			old := tx.state.Decisions["head"]
			tx.state.Decisions = map[string]domain.VulnerabilityDecision{}
			for i := range count {
				copy := old
				copy.ID = fmt.Sprintf("head-%03d", i)
				tx.state.Decisions[copy.ID] = copy
			}
			heads, err := storage.ReadActiveDecisionHeads(t.Context(), "tenant", "finding", 129)
			if err != nil {
				t.Fatal(err)
			}
			value.Supersedes = ""
			if count > 0 {
				value.Supersedes = "head-000"
			}
			before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
			if err != nil {
				t.Fatal(err)
			}
			err = storage.AppendVulnerabilityDecision(t.Context(), value, heads)
			if count == 129 {
				if err == nil || !reflect.DeepEqual(before, tx.state) {
					t.Fatal("manual append dropped overflow head or partially mutated history", err)
				}
				return
			}
			if err != nil || len(tx.state.Decisions) != count+1 {
				t.Fatal("manual append rejected valid head boundary", count, err)
			}
			for id, original := range before.Decisions {
				original.SupersededBy = value.ID
				if !reflect.DeepEqual(original, tx.state.Decisions[id]) {
					t.Fatal("manual append rewrote prior core at head limit", id)
				}
			}
		})
	}
}

func memoryManualDecisionAppendFixture(t *testing.T) (*memoryUnitOfWork, memoryManualDecisionStorage, riskdomain.VulnerabilityDecision, []riskapp.ActiveDecisionHead) {
	t.Helper()
	tx, reader := memoryManualDecisionSupportFixture(t)
	storage, ok := tx.Repositories().Decisions.(memoryManualDecisionStorage)
	if !ok {
		t.Fatal("memory Decision repository lacks checked native append")
	}
	f, err := reader.ReadDecisionFinding(t.Context(), "tenant", "finding")
	if err != nil {
		t.Fatal(err)
	}
	heads, err := reader.ReadActiveDecisionHeads(t.Context(), "tenant", "finding", 129)
	if err != nil {
		t.Fatal(err)
	}
	status, _ := riskdomain.ParseDecisionStatus("fixed")
	v := riskdomain.VulnerabilityDecision{ID: "new-decision", TenantID: "tenant", FindingID: f.ID, ScanID: f.ScanID, ReleaseID: f.ReleaseID, Vulnerability: f.Vulnerability, Component: f.Component, SBOMID: f.SBOMID, SBOMComponentPURL: f.SBOMComponentPURL, SBOMComponentName: f.SBOMComponentName, Status: status, Justification: "reviewed", ImpactStatement: "patched", ActionStatement: "ship", InternalNotes: "private new review", Source: "api", EvidenceIDs: []string{"sbom-source"}, SupportingRefs: []riskdomain.SupportingReference{{Type: "approval", ID: "approval"}}, VEXDocumentID: "vex", Supersedes: "head", ApprovedBy: "actor", SchemaVersion: riskdomain.VulnerabilityDecisionVersion, CreatedAt: fixedNow()}
	return tx, storage, v, heads
}

func TestMemoryManualDecisionAppendPreservesHistoricalCoreAndDetachesNewFields(t *testing.T) {
	tx, storage, value, heads := memoryManualDecisionAppendFixture(t)
	old := tx.state.Decisions["head"]
	if err := storage.AppendVulnerabilityDecision(t.Context(), value, heads); err != nil {
		t.Fatal(err)
	}
	// Snapshot.Decisions stores the projected DTO view, not SQL base rows.
	// Only its derived superseded_by value changes; historical core is intact.
	old.SupersededBy = value.ID
	if !reflect.DeepEqual(tx.state.Decisions[old.ID], old) || !reflect.DeepEqual(tx.state.Decisions[value.ID], domain.VulnerabilityDecisionFromContextModel(value)) {
		t.Fatal("manual append rewrote historical core or lost new decision fields")
	}
	value.EvidenceIDs[0], value.SupportingRefs[0].ID = "changed", "changed"
	if tx.state.Decisions[value.ID].EvidenceIDs[0] != "sbom-source" || tx.state.Decisions[value.ID].SupportingRefs[0].ID != "approval" {
		t.Fatal("manual append shared mutable caller fields")
	}
	current, err := storage.ReadActiveDecisionHeads(t.Context(), "tenant", "finding", 129)
	if err != nil || len(current) != 1 || current[0].ID != value.ID || current[0].Status.String() != "fixed" {
		t.Fatal("manual append did not project exactly one new active head", err)
	}
}

func TestMemoryManualDecisionAppendRejectsStaleHeadsAndBadReferencesWithoutMutation(t *testing.T) {
	for _, kind := range []string{"stale-heads", "wrong-head", "duplicate-head", "collision", "scan", "release", "vulnerability", "component", "sbom", "evidence", "vex", "support", "supersedes", "oversized-notes"} {
		t.Run(kind, func(t *testing.T) {
			tx, storage, value, heads := memoryManualDecisionAppendFixture(t)
			switch kind {
			case "stale-heads":
				heads = nil
			case "wrong-head":
				heads[0].Status, _ = riskdomain.ParseDecisionStatus("not_affected")
			case "duplicate-head":
				heads = append(heads, heads[0])
			case "collision":
				tx.state.Decisions[value.ID] = domain.VulnerabilityDecision{ID: value.ID, TenantID: "foreign"}
			case "scan":
				value.ScanID = "other-scan"
			case "release":
				value.ReleaseID = "other-release"
			case "vulnerability":
				value.Vulnerability = "CVE-other"
			case "component":
				value.Component = "other"
			case "sbom":
				value.SBOMID = "other"
			case "evidence":
				value.EvidenceIDs = []string{"missing"}
			case "vex":
				value.VEXDocumentID = "missing"
			case "support":
				value.SupportingRefs = []riskdomain.SupportingReference{{Type: "approval", ID: "missing"}}
			case "supersedes":
				value.Supersedes = "other-head"
			case "oversized-notes":
				value.InternalNotes = string(make([]byte, 8193))
			}
			before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
			if err != nil {
				t.Fatal(err)
			}
			if err := storage.AppendVulnerabilityDecision(t.Context(), value, heads); err == nil || !reflect.DeepEqual(before, tx.state) {
				t.Fatal("rejected manual append mutated projected history", kind, err)
			}
		})
	}
}

func TestMemoryManualDecisionAppendRejectsCanceledAndClosedTransactions(t *testing.T) {
	tx, storage, value, heads := memoryManualDecisionAppendFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := storage.AppendVulnerabilityDecision(ctx, value, heads); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(before, tx.state) {
		t.Fatal("canceled manual append published effects", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := storage.AppendVulnerabilityDecision(t.Context(), value, heads); !errors.Is(err, ErrConflict) {
		t.Fatal("manual append accepted a closed transaction", err)
	}
}
