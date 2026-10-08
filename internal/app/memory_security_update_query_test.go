package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func memorySecurityUpdateFixture(t *testing.T) (*memoryUnitOfWork, packagequery.SecurityUpdateReader) {
	t.Helper()
	tx, _ := memoryCRAVulnerabilityFixture(t)
	reader, ok := tx.Repositories().Packages.(packagequery.SecurityUpdateReader)
	if !ok {
		t.Fatal("memory package repository lacks native security-update snapshots")
	}
	at := fixedNow()
	tx.state.Incidents["incident"] = domain.Incident{ID: "incident", TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", Title: "Response", Severity: "high", Status: "closed", OpenedAt: at, ClosedAt: &at, SchemaVersion: "incident.v1", CreatedAt: at}
	tx.state.RemediationTasks["task"] = domain.RemediationTask{ID: "task", TenantID: "tenant", IncidentID: "incident", ReleaseID: "tenant-release", Title: "Patch", Owner: "security", Status: "open", DueAt: &at, EvidenceID: "tenant-evidence", SchemaVersion: "task.v1", CreatedAt: at}
	// Report-safe scan references must not inspect raw finding bodies.
	scan := tx.state.VulnerabilityScans["tenant-scan"]
	scan.Findings = nil
	tx.state.VulnerabilityScans[scan.ID] = scan
	return tx, reader
}

func TestMemorySecurityUpdateQueryPreservesCompleteCurrentPublicFactsAndDetachesMetadata(t *testing.T) {
	tx, reader := memorySecurityUpdateFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	value, err := reader.ReadSecurityUpdateSnapshot(t.Context(), "tenant", "tenant-product", "tenant-release")
	if err != nil || value.TenantID != "tenant" || value.ProductID != "tenant-product" || value.ReleaseID != "tenant-release" || !reflect.DeepEqual(value.ScanEvidenceIDs, []string{"tenant-evidence"}) || len(value.Decisions) != 1 || len(value.Incidents) != 1 || len(value.Tasks) != 1 || !reflect.DeepEqual(value.VEXEvidenceIDs, map[string]string{"vex": "vex-evidence"}) {
		t.Fatal("security-update snapshot lost complete current scoped records", value, err)
	}
	wantDecision := tx.state.Decisions["decision"]
	wantDecision.InternalNotes = ""
	if !reflect.DeepEqual(domain.VulnerabilityDecisionFromContextModel(value.Decisions[0]), wantDecision) || !reflect.DeepEqual(domain.IncidentFromContextModel(value.Incidents[0]), tx.state.Incidents["incident"]) || !reflect.DeepEqual(domain.RemediationTask(value.Tasks[0]), tx.state.RemediationTasks["task"]) {
		t.Fatal("security-update snapshot lost recorded metadata or exposed private notes")
	}
	value.ScanEvidenceIDs[0], value.Decisions[0].EvidenceIDs[0], value.Decisions[0].SupportingRefs[0].ID, value.VEXEvidenceIDs["vex"] = "changed", "changed", "changed", "changed"
	*value.Decisions[0].ReviewedAt, *value.Decisions[0].ReviewDueAt, *value.Incidents[0].ClosedAt, *value.Tasks[0].DueAt = fixedNow().AddDate(1, 0, 0), fixedNow().AddDate(1, 0, 0), fixedNow().AddDate(1, 0, 0), fixedNow().AddDate(1, 0, 0)
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("security-update read or result mutation changed current repository state")
	}
}

func TestMemorySecurityUpdateQueryFiltersOtherReleasesHistoryAndTaskParents(t *testing.T) {
	tx, reader := memorySecurityUpdateFixture(t)
	tx.state.Products["other-product"] = domain.Product{ID: "other-product", TenantID: "tenant"}
	tx.state.Releases["other-release"] = domain.Release{ID: "other-release", TenantID: "tenant", ProductID: "other-product"}
	other := tx.state.Incidents["incident"]
	other.ID, other.ProductID, other.ReleaseID, other.Status = "other-incident", "other-product", "other-release", "invalid"
	tx.state.Incidents[other.ID] = other
	for _, tc := range []struct{ id, incident, release string }{
		{"incident-only", "incident", ""}, {"release-only", "", "tenant-release"},
		{"foreign-incident", "other-incident", "tenant-release"}, {"mismatched-release", "incident", "other-release"}, {"unbound", "", ""},
	} {
		task := tx.state.RemediationTasks["task"]
		task.ID, task.IncidentID, task.ReleaseID = tc.id, tc.incident, tc.release
		tx.state.RemediationTasks[task.ID] = task
	}
	d := tx.state.Decisions["decision"]
	d.ID, d.Status, d.InternalNotes = "affected", "affected", strings.Repeat("private", 10000)
	tx.state.Decisions[d.ID] = d
	value, err := reader.ReadSecurityUpdateSnapshot(t.Context(), "tenant", "tenant-product", "tenant-release")
	if err != nil || len(value.Decisions) != 1 || len(value.Incidents) != 1 || len(value.Tasks) != 3 || value.Tasks[0].ID != "incident-only" || value.Tasks[1].ID != "release-only" || value.Tasks[2].ID != "task" {
		t.Fatal("security-update snapshot admitted history, foreign parents or unrelated tasks", value, err)
	}
}

func TestMemorySecurityUpdateQueryRejectsInvalidSelectedEvidenceAndRecords(t *testing.T) {
	for _, change := range []string{"scan-evidence", "decision-key", "decision-evidence", "supporting-evidence", "vex-release", "vex-evidence", "incident-status", "task-evidence", "evidence-product", "evidence-project", "evidence-release"} {
		t.Run(change, func(t *testing.T) {
			tx, reader := memorySecurityUpdateFixture(t)
			switch change {
			case "scan-evidence":
				v := tx.state.VulnerabilityScans["tenant-scan"]
				v.EvidenceID = "foreign-evidence"
				tx.state.VulnerabilityScans[v.ID] = v
			case "decision-key", "decision-evidence", "supporting-evidence":
				v := tx.state.Decisions["decision"]
				switch change {
				case "decision-key":
					v.ID = "mismatched"
				case "decision-evidence":
					v.EvidenceIDs = []string{"foreign-evidence"}
				case "supporting-evidence":
					v.SupportingRefs = []domain.SubjectRef{{Type: "evidence", ID: "foreign-evidence"}}
				}
				tx.state.Decisions["decision"] = v
			case "vex-release", "vex-evidence":
				v := tx.state.VEXDocuments["vex"]
				if change == "vex-release" {
					v.ReleaseID = "foreign-release"
				} else {
					v.EvidenceID = "foreign-evidence"
				}
				tx.state.VEXDocuments[v.ID] = v
			case "incident-status":
				v := tx.state.Incidents["incident"]
				v.Status = "invalid"
				tx.state.Incidents[v.ID] = v
			case "task-evidence":
				v := tx.state.RemediationTasks["task"]
				v.EvidenceID = "foreign-evidence"
				tx.state.RemediationTasks[v.ID] = v
			default:
				e := tx.state.Evidence["tenant-evidence"]
				switch change {
				case "evidence-product":
					e.ProductID = "foreign-product"
				case "evidence-project":
					e.ProjectID = "foreign-project"
				case "evidence-release":
					e.ReleaseID = "foreign-release"
				}
				tx.state.Evidence[e.ID] = e
			}
			value, err := reader.ReadSecurityUpdateSnapshot(t.Context(), "tenant", "tenant-product", "tenant-release")
			if !errors.Is(err, packagequery.ErrSecurityUpdateProjection) || !reflect.DeepEqual(value, packagequery.SecurityUpdateSnapshot{}) {
				t.Fatal("invalid selected security-update data returned a partial report", value, err)
			}
		})
	}
}

func TestMemorySecurityUpdateQueryPreservesCombinedRowAndEvidenceBudgets(t *testing.T) {
	for _, extra := range []int{0, 1} {
		t.Run(fmt.Sprintf("rows-%d", extra), func(t *testing.T) {
			tx, reader := memorySecurityUpdateFixture(t)
			v := tx.state.RemediationTasks["task"]
			for i := 0; i < packagequery.MaxSecurityUpdateEntries-4+extra; i++ {
				v.ID = fmt.Sprintf("extra-%04d", i)
				tx.state.RemediationTasks[v.ID] = v
			}
			value, err := reader.ReadSecurityUpdateSnapshot(t.Context(), "tenant", "tenant-product", "tenant-release")
			if extra == 0 {
				if err != nil || len(value.ScanEvidenceIDs)+len(value.Decisions)+len(value.Incidents)+len(value.Tasks) != packagequery.MaxSecurityUpdateEntries {
					t.Fatal("exact shared security-update row budget rejected", err)
				}
			} else if !errors.Is(err, packagequery.ErrSecurityUpdateCapacity) || !reflect.DeepEqual(value, packagequery.SecurityUpdateSnapshot{}) {
				t.Fatal("overflow returned a truncated or partial security-update snapshot", value, err)
			}
		})
	}
	for _, extra := range []int{0, 1} {
		t.Run(fmt.Sprintf("evidence-%d", extra), func(t *testing.T) {
			tx, reader := memorySecurityUpdateFixture(t)
			d := tx.state.Decisions["decision"]
			for i := 0; i < packagequery.MaxSecurityUpdateEntries-2+extra; i++ {
				id := fmt.Sprintf("evidence-%04d", i)
				tx.state.Evidence[id] = domain.EvidenceItem{ID: id, TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release"}
				d.EvidenceIDs = append(d.EvidenceIDs, id)
			}
			tx.state.Decisions[d.ID] = d
			value, err := reader.ReadSecurityUpdateSnapshot(t.Context(), "tenant", "tenant-product", "tenant-release")
			if extra == 0 {
				if err != nil || len(value.Decisions[0].EvidenceIDs) != packagequery.MaxSecurityUpdateEntries-1 {
					t.Fatal("exact unique linked-evidence budget rejected", err)
				}
			} else if !errors.Is(err, packagequery.ErrSecurityUpdateCapacity) || !reflect.DeepEqual(value, packagequery.SecurityUpdateSnapshot{}) {
				t.Fatal("linked-evidence overflow returned partial data", value, err)
			}
		})
	}
}

func TestMemorySecurityUpdateQueryHonorsContextOwnedRootsAndClosedTransactions(t *testing.T) {
	tx, reader := memorySecurityUpdateFixture(t)
	for _, pair := range [][2]string{{"foreign-product", "foreign-release"}, {"tenant-product", "foreign-release"}, {"foreign-product", "tenant-release"}} {
		value, err := reader.ReadSecurityUpdateSnapshot(t.Context(), "tenant", pair[0], pair[1])
		if !errors.Is(err, packagequery.ErrSecurityUpdateNotFound) || !reflect.DeepEqual(value, packagequery.SecurityUpdateSnapshot{}) {
			t.Fatal("foreign or mismatched root exposed security-update records", value, err)
		}
	}
	var absent context.Context
	if _, err := reader.ReadSecurityUpdateSnapshot(absent, "tenant", "tenant-product", "tenant-release"); !errors.Is(err, packagequery.ErrSecurityUpdateValidation) {
		t.Fatal("nil context accepted", err)
	}
	base, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx := &memoryCRACancelDuringRead{Context: base, cancel: cancel}
	value, err := reader.ReadSecurityUpdateSnapshot(ctx, "tenant", "tenant-product", "tenant-release")
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(value, packagequery.SecurityUpdateSnapshot{}) {
		t.Fatal("mid-selection cancellation returned partial security-update records", value, err)
	}
	if _, err := reader.ReadSecurityUpdateSnapshot(t.Context(), "tenant", "tenant-product", "tenant-release"); err != nil {
		t.Fatal("canceled read retained the transaction lock", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if value, err := reader.ReadSecurityUpdateSnapshot(t.Context(), "tenant", "tenant-product", "tenant-release"); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(value, packagequery.SecurityUpdateSnapshot{}) {
		t.Fatal("closed transaction returned security-update records", value, err)
	}
}
