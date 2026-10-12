package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

type memoryReleaseSummaryReader interface {
	ReadReleaseSecuritySummarySnapshotAt(context.Context, string, string, time.Time) (riskquery.ReleaseSecuritySummarySnapshot, error)
}

func memoryReleaseSummaryFixture(t *testing.T) (*memoryUnitOfWork, memoryReleaseSummaryReader) {
	t.Helper()
	tx, _ := memoryReadinessQueryFixture(t)
	r, ok := tx.Repositories().Decisions.(memoryReleaseSummaryReader)
	if !ok {
		t.Fatal("memory risk repository lacks focused release-summary reader")
	}
	p := tx.state.Products["tenant-product"]
	p.Name, p.Slug = "Product", "product"
	tx.state.Products[p.ID] = p
	v := tx.state.Releases["tenant-release"]
	v.Version, v.State = "1", "draft"
	tx.state.Releases[v.ID] = v
	return tx, r
}

func TestMemoryReleaseSummaryQueryReturnsOwnedSafeGroupsFindingsAndCurrentGovernance(t *testing.T) {
	tx, r := memoryReleaseSummaryFixture(t)
	tx.state.Decisions["decision"] = domain.VulnerabilityDecision{ID: "decision", TenantID: "tenant", ReleaseID: "tenant-release", ScanID: "scan", FindingID: "finding", Vulnerability: "CVE-fixture", Component: "component", Status: "fixed", InternalNotes: strings.Repeat("private", 10000)}
	tx.state.Approvals["approval"] = domain.ApprovalRecord{ID: "approval", TenantID: "tenant", SubjectType: "release", SubjectID: "tenant-release", Decision: "approved", Reason: strings.Repeat("private", 10000)}
	tx.state.Exceptions["exception"] = domain.Exception{ID: "exception", TenantID: "tenant", ReleaseID: "tenant-release", FindingID: "finding", Owner: "Owner", Reason: "Review", ExpiresAt: fixedNow().Add(time.Hour)}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	v, err := r.ReadReleaseSecuritySummarySnapshotAt(t.Context(), "tenant", "tenant-release", fixedNow())
	if err != nil || v.TenantID != "tenant" || v.Product != (riskdomain.ReleaseSecurityProductSummary{ID: "tenant-product", Name: "Product", Slug: "product"}) || v.Release != (riskdomain.ReleaseSecurityReleaseSummary{ID: "tenant-release", Version: "1", State: "draft"}) || !reflect.DeepEqual(v.OpenFindingsBySeverity, map[string]int{"critical": 1, "high": 1}) || !reflect.DeepEqual(v.DecisionsByStatus, map[string]int{"fixed": 1}) || !reflect.DeepEqual(v.MissingRequiredDecisions, []riskdomain.ReleaseSecurityMissingDecision{{FindingID: "high", ScanID: "scan", Vulnerability: "CVE-high", Component: "component", Severity: "high", State: "open"}}) || v.ApprovalSummary.Total != 1 || v.ApprovalSummary.Approved != 1 || v.ExceptionSummary.Unapproved != 1 || v.Readiness.UnhandledCritical || !v.Readiness.UnhandledHigh {
		t.Fatal("release summary lost current complete safe projection", v, err)
	}
	if v.Counts["vulnerability_decisions"] != 1 || v.Counts["build_attestations"] != 1 || v.Counts["passed_builds"] != 1 || v.Counts["vulnerability_scans"] != 1 {
		t.Fatal("summary did not reuse exact nine-count projection", v.Counts)
	}
	for _, values := range []map[string]int{v.Counts, v.OpenFindingsBySeverity, v.DecisionsByStatus} {
		for k := range values {
			values[k] = -1
		}
	}
	v.MissingRequiredDecisions[0].Vulnerability = "changed"
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("summary reads/result mutations changed repository state")
	}
	v, err = r.ReadReleaseSecuritySummarySnapshotAt(t.Context(), "tenant", "tenant-release", fixedNow().Add(2*time.Hour))
	if err != nil || v.ExceptionSummary.Expired != 1 || v.ExceptionSummary.Unapproved != 0 {
		t.Fatal("summary governance ignored explicit time", v.ExceptionSummary, err)
	}
}

func TestMemoryReleaseSummaryQueryRejectsSelectedOverflowAndForeignParents(t *testing.T) {
	tx, r := memoryReleaseSummaryFixture(t)
	p := tx.state.Products["tenant-product"]
	p.Name = strings.Repeat("x", 1025)
	tx.state.Products[p.ID] = p
	if v, err := r.ReadReleaseSecuritySummarySnapshotAt(t.Context(), "tenant", "tenant-release", fixedNow()); !errors.Is(err, riskquery.ErrInvalidProjection) || !reflect.DeepEqual(v, riskquery.ReleaseSecuritySummarySnapshot{}) {
		t.Fatal("oversized selected product returned partial summary", v, err)
	}
	p.Name = "Product"
	tx.state.Products[p.ID] = p
	scan := tx.state.VulnerabilityScans["scan"]
	scan.Findings[0].Component = strings.Repeat("x", 1025)
	tx.state.VulnerabilityScans[scan.ID] = scan
	if v, err := r.ReadReleaseSecuritySummarySnapshotAt(t.Context(), "tenant", "tenant-release", fixedNow()); !errors.Is(err, riskquery.ErrInvalidProjection) || !reflect.DeepEqual(v, riskquery.ReleaseSecuritySummarySnapshot{}) {
		t.Fatal("oversized selected finding returned partial summary", v, err)
	}
	for _, tenant := range []string{"foreign", "missing"} {
		if v, err := r.ReadReleaseSecuritySummarySnapshotAt(t.Context(), tenant, "tenant-release", fixedNow()); !errors.Is(err, riskquery.ErrNotFound) || !reflect.DeepEqual(v, riskquery.ReleaseSecuritySummarySnapshot{}) {
			t.Fatal("foreign summary returned data", v, err)
		}
	}
	root := tx.state.Releases["tenant-release"]
	root.ProductID = "foreign-product"
	tx.state.Releases[root.ID] = root
	if _, err := r.ReadReleaseSecuritySummarySnapshotAt(t.Context(), "tenant", root.ID, fixedNow()); !errors.Is(err, riskquery.ErrNotFound) {
		t.Fatal("foreign parent accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := r.ReadReleaseSecuritySummarySnapshotAt(ctx, "tenant", root.ID, fixedNow()); !errors.Is(err, context.Canceled) {
		t.Fatal("summary ignored cancellation", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadReleaseSecuritySummarySnapshotAt(t.Context(), "tenant", root.ID, fixedNow()); !errors.Is(err, ErrConflict) {
		t.Fatal("closed transaction returned summary", err)
	}
}

func TestMemoryReleaseSummaryQueryEnforcesGroupAndFindingBoundaries(t *testing.T) {
	for _, groups := range []int{32, 33} {
		t.Run(fmt.Sprintf("groups-%d", groups), func(t *testing.T) {
			tx, reader := memoryReleaseSummaryFixture(t)
			scan := tx.state.VulnerabilityScans["scan"]
			scan.Findings = make([]domain.VulnerabilityFinding, groups)
			for i := range groups {
				scan.Findings[i] = domain.VulnerabilityFinding{ID: fmt.Sprintf("finding-%04d", i), Severity: fmt.Sprintf("severity-%02d", i), State: "open"}
			}
			tx.state.VulnerabilityScans[scan.ID] = scan
			value, err := reader.ReadReleaseSecuritySummarySnapshotAt(t.Context(), "tenant", "tenant-release", fixedNow())
			if groups == 32 {
				if err != nil || len(value.OpenFindingsBySeverity) != groups || value.Counts["vulnerability_scans"] != 1 {
					t.Fatal("exact group limit rejected or truncated", value, err)
				}
			} else if !errors.Is(err, riskquery.ErrInvalidProjection) || !reflect.DeepEqual(value, riskquery.ReleaseSecuritySummarySnapshot{}) {
				t.Fatal("excess groups returned partial summary", value, err)
			}
		})
	}
	for _, count := range []int{riskquery.MaxSecuritySummaryFindings, riskquery.MaxSecuritySummaryFindings + 1} {
		t.Run(fmt.Sprintf("findings-%d", count), func(t *testing.T) {
			tx, reader := memoryReleaseSummaryFixture(t)
			scan := tx.state.VulnerabilityScans["scan"]
			scan.Findings = make([]domain.VulnerabilityFinding, count)
			for i := range count {
				scan.Findings[i] = domain.VulnerabilityFinding{ID: fmt.Sprintf("finding-%04d", count-i), Vulnerability: "CVE-fixture", Component: "component", Severity: "HIGH", State: "OPEN"}
			}
			tx.state.VulnerabilityScans[scan.ID] = scan
			value, err := reader.ReadReleaseSecuritySummarySnapshotAt(t.Context(), "tenant", "tenant-release", fixedNow())
			if count == riskquery.MaxSecuritySummaryFindings {
				if err != nil || len(value.MissingRequiredDecisions) != count || value.OpenFindingsBySeverity["high"] != count || value.MissingRequiredDecisions[0].FindingID != "finding-0001" || value.MissingRequiredDecisions[count-1].FindingID != "finding-4096" || value.MissingRequiredDecisions[0].State != "open" {
					t.Fatal("exact finding limit rejected, truncated or unordered", err)
				}
			} else if !errors.Is(err, riskquery.ErrInvalidProjection) || !reflect.DeepEqual(value, riskquery.ReleaseSecuritySummarySnapshot{}) {
				t.Fatal("excess findings returned partial summary", err)
			}
		})
	}
}
