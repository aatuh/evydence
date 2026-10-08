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
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func memoryReadinessReportFixture(t *testing.T) (*memoryUnitOfWork, packagequery.ReleaseReadinessReportReader) {
	t.Helper()
	tx, _ := memoryReadinessQueryFixture(t)
	reader, ok := tx.Repositories().Packages.(packagequery.ReleaseReadinessReportReader)
	if !ok {
		t.Fatal("memory Package repository lacks native readiness report snapshots")
	}
	at := fixedNow()
	tx.state.Decisions["decision"] = domain.VulnerabilityDecision{ID: "decision", TenantID: "tenant", ReleaseID: "tenant-release", ScanID: "scan", FindingID: "finding", Vulnerability: "CVE-fixture", Component: "component", Status: "affected", InternalNotes: strings.Repeat("private", 10000), CreatedAt: at}
	tx.state.Exceptions["exception"] = domain.Exception{ID: "exception", TenantID: "tenant", ReleaseID: "tenant-release", FindingID: "high", Owner: "security", Reason: "Reviewed risk", Approved: true, ApprovedBy: "reviewer", ApprovedAt: &at, ExpiresAt: at.Add(time.Hour), CreatedAt: at}
	tx.state.RedactionProfiles["profile"] = domain.RedactionProfile{ID: "profile", TenantID: "tenant", AllowedTypes: []string{"sbom"}, ExcludedFields: []string{"payload_ref", "object_key", "private_key", "token", "secret", "internal_notes"}}
	tx.state.CustomerPackages["package"] = domain.CustomerSecurityPackage{ID: "package", TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", RedactionProfileID: "profile", State: "generated", ExpiresAt: at.Add(time.Hour), Manifest: map[string]any{"private": strings.Repeat("private", 10000)}}
	return tx, reader
}

func TestMemoryReadinessReportQueryReturnsCompleteCurrentTrustedFactsWithoutWrites(t *testing.T) {
	tx, reader := memoryReadinessReportFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	value, err := reader.ReadReleaseReadinessReportSnapshot(t.Context(), "tenant", "tenant-release", fixedNow())
	want := packagequery.ReleaseReadinessReportSnapshot{
		Readiness:           riskdomain.ReadinessSnapshot{SnapshotVersion: riskdomain.ReadinessSnapshotVersion, TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", HasArtifact: true, HasArtifactDigest: true, HasSBOM: true, HasVulnerabilityScan: true, HasPassedBuild: true, HasVerifiedBuildAttestation: true, UnhandledCritical: true, PackageCount: 1},
		BlockingFindings:    []packagedomain.BlockingFinding{{FindingID: "finding", ScanID: "scan", ReleaseID: "tenant-release", Vulnerability: "CVE-fixture", Component: "component", Severity: "critical", State: "open"}},
		AcceptedExceptions:  []packagedomain.AcceptedExceptionSnapshot{packagedomain.AcceptedExceptionSnapshot(tx.state.Exceptions["exception"])},
		ActiveDecisionCount: 1, HasActiveCustomerPackage: true,
	}
	if err != nil || !reflect.DeepEqual(value, want) {
		t.Fatal("readiness report lost exact trusted facts, blockers, exception metadata or counts", value, want, err)
	}
	value.BlockingFindings[0].Component = "changed"
	*value.AcceptedExceptions[0].ApprovedAt = fixedNow().AddDate(1, 0, 0)
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("readiness report read or result mutation changed current repository state")
	}
	value, err = reader.ReadReleaseReadinessReportSnapshot(t.Context(), "tenant", "tenant-release", fixedNow().Add(2*time.Hour))
	if err != nil || !value.Readiness.UnhandledHigh || len(value.AcceptedExceptions) != 0 || value.HasActiveCustomerPackage || !reflect.DeepEqual(value.Readiness.InvalidPackageOrProfileIDs, []string{"package"}) {
		t.Fatal("explicit report time failed to expire exceptions/packages", value, err)
	}
}

func TestMemoryReadinessReportQueryDoesNotTrustAmbiguousDecisionsOrForeignHandling(t *testing.T) {
	for _, change := range []string{"fixed", "ambiguous", "foreign-decision", "foreign-receipt"} {
		t.Run(change, func(t *testing.T) {
			tx, reader := memoryReadinessReportFixture(t)
			d := tx.state.Decisions["decision"]
			d.Status = "fixed"
			tx.state.Decisions[d.ID] = d
			wantBlockers := 1
			switch change {
			case "fixed":
				wantBlockers = 0
			case "ambiguous":
				scan := tx.state.VulnerabilityScans["scan"]
				scan.Findings = append(scan.Findings, scan.Findings[0])
				tx.state.VulnerabilityScans[scan.ID] = scan
				wantBlockers = 2
			case "foreign-decision":
				d.TenantID = "foreign"
				tx.state.Decisions[d.ID] = d
			case "foreign-receipt":
				v := tx.state.VerificationResults["receipt"]
				v.TenantID = "foreign"
				tx.state.VerificationResults[v.ID] = v
				wantBlockers = 0
			}
			value, err := reader.ReadReleaseReadinessReportSnapshot(t.Context(), "tenant", "tenant-release", fixedNow())
			if err != nil || len(value.BlockingFindings) != wantBlockers || value.Readiness.UnhandledCritical != (wantBlockers != 0) || change == "foreign-receipt" && value.Readiness.HasVerifiedBuildAttestation {
				t.Fatal("readiness report assigned false trust", value, err)
			}
		})
	}
}

func TestMemoryReadinessReportQuerySharesDetailBudgetWithPolicyDiagnostics(t *testing.T) {
	for _, extra := range []int{0, 1} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			tx, reader := memoryReadinessReportFixture(t)
			d := tx.state.Decisions["decision"]
			d.CustomerVisible, d.ImpactStatement = true, ""
			tx.state.Decisions[d.ID] = d
			x := tx.state.Exceptions["exception"]
			// One blocker, one exception and one policy-diagnostic ID exist.
			for i := 0; i < packagequery.MaxReleaseReadinessEntries-3+extra; i++ {
				x.ID = fmt.Sprintf("accepted-%04d", i)
				tx.state.Exceptions[x.ID] = x
			}
			value, err := reader.ReadReleaseReadinessReportSnapshot(t.Context(), "tenant", "tenant-release", fixedNow())
			if extra == 0 {
				if err != nil || len(value.BlockingFindings)+len(value.AcceptedExceptions)+len(value.Readiness.MissingCustomerStatementIDs) != packagequery.MaxReleaseReadinessEntries {
					t.Fatal("exact combined readiness detail/diagnostic budget rejected", err)
				}
			} else if !errors.Is(err, packagequery.ErrReleaseReadinessProjection) || !reflect.DeepEqual(value, packagequery.ReleaseReadinessReportSnapshot{}) {
				t.Fatal("overflow returned truncated or partial readiness details", value, err)
			}
		})
	}
}

func TestMemoryReadinessReportQueryBoundsSelectedTextWithoutTruncation(t *testing.T) {
	for _, kind := range []string{"reason", "vulnerability"} {
		for _, extra := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s-%d", kind, extra), func(t *testing.T) {
				tx, reader := memoryReadinessReportFixture(t)
				if kind == "reason" {
					x := tx.state.Exceptions["exception"]
					x.Reason = strings.Repeat("x", 4096+extra)
					tx.state.Exceptions[x.ID] = x
				} else {
					scan := tx.state.VulnerabilityScans["scan"]
					scan.Findings[0].Vulnerability = strings.Repeat("x", 1024+extra)
					tx.state.VulnerabilityScans[scan.ID] = scan
				}
				value, err := reader.ReadReleaseReadinessReportSnapshot(t.Context(), "tenant", "tenant-release", fixedNow())
				if extra == 0 {
					if err != nil || len(value.AcceptedExceptions) != 1 || len(value.BlockingFindings) != 1 || kind == "reason" && len(value.AcceptedExceptions[0].Reason) != 4096 || kind == "vulnerability" && len(value.BlockingFindings[0].Vulnerability) != 1024 {
						t.Fatal("exact text boundary rejected or silently truncated", value, err)
					}
				} else if !errors.Is(err, packagequery.ErrReleaseReadinessProjection) || !reflect.DeepEqual(value, packagequery.ReleaseReadinessReportSnapshot{}) {
					t.Fatal("oversized selected text returned partial readiness details", value, err)
				}
			})
		}
	}
}

func TestMemoryReadinessReportQueryRejectsForeignRootsCanceledAndClosedReads(t *testing.T) {
	tx, reader := memoryReadinessReportFixture(t)
	for _, release := range []string{"foreign-release", "missing-release"} {
		value, err := reader.ReadReleaseReadinessReportSnapshot(t.Context(), "tenant", release, fixedNow())
		if !errors.Is(err, packagequery.ErrReleaseReadinessNotFound) || !reflect.DeepEqual(value, packagequery.ReleaseReadinessReportSnapshot{}) {
			t.Fatal("foreign or missing release exposed readiness details", value, err)
		}
	}
	var absent context.Context
	if _, err := reader.ReadReleaseReadinessReportSnapshot(absent, "tenant", "tenant-release", fixedNow()); !errors.Is(err, packagequery.ErrReleaseReadinessValidation) {
		t.Fatal("nil readiness report context accepted", err)
	}
	if _, err := reader.ReadReleaseReadinessReportSnapshot(t.Context(), "tenant", "tenant-release", time.Time{}); !errors.Is(err, packagequery.ErrReleaseReadinessValidation) {
		t.Fatal("zero readiness report time accepted", err)
	}
	base, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx := &memoryCRACancelDuringRead{Context: base, cancel: cancel}
	value, err := reader.ReadReleaseReadinessReportSnapshot(ctx, "tenant", "tenant-release", fixedNow())
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(value, packagequery.ReleaseReadinessReportSnapshot{}) {
		t.Fatal("mid-selection cancellation returned readiness details", value, err)
	}
	if _, err := reader.ReadReleaseReadinessReportSnapshot(t.Context(), "tenant", "tenant-release", fixedNow()); err != nil {
		t.Fatal("canceled readiness report retained transaction lock", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if value, err := reader.ReadReleaseReadinessReportSnapshot(t.Context(), "tenant", "tenant-release", fixedNow()); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(value, packagequery.ReleaseReadinessReportSnapshot{}) {
		t.Fatal("closed readiness report transaction returned data", value, err)
	}
}
