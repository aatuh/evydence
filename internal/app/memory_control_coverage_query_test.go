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
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func memoryControlCoverageFixture(t *testing.T) (*memoryUnitOfWork, packagequery.ControlCoverageReader) {
	t.Helper()
	_, tx := memoryGovernanceReadFixture(t)
	reader, ok := tx.Repositories().Packages.(packagequery.ControlCoverageReader)
	if !ok {
		t.Fatal("memory package repository lacks native control coverage snapshots")
	}
	c := tx.state.SecurityControls["tenant-control"]
	c.Code, c.Title, c.Objective = "BUILD", "Build review", "Record reviewed build evidence"
	c.EvidenceRequirements = []domain.ControlEvidenceRequirement{{Type: "build", FreshnessDays: 30, Required: true}}
	c.Applicability, c.Limitations = []string{"software"}, []string{"Human review required"}
	tx.state.SecurityControls[c.ID] = c
	e := tx.state.Evidence["tenant-evidence"]
	e.ObservedAt = fixedNow().Add(-31 * 24 * time.Hour)
	tx.state.Evidence[e.ID] = e
	tx.state.ControlEvidence["link"] = domain.ControlEvidence{ID: "link", TenantID: "tenant", ControlID: c.ID, EvidenceType: "build", SubjectType: "evidence", SubjectID: e.ID, ProductID: "tenant-product", ReleaseID: "tenant-release", Confidence: "high", Notes: "Reviewed", SchemaVersion: "control-evidence.v1", CreatedAt: fixedNow()}
	c.ID, c.Code, c.Title = "waived-control", "VEX", "VEX review"
	c.EvidenceRequirements = []domain.ControlEvidenceRequirement{{Type: "vex", Required: true}}
	tx.state.SecurityControls[c.ID] = c
	x := tx.state.Exceptions["tenant-exception"]
	x.ControlID = c.ID
	tx.state.Exceptions[x.ID] = x
	return tx, reader
}

func TestMemoryControlCoverageQueryReturnsCurrentDetachedFactsAndSubjectTime(t *testing.T) {
	tx, reader := memoryControlCoverageFixture(t)
	// Foreign malformed records must not consume this scope's byte/row budget.
	foreign := tx.state.SecurityControls["foreign-control"]
	foreign.Title = strings.Repeat("private", 10000)
	tx.state.SecurityControls[foreign.ID] = foreign
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, framework := range []string{"tenant-framework", ""} {
		value, err := reader.ReadControlCoverageSnapshot(t.Context(), "tenant", framework, "", "tenant-release", fixedNow())
		if err != nil || value.TenantID != "tenant" || value.FrameworkID != "tenant-framework" || value.ScopeProductID != "tenant-product" || value.ScopeReleaseID != "tenant-release" || len(value.Controls) != 2 || len(value.Links) != 1 || len(value.Exceptions) != 1 || !value.Links[0].SubjectObservedAt.Equal(fixedNow().Add(-31*24*time.Hour)) {
			t.Fatal("coverage snapshot lost current scope, facts or actual observation time", value, err)
		}
		if domain.ControlEvidence(value.Links[0].Link) != tx.state.ControlEvidence["link"] || !reflect.DeepEqual(domain.Exception(value.Exceptions[0]), tx.state.Exceptions["tenant-exception"]) {
			t.Fatal("coverage snapshot changed complete persisted link/exception metadata")
		}
		value.Controls[0].EvidenceRequirements[0].Type, value.Controls[0].Applicability[0], value.Controls[0].Limitations[0] = "changed", "changed", "changed"
		*value.Exceptions[0].ApprovedAt = fixedNow().AddDate(1, 0, 0)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("coverage read or response mutation changed repository state")
	}
	query, err := packagequery.NewControlCoverageReport(reader, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	actor := domain.Actor{TenantID: "tenant", KeyID: "reader", Scopes: []string{"report:read"}}
	value, err := query.Coverage(t.Context(), actor, packagequery.ControlCoverageFilter{ProductID: "tenant-product", ReleaseID: "tenant-release"})
	if err != nil || value.Result != "failed" || value.Controls[0].Status != "partial" || !reflect.DeepEqual(value.Controls[0].Missing, []string{"fresh_build"}) || value.Controls[1].Status != "waived" || len(value.AcceptedExceptions) != 1 {
		t.Fatal("native coverage did not evaluate actual freshness and current exception", value, err)
	}
}

func TestMemoryControlCoverageQueryFiltersInvalidParentsOtherFrameworksAndExpiry(t *testing.T) {
	for _, change := range []string{"foreign-subject", "broken-project", "mismatched-link", "other-framework", "expired-exception", "pending-exception", "foreign-exception-parent"} {
		t.Run(change, func(t *testing.T) {
			tx, reader := memoryControlCoverageFixture(t)
			wantLinks, wantExceptions := 1, 1
			switch change {
			case "foreign-subject", "mismatched-link":
				v := tx.state.ControlEvidence["link"]
				if change == "foreign-subject" {
					v.SubjectID = "foreign-evidence"
				} else {
					v.ReleaseID = "foreign-release"
				}
				tx.state.ControlEvidence[v.ID] = v
				wantLinks = 0
			case "broken-project":
				e := tx.state.Evidence["tenant-evidence"]
				e.ProjectID = "foreign-project"
				tx.state.Evidence[e.ID] = e
				wantLinks = 0
			case "other-framework":
				f := tx.state.ControlFrameworks["tenant-framework"]
				f.ID = "other-framework"
				tx.state.ControlFrameworks[f.ID] = f
				c := tx.state.SecurityControls["waived-control"]
				c.FrameworkID = f.ID
				tx.state.SecurityControls[c.ID] = c
				wantExceptions = 0
			default:
				x := tx.state.Exceptions["tenant-exception"]
				switch change {
				case "expired-exception":
					x.ExpiresAt = fixedNow()
				case "pending-exception":
					x.Approved = false
				case "foreign-exception-parent":
					x.ReleaseID = "foreign-release"
				}
				tx.state.Exceptions[x.ID] = x
				wantExceptions = 0
			}
			value, err := reader.ReadControlCoverageSnapshot(t.Context(), "tenant", "tenant-framework", "tenant-product", "tenant-release", fixedNow())
			if err != nil || len(value.Links) != wantLinks || len(value.Exceptions) != wantExceptions {
				t.Fatal("coverage admitted invalid, foreign, unrelated or expired records", value, err)
			}
		})
	}
}

func TestMemoryControlCoverageQueryBoundsRowsAndBytesWithoutPartialResults(t *testing.T) {
	for _, change := range []string{"exact-row-limit", "row-limit", "control-bytes", "link-bytes", "exception-bytes", "snapshot-bytes"} {
		t.Run(change, func(t *testing.T) {
			tx, reader := memoryControlCoverageFixture(t)
			switch change {
			case "exact-row-limit", "row-limit":
				c := tx.state.SecurityControls["tenant-control"]
				extra := packagequery.MaxControlCoverageEntries
				if change == "exact-row-limit" {
					extra -= 4 // Two controls, one link and one exception already exist.
				}
				for i := 0; i < extra; i++ {
					c.ID = fmt.Sprintf("extra-%04d", i)
					c.Code = c.ID
					tx.state.SecurityControls[c.ID] = c
				}
			case "control-bytes", "snapshot-bytes":
				c := tx.state.SecurityControls["tenant-control"]
				c.Objective = strings.Repeat("x", 65<<10)
				if change == "snapshot-bytes" {
					c.Objective = strings.Repeat("x", 60<<10)
					for i := 0; i < 140; i++ {
						c.ID = fmt.Sprintf("large-%04d", i)
						tx.state.SecurityControls[c.ID] = c
					}
				} else {
					tx.state.SecurityControls[c.ID] = c
				}
			case "link-bytes":
				v := tx.state.ControlEvidence["link"]
				v.Notes = strings.Repeat("x", 9<<10)
				tx.state.ControlEvidence[v.ID] = v
			case "exception-bytes":
				x := tx.state.Exceptions["tenant-exception"]
				x.Reason = strings.Repeat("x", 9<<10)
				tx.state.Exceptions[x.ID] = x
			}
			value, err := reader.ReadControlCoverageSnapshot(t.Context(), "tenant", "tenant-framework", "tenant-product", "tenant-release", fixedNow())
			if change == "exact-row-limit" {
				if err != nil || len(value.Controls)+len(value.Links)+len(value.Exceptions) != packagequery.MaxControlCoverageEntries {
					t.Fatal("exact shared coverage entry limit rejected", err)
				}
				return
			}
			if !errors.Is(err, packagequery.ErrControlCoverageCapacity) || !reflect.DeepEqual(value, packagequery.ControlCoverageSnapshot{}) {
				t.Fatal("over-budget coverage returned partial data", value, err)
			}
		})
	}
}

func TestMemoryControlCoverageQueryRejectsForeignRootsCancellationAndClosedTransactions(t *testing.T) {
	tx, reader := memoryControlCoverageFixture(t)
	for _, coords := range [][3]string{{"foreign-framework", "tenant-product", "tenant-release"}, {"tenant-framework", "foreign-product", "tenant-release"}, {"tenant-framework", "tenant-product", "foreign-release"}} {
		value, err := reader.ReadControlCoverageSnapshot(t.Context(), "tenant", coords[0], coords[1], coords[2], fixedNow())
		if !errors.Is(err, packagequery.ErrControlCoverageNotFound) || !reflect.DeepEqual(value, packagequery.ControlCoverageSnapshot{}) {
			t.Fatal("foreign root returned coverage facts", value, err)
		}
	}
	var absent context.Context
	if _, err := reader.ReadControlCoverageSnapshot(absent, "tenant", "", "", "", fixedNow()); !errors.Is(err, packagequery.ErrControlCoverageValidation) {
		t.Fatal("nil coverage context accepted", err)
	}
	if _, err := reader.ReadControlCoverageSnapshot(t.Context(), "tenant", "", "", "", time.Time{}); !errors.Is(err, packagequery.ErrControlCoverageValidation) {
		t.Fatal("zero coverage evaluation time accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reader.ReadControlCoverageSnapshot(ctx, "tenant", "", "", "", fixedNow()); !errors.Is(err, context.Canceled) {
		t.Fatal("coverage ignored cancellation", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if value, err := reader.ReadControlCoverageSnapshot(t.Context(), "tenant", "", "", "", fixedNow()); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(value, packagequery.ControlCoverageSnapshot{}) {
		t.Fatal("closed transaction returned coverage facts", value, err)
	}
}

func TestMemoryControlCoverageQueryResolvesEveryNativeSubjectAndRejectsForeignCounterparts(t *testing.T) {
	tx, reader := memoryControlCoverageFixture(t)
	at := fixedNow().Add(-time.Hour)
	for _, tenant := range []string{"tenant", "foreign"} {
		product, release, project := tenant+"-product", tenant+"-release", tenant+"-project"
		evidence := tenant + "-evidence"
		tx.state.Projects[project] = domain.Project{ID: project, TenantID: tenant, ProductID: product}
		e := tx.state.Evidence[evidence]
		e.ProjectID, e.SubjectRefs = project, []domain.SubjectRef{{Type: "artifact", ID: tenant + "-artifact"}}
		e.ObservedAt = at.Add(-time.Hour)
		tx.state.Evidence[e.ID] = e
		tx.state.Artifacts[tenant+"-artifact"] = domain.Artifact{ID: tenant + "-artifact", TenantID: tenant, Digest: "digest"}
		tx.state.BuildRuns[tenant+"-build"] = domain.BuildRun{ID: tenant + "-build", TenantID: tenant, ProjectID: project, ReleaseID: release, Outputs: []domain.BuildOutput{{ArtifactID: tenant + "-artifact", Digest: "digest"}}, CreatedAt: at}
		tx.state.BuildAttestations[tenant+"-attestation"] = domain.BuildAttestation{ID: tenant + "-attestation", TenantID: tenant, BuildID: tenant + "-build", EvidenceID: evidence, CreatedAt: at}
		tx.state.SBOMs[tenant+"-sbom"] = domain.SBOM{ID: tenant + "-sbom", TenantID: tenant, ReleaseID: release, EvidenceID: evidence, CreatedAt: at}
		tx.state.VEXDocuments[tenant+"-vex"] = domain.VEXDocument{ID: tenant + "-vex", TenantID: tenant, ReleaseID: release, EvidenceID: evidence, CreatedAt: at}
		scan := tx.state.VulnerabilityScans[tenant+"-scan"]
		scan.CreatedAt = at
		tx.state.VulnerabilityScans[scan.ID] = scan
		tx.state.Decisions[tenant+"-decision"] = domain.VulnerabilityDecision{ID: tenant + "-decision", TenantID: tenant, ReleaseID: release, ScanID: scan.ID, CreatedAt: at}
		x := tx.state.Exceptions[tenant+"-exception"]
		x.CreatedAt = at
		tx.state.Exceptions[x.ID] = x
		c := tx.state.OpenAPIContracts[tenant+"-contract-base"]
		c.EvidenceID, c.CreatedAt = evidence, at
		tx.state.OpenAPIContracts[c.ID] = c
		tx.state.ReleaseBundles[tenant+"-bundle"] = domain.ReleaseBundle{ID: tenant + "-bundle", TenantID: tenant, ReleaseID: release, CreatedAt: at}
	}
	for _, tc := range []struct {
		kind, suffix string
		observed     time.Time
	}{
		{"evidence", "evidence", at.Add(-time.Hour)}, {"evidence_item", "evidence", at.Add(-time.Hour)},
		{"product", "product", fixedNow()}, {"release", "release", fixedNow()}, {"artifact", "artifact", fixedNow()},
		{"sbom", "sbom", at}, {"vulnerability_scan", "scan", at}, {"vex", "vex", at}, {"vulnerability_decision", "decision", at},
		{"finding", "finding", fixedNow()}, {"vulnerability_finding", "finding", fixedNow()}, {"exception", "exception", at},
		{"build", "build", at}, {"build_attestation", "attestation", at}, {"openapi_contract", "contract-base", at}, {"release_bundle", "bundle", at},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			for _, tenant := range []string{"tenant", "foreign"} {
				link := tx.state.ControlEvidence["link"]
				link.ReleaseID = "tenant-release"
				link.SubjectType, link.SubjectID = tc.kind, tenant+"-"+tc.suffix
				// Product-only subjects and the global owned-artifact branch have
				// no release coordinate; nullable links must retain that contract.
				if tc.kind == "product" {
					link.ReleaseID = ""
				}
				tx.state.ControlEvidence[link.ID] = link
				value, err := reader.ReadControlCoverageSnapshot(t.Context(), "tenant", "tenant-framework", "tenant-product", "tenant-release", fixedNow())
				want := 1
				if tenant == "foreign" {
					want = 0
				}
				if err != nil || len(value.Links) != want || want == 1 && !value.Links[0].SubjectObservedAt.Equal(tc.observed) {
					t.Fatal("native subject selection lost current ownership or timestamp", value, err)
				}
			}
		})
	}
}

func TestMemoryControlCoverageQueryCancellationDuringSelectionReturnsNoPartialFacts(t *testing.T) {
	tx, reader := memoryControlCoverageFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	base, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx := &memoryCRACancelDuringRead{Context: base, cancel: cancel}
	value, err := reader.ReadControlCoverageSnapshot(ctx, "tenant", "tenant-framework", "tenant-product", "tenant-release", fixedNow())
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(value, packagequery.ControlCoverageSnapshot{}) || ctx.checks < 5 {
		t.Fatal("mid-selection cancellation returned partial coverage", value, err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("canceled coverage read changed repository state")
	}
	value, err = reader.ReadControlCoverageSnapshot(t.Context(), "tenant", "tenant-framework", "tenant-product", "tenant-release", fixedNow())
	if err != nil || len(value.Controls) != 2 || len(value.Exceptions) != 1 {
		t.Fatal("canceled coverage read retained the transaction lock or corrupted facts", value, err)
	}
}
