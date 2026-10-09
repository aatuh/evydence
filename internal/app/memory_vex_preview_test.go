package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

func memoryVEXPreviewFixture(t *testing.T) (*memoryUnitOfWork, evidencequery.VEXPreviewReader, domain.Actor) {
	t.Helper()
	tx, _ := memoryParsedPointFixture(t)
	r, ok := tx.Repositories().Evidence.(evidencequery.VEXPreviewReader)
	if !ok {
		t.Fatal("memory Evidence repository lacks focused VEX preview snapshots")
	}
	scan := tx.state.VulnerabilityScans["scan"]
	scan.Findings = []domain.VulnerabilityFinding{{ID: "b", Vulnerability: "CVE-fixture", Component: "pkg:generic/b@1"}, {ID: "unrelated", Vulnerability: "CVE-other", Component: "pkg:generic/other@1"}}
	tx.state.VulnerabilityScans[scan.ID] = scan
	scan.ID = "a-scan"
	scan.Findings = []domain.VulnerabilityFinding{{ID: "a", Vulnerability: "CVE-fixture", Component: "pkg:generic/a@1"}}
	tx.state.VulnerabilityScans[scan.ID] = scan
	tx.state.Decisions = map[string]domain.VulnerabilityDecision{"decision": {ID: "decision", TenantID: "tenant", ScanID: "scan", FindingID: "b", ReleaseID: "tenant-release", InternalNotes: "private decision text"}}
	actor := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{ScopeEvidenceRead}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "tenant-product", Scopes: []string{ScopeEvidenceRead}}}}
	return tx, r, actor
}

func TestMemoryVEXPreviewBoundsScansFindingsAndSelectedText(t *testing.T) {
	prepare := func(application.ResourceReferences, application.Authorizer) ([]string, error) {
		return []string{"CVE-fixture"}, nil
	}
	for _, field := range []string{"scans", "findings", "text"} {
		t.Run(field, func(t *testing.T) {
			tx, reader, _ := memoryVEXPreviewFixture(t)
			delete(tx.state.VulnerabilityScans, "a-scan")
			scan := tx.state.VulnerabilityScans["scan"]
			tx.state.Decisions = nil
			switch field {
			case "scans":
				scan.Findings = nil
				tx.state.VulnerabilityScans[scan.ID] = scan
				for i := 1; i < evidencequery.MaxVEXPreviewScans; i++ {
					copy := scan
					copy.ID = fmt.Sprintf("scan-%04d", i)
					tx.state.VulnerabilityScans[copy.ID] = copy
				}
			case "findings":
				scan.Findings = make([]domain.VulnerabilityFinding, evidencequery.MaxVEXPreviewFindings)
				for i := range scan.Findings {
					scan.Findings[i] = domain.VulnerabilityFinding{ID: fmt.Sprintf("finding-%04d", i), Vulnerability: "CVE-fixture", Component: "pkg:generic/api@1"}
				}
				tx.state.VulnerabilityScans[scan.ID] = scan
			case "text":
				// Include every projected coordinate, not only component bytes.
				scan.Findings = make([]domain.VulnerabilityFinding, 8)
				remaining := evidencequery.MaxVEXPreviewTextBytes
				for i := range scan.Findings {
					id := fmt.Sprintf("finding-%d", i)
					remaining -= len(id) + len(scan.ID) + len(scan.TenantID) + len(scan.ReleaseID) + len("CVE-fixture")
					scan.Findings[i] = domain.VulnerabilityFinding{ID: id, Vulnerability: "CVE-fixture"}
				}
				for i := range scan.Findings {
					length := min(1<<20, remaining)
					scan.Findings[i].Component = strings.Repeat("x", length)
					remaining -= length
				}
				if remaining != 0 {
					t.Fatal("text-boundary fixture did not consume exact budget")
				}
				tx.state.VulnerabilityScans[scan.ID] = scan
			}
			if point, err := reader.ReadVEXPreviewSnapshot(t.Context(), "tenant", "tenant-release", "", prepare); err != nil || field == "findings" && len(point.Findings) != evidencequery.MaxVEXPreviewFindings {
				t.Fatal("exact preview limit was rejected or truncated", field, err)
			}
			switch field {
			case "scans":
				copy := scan
				copy.ID = "overflow-scan"
				tx.state.VulnerabilityScans[copy.ID] = copy
			case "findings":
				scan.Findings = append(scan.Findings, domain.VulnerabilityFinding{ID: "overflow-finding", Vulnerability: "CVE-fixture"})
				tx.state.VulnerabilityScans[scan.ID] = scan
			case "text":
				scan.Findings[len(scan.Findings)-1].Component += "x"
				tx.state.VulnerabilityScans[scan.ID] = scan
			}
			if point, err := reader.ReadVEXPreviewSnapshot(t.Context(), "tenant", "tenant-release", "", prepare); !errors.Is(err, evidencequery.ErrConflict) || !reflect.DeepEqual(point, evidencequery.VEXPreviewSnapshot{}) {
				t.Fatal("overflow returned truncated or partial preview", field, err)
			}
		})
	}
}

func TestMemoryVEXPreviewRejectsSelectedDecisionLinkageAndIgnoresUnselectedPrivateText(t *testing.T) {
	tx, reader, _ := memoryVEXPreviewFixture(t)
	prepare := func(application.ResourceReferences, application.Authorizer) ([]string, error) {
		return []string{"CVE-fixture"}, nil
	}
	scan := tx.state.VulnerabilityScans["scan"]
	scan.Findings[1].Component = strings.Repeat("private", 200000)
	tx.state.VulnerabilityScans[scan.ID] = scan
	decision := tx.state.Decisions["decision"]
	decision.InternalNotes = strings.Repeat("private", 200000)
	tx.state.Decisions[decision.ID] = decision
	if point, err := reader.ReadVEXPreviewSnapshot(t.Context(), "tenant", "tenant-release", "", prepare); err != nil || len(point.Findings) != 2 || !point.Findings[1].HasActiveDecision {
		t.Fatal("preview inspected unrelated/private fields or lost active presence", point, err)
	}
	for _, field := range []string{"scan", "release"} {
		corrupt := decision
		if field == "scan" {
			corrupt.ScanID = "another"
		} else {
			corrupt.ReleaseID = "another"
		}
		tx.state.Decisions[corrupt.ID] = corrupt
		if point, err := reader.ReadVEXPreviewSnapshot(t.Context(), "tenant", "tenant-release", "", prepare); !errors.Is(err, evidencequery.ErrConflict) || !reflect.DeepEqual(point, evidencequery.VEXPreviewSnapshot{}) {
			t.Fatal("selected active decision crossed scan/release ownership", point, err)
		}
	}
	decision.TenantID = "foreign"
	tx.state.Decisions[decision.ID] = decision
	point, err := reader.ReadVEXPreviewSnapshot(t.Context(), "tenant", "tenant-release", "", prepare)
	if err != nil || point.Findings[1].HasActiveDecision {
		t.Fatal("preview used a foreign active-decision presence", point, err)
	}
}

func TestMemoryVEXPreviewReadsCurrentSortedCoordinatesAndArtifactGrants(t *testing.T) {
	tx, reader, actor := memoryVEXPreviewFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	prepare := func(refs application.ResourceReferences, auth application.Authorizer) ([]string, error) {
		calls++
		if refs != (application.ResourceReferences{ProductID: "tenant-product", ReleaseID: "tenant-release"}) {
			t.Fatal("preview preparation lost owned release coordinates", refs)
		}
		if err := auth.Authorize(t.Context(), actor, application.AuthorizationRequest{Scope: ScopeEvidenceRead, Resources: application.ResourceReferences{ArtifactID: "artifact"}}); err != nil {
			return nil, err
		}
		return []string{"CVE-fixture"}, nil
	}
	got, err := reader.ReadVEXPreviewSnapshot(t.Context(), "tenant", " tenant-release ", " artifact ", prepare)
	want := evidencequery.VEXPreviewSnapshot{TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", ArtifactID: "artifact", Findings: []evidencequery.VEXPreviewFinding{{ID: "a", ScanID: "a-scan", TenantID: "tenant", ReleaseID: "tenant-release", Vulnerability: "CVE-fixture", Component: "pkg:generic/a@1"}, {ID: "b", ScanID: "scan", TenantID: "tenant", ReleaseID: "tenant-release", Vulnerability: "CVE-fixture", Component: "pkg:generic/b@1", HasActiveDecision: true}}}
	if err != nil || calls != 1 || !reflect.DeepEqual(got, want) {
		t.Fatal("preview did not select complete current bounded coordinates", got, err)
	}
	got.Findings[0].Component = "changed"
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("preview read or caller mutation changed repository data")
	}
	for id, e := range tx.state.Evidence {
		e.SubjectRefs = nil
		tx.state.Evidence[id] = e
	}
	for id, b := range tx.state.BuildRuns {
		b.Outputs = nil
		tx.state.BuildRuns[id] = b
	}
	if point, err := reader.ReadVEXPreviewSnapshot(t.Context(), "tenant", "tenant-release", "artifact", prepare); !errors.Is(err, application.ErrForbidden) || !reflect.DeepEqual(point, evidencequery.VEXPreviewSnapshot{}) {
		t.Fatal("preview retained a removed artifact association", point, err)
	}
}

func TestMemoryVEXPreviewAuthorizesBeforePrivateSelectionAndRejectsMissingParents(t *testing.T) {
	tx, reader, _ := memoryVEXPreviewFixture(t)
	scan := tx.state.VulnerabilityScans["scan"]
	scan.EvidenceID = "missing-private-source"
	tx.state.VulnerabilityScans[scan.ID] = scan
	denied := func(application.ResourceReferences, application.Authorizer) ([]string, error) {
		return nil, application.ErrForbidden
	}
	if point, err := reader.ReadVEXPreviewSnapshot(t.Context(), "tenant", "tenant-release", "", denied); !errors.Is(err, application.ErrForbidden) || !reflect.DeepEqual(point, evidencequery.VEXPreviewSnapshot{}) {
		t.Fatal("preview selected corrupt private candidates before authority", point, err)
	}
	prepare := func(application.ResourceReferences, application.Authorizer) ([]string, error) {
		return []string{"CVE-fixture"}, nil
	}
	if _, err := reader.ReadVEXPreviewSnapshot(t.Context(), "tenant", "tenant-release", "", prepare); !errors.Is(err, evidencequery.ErrNotFound) {
		t.Fatal("owned preview accepted a missing scan source", err)
	}
	for _, scope := range [][3]string{{"foreign", "tenant-release", ""}, {"tenant", "missing", ""}, {"tenant", "tenant-release", "missing"}} {
		called := false
		prepare := func(application.ResourceReferences, application.Authorizer) ([]string, error) {
			called = true
			return nil, nil
		}
		if _, err := reader.ReadVEXPreviewSnapshot(t.Context(), scope[0], scope[1], scope[2], prepare); !errors.Is(err, evidencequery.ErrNotFound) || called {
			t.Fatal("preview exposed foreign/missing parents to preparation", err)
		}
	}
}

func TestMemoryVEXPreviewRejectsInvalidContextsAndClosedTransactions(t *testing.T) {
	tx, reader, _ := memoryVEXPreviewFixture(t)
	prepare := func(application.ResourceReferences, application.Authorizer) ([]string, error) {
		return []string{"CVE-fixture"}, nil
	}
	var absent context.Context
	if _, err := reader.ReadVEXPreviewSnapshot(absent, "tenant", "tenant-release", "", prepare); !errors.Is(err, evidencequery.ErrValidation) {
		t.Fatal("preview accepted a nil context", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if point, err := reader.ReadVEXPreviewSnapshot(ctx, "tenant", "tenant-release", "", prepare); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(point, evidencequery.VEXPreviewSnapshot{}) {
		t.Fatal("canceled preview returned data", point, err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadVEXPreviewSnapshot(t.Context(), "tenant", "tenant-release", "", prepare); !errors.Is(err, ErrConflict) {
		t.Fatal("closed preview transaction accepted", err)
	}
}
