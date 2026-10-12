package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func TestMemoryWorkflowReaderUsesOnlyOwnedIdentifiersAndDeclaredRelease(t *testing.T) {
	factory, tx := memoryGovernanceReadFixture(t)
	reader, ok := tx.Repositories().Risk.(riskapp.VulnerabilityWorkflowReader)
	if !ok {
		t.Fatal("memory Risk lacks focused workflow ownership reader")
	}
	scan := tx.state.VulnerabilityScans["tenant-scan"]
	scan.Findings[0].Vulnerability = strings.Repeat("private", 1000)
	scan.Findings[0].Component = strings.Repeat("private", 1000)
	tx.state.VulnerabilityScans[scan.ID] = scan
	tx.state.VulnerabilityWorkflow["old"] = domain.VulnerabilityWorkflowRecord{ID: "old", TenantID: "tenant", FindingID: "tenant-finding", Reason: strings.Repeat("private", 1000)}
	pending, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	want := riskapp.GovernanceSubjectReference{TenantID: "tenant", Type: "finding", ID: "tenant-finding", ProductID: "tenant-product", ReleaseID: "tenant-release"}
	v, err := reader.ReadWorkflowFinding(t.Context(), "tenant", "tenant-finding")
	if err != nil || v != want {
		t.Fatal("workflow ownership consulted vulnerability text or history", v, err)
	}
	for _, id := range []string{"foreign-finding", "missing"} {
		if _, err := reader.ReadWorkflowFinding(t.Context(), "tenant", id); !errors.Is(err, ErrNotFound) {
			t.Fatal("unowned finding exposed", id, err)
		}
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reader.ReadWorkflowFinding(cancelled, "tenant", "tenant-finding"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled workflow read accepted", err)
	}
	for _, id := range []string{"", " bad ", "bad\x00", strings.Repeat("x", 1025)} {
		if _, err := reader.ReadWorkflowFinding(t.Context(), "tenant", id); !errors.Is(err, ErrValidation) {
			t.Fatal("invalid workflow identifier accepted", err)
		}
	}
	if !reflect.DeepEqual(pending, tx.state) {
		t.Fatal("workflow reads changed pending data")
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("workflow reads published data", err)
	}
	// A source may have a release while its scan intentionally declares none.
	// Workflow semantics must not infer a release from that source.
	scan.ReleaseID = ""
	tx.state.VulnerabilityScans[scan.ID] = scan
	want.ReleaseID = ""
	v, err = reader.ReadWorkflowFinding(t.Context(), "tenant", "tenant-finding")
	if err != nil || v != want {
		t.Fatal("release-less workflow inferred a source release", v, err)
	}
	source := tx.state.Evidence["tenant-evidence"]
	source.ProductID, source.ReleaseID = "", ""
	tx.state.Evidence[source.ID] = source
	want.ProductID = ""
	v, err = reader.ReadWorkflowFinding(t.Context(), "tenant", "tenant-finding")
	if err != nil || v != want {
		t.Fatal("tenant-wide release-less workflow required artificial parents", v, err)
	}
}

func TestMemoryWorkflowReaderRejectsBrokenParentsAndAmbiguousFindingIDs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*MemoryUnitOfWorkSnapshot)
		want   error
	}{
		{"foreign product", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Products["tenant-product"]
			v.TenantID = "foreign"
			s.Products[v.ID] = v
		}, ErrNotFound},
		{"wrong source kind", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Evidence["tenant-evidence"]
			v.Type = "sbom"
			s.Evidence[v.ID] = v
		}, ErrNotFound},
		{"missing release", func(s *MemoryUnitOfWorkSnapshot) { delete(s.Releases, "tenant-release") }, ErrNotFound},
		{"conflicting source release", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Evidence["tenant-evidence"]
			v.ReleaseID = "foreign-release"
			s.Evidence[v.ID] = v
		}, ErrNotFound},
		{"foreign source", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Evidence["tenant-evidence"]
			v.TenantID = "foreign"
			s.Evidence[v.ID] = v
		}, ErrNotFound},
		{"oversized release coordinate", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.VulnerabilityScans["tenant-scan"]
			v.ReleaseID = strings.Repeat("x", 1025)
			s.VulnerabilityScans[v.ID] = v
		}, ErrValidation},
		{"duplicate finding", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.VulnerabilityScans["tenant-scan"]
			v.Findings = append(v.Findings, v.Findings[0])
			s.VulnerabilityScans[v.ID] = v
		}, ErrConflict},
		{"duplicate scan", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.VulnerabilityScans["tenant-scan"]
			v.ID = "second"
			s.VulnerabilityScans[v.ID] = v
		}, ErrConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, tx := memoryGovernanceReadFixture(t)
			reader, ok := tx.Repositories().Risk.(riskapp.VulnerabilityWorkflowReader)
			if !ok {
				t.Fatal("memory Risk lacks workflow reader")
			}
			tc.change(&tx.state)
			pending, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
			if err != nil {
				t.Fatal(err)
			}
			v, err := reader.ReadWorkflowFinding(t.Context(), "tenant", "tenant-finding")
			if !errors.Is(err, tc.want) || v != (riskapp.GovernanceSubjectReference{}) {
				t.Fatal("invalid workflow coordinates disclosed", v, err, tc.want)
			}
			if !reflect.DeepEqual(pending, tx.state) {
				t.Fatal("rejected workflow read changed pending data")
			}
		})
	}
}
