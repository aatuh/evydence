package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func memoryDiffReadFixture(t *testing.T) (*memoryUnitOfWork, evidenceapp.SBOMDiffReader, evidenceapp.ContractDiffReader) {
	t.Helper()
	_, tx := memoryMembershipReadFixture(t)
	for _, tenant := range []string{"tenant", "foreign"} {
		e := domain.EvidenceItem{ID: tenant + "-sbom-source", TenantID: tenant, Type: "sbom", ProductID: tenant + "-product", ProjectID: tenant + "-project", ReleaseID: tenant + "-release", SubjectRefs: []domain.SubjectRef{{Type: "artifact", ID: tenant + "-artifact"}}}
		tx.state.Evidence[e.ID] = e
		tx.state.Artifacts[tenant+"-artifact"] = domain.Artifact{ID: tenant + "-artifact", TenantID: tenant}
		tx.state.SBOMs[tenant+"-sbom"] = domain.SBOM{ID: tenant + "-sbom", TenantID: tenant, EvidenceID: e.ID, ReleaseID: e.ReleaseID, ArtifactID: tenant + "-artifact", ComponentCount: 1, Components: []domain.SBOMComponent{{Identity: "identity", Name: "one", Version: "1", PURL: "pkg:generic/one@1"}}}
		e.ID, e.Type, e.SubjectRefs = tenant+"-contract-source", "openapi_contract", nil
		tx.state.Evidence[e.ID] = e
		tx.state.OpenAPIContracts[tenant+"-contract"] = domain.OpenAPIContract{ID: tenant + "-contract", TenantID: tenant, EvidenceID: e.ID, ProductID: e.ProductID, ReleaseID: e.ReleaseID, Hash: "sha256:" + strings.Repeat("a", 64), PathCount: 1, Version: "private", Operations: []domain.OpenAPIOperation{{Path: "/items", Method: "GET", OperationID: "listItems", RequiredRequestFields: []string{"name"}, ResponseStatuses: []string{"200"}}}}
	}
	s, ok := tx.Repositories().Evidence.(evidenceapp.SBOMDiffReader)
	if !ok {
		t.Fatal("memory evidence lacks focused SBOM diff reads")
	}
	c, ok := tx.Repositories().Evidence.(evidenceapp.ContractDiffReader)
	if !ok {
		t.Fatal("memory evidence lacks focused contract diff reads")
	}
	return tx, s, c
}

func TestMemoryDiffReadersUseCurrentCoherentSubjectsAndDetachedBoundedProjections(t *testing.T) {
	tx, s, c := memoryDiffReadFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := s.ReadSBOMDiffSubject(t.Context(), "tenant", "tenant-sbom")
	want := evidenceapp.SBOMDiffSubject{ID: "tenant-sbom", TenantID: "tenant", EvidenceID: "tenant-sbom-source", Resources: application.ResourceReferences{ProductID: "tenant-product", ProjectID: "tenant-project", ReleaseID: "tenant-release", ArtifactID: "tenant-artifact"}}
	if err != nil || subject != want {
		t.Fatal("SBOM subject lost current coordinates", subject, err)
	}
	components, err := s.ReadSBOMDiffComponents(t.Context(), "tenant", subject.ID)
	if err != nil || !reflect.DeepEqual(components, []evidencedomain.SBOMComponent{{Identity: "identity", Name: "one", Version: "1", PURL: "pkg:generic/one@1"}}) {
		t.Fatal("component projection changed", components, err)
	}
	components[0].Name = "mutated"
	contractSubject, err := c.ReadContractDiffSubject(t.Context(), "tenant", "tenant-contract")
	if err != nil || contractSubject != (evidenceapp.ContractDiffSubject{ID: "tenant-contract", TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", EvidenceID: "tenant-contract-source"}) {
		t.Fatal("contract subject changed", contractSubject, err)
	}
	contract, err := c.ReadContractDiffProjection(t.Context(), "tenant", contractSubject.ID)
	wantContract := evidencedomain.OpenAPIContract{ID: contractSubject.ID, TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", EvidenceID: "tenant-contract-source", Hash: "sha256:" + strings.Repeat("a", 64), PathCount: 1, Operations: []evidencedomain.OpenAPIOperation{{Path: "/items", Method: "GET", OperationID: "listItems", RequiredRequestFields: []string{"name"}, ResponseStatuses: []string{"200"}}}}
	if err != nil || !reflect.DeepEqual(contract, wantContract) {
		t.Fatal("bounded contract transferred unrelated fields or lost operations", contract, err)
	}
	contract.Operations[0].RequiredRequestFields[0], contract.Operations[0].ResponseStatuses[0] = "mutated", "500"
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("reads or caller mutation changed repository")
	}
	// Coordinate-only preflight must ignore invalid/oversized projection data.
	b := tx.state.SBOMs[subject.ID]
	b.ComponentCount = -1
	b.Components = make([]domain.SBOMComponent, evidenceapp.SBOMDiffComponentLimit+1)
	tx.state.SBOMs[b.ID] = b
	o := tx.state.OpenAPIContracts[contractSubject.ID]
	o.Hash = strings.Repeat("x", 72)
	o.Operations = []domain.OpenAPIOperation{{Path: strings.Repeat("x", evidenceapp.ContractDiffProjectionByteLimit+1)}}
	tx.state.OpenAPIContracts[o.ID] = o
	if got, err := s.ReadSBOMDiffSubject(t.Context(), "tenant", b.ID); err != nil || got != subject {
		t.Fatal("SBOM preflight inspected components", err)
	}
	if got, err := c.ReadContractDiffSubject(t.Context(), "tenant", o.ID); err != nil || got != contractSubject {
		t.Fatal("contract preflight inspected operations/hash", err)
	}
	if got, err := s.ReadSBOMDiffComponents(t.Context(), "tenant", b.ID); !errors.Is(err, ErrValidation) || got != nil {
		t.Fatal("oversized components transferred", err)
	}
	if got, err := c.ReadContractDiffProjection(t.Context(), "tenant", o.ID); !errors.Is(err, ErrValidation) || !reflect.DeepEqual(got, evidencedomain.OpenAPIContract{}) {
		t.Fatal("oversized operations transferred", err)
	}
	// Exercise each projection budget independently of invalid count/hash.
	b.ComponentCount = len(b.Components)
	tx.state.SBOMs[b.ID] = b
	if got, err := s.ReadSBOMDiffComponents(t.Context(), "tenant", b.ID); !errors.Is(err, ErrValidation) || got != nil {
		t.Fatal("component cap depended on invalid count", err)
	}
	o.Hash = "sha256:" + strings.Repeat("a", 64)
	tx.state.OpenAPIContracts[o.ID] = o
	if got, err := c.ReadContractDiffProjection(t.Context(), "tenant", o.ID); !errors.Is(err, ErrValidation) || !reflect.DeepEqual(got, evidencedomain.OpenAPIContract{}) {
		t.Fatal("operation byte bound depended on invalid hash", err)
	}
	b.Components = []domain.SBOMComponent{{Name: "one"}}
	b.ComponentCount = 2
	tx.state.SBOMs[b.ID] = b
	if got, err := s.ReadSBOMDiffComponents(t.Context(), "tenant", b.ID); !errors.Is(err, ErrValidation) || got != nil {
		t.Fatal("component count mismatch transferred", err)
	}
	// A build resolves ownership, not an absent source SBOM release.
	tx.state.BuildRuns["build"] = domain.BuildRun{ID: "build", TenantID: "tenant", ProjectID: "tenant-project", ReleaseID: "tenant-release"}
	e := tx.state.Evidence[b.EvidenceID]
	e.ReleaseID, e.BuildID = "", "build"
	tx.state.Evidence[e.ID] = e
	b.ReleaseID = ""
	tx.state.SBOMs[b.ID] = b
	if got, err := s.ReadSBOMDiffSubject(t.Context(), "tenant", b.ID); err != nil || got.Resources.ReleaseID != "" || got.Resources.ProjectID != "tenant-project" {
		t.Fatal("build invented parsed SBOM release", got, err)
	}
}

func TestMemoryDiffReadersRejectForeignIncoherentAndInvalidCoordinates(t *testing.T) {
	tx, s, c := memoryDiffReadFixture(t)
	for _, id := range []string{"missing", "foreign-sbom"} {
		if v, err := s.ReadSBOMDiffSubject(t.Context(), "tenant", id); !errors.Is(err, ErrNotFound) || v != (evidenceapp.SBOMDiffSubject{}) {
			t.Fatal("foreign SBOM returned", v, err)
		}
	}
	for _, id := range []string{"missing", "foreign-contract"} {
		if v, err := c.ReadContractDiffSubject(t.Context(), "tenant", id); !errors.Is(err, ErrNotFound) || v != (evidenceapp.ContractDiffSubject{}) {
			t.Fatal("foreign contract returned", v, err)
		}
	}
	for _, id := range []string{"missing", "foreign-release"} {
		if v, err := c.ReadContractDiffRelease(t.Context(), "tenant", id); !errors.Is(err, ErrNotFound) || v != (evidenceapp.ContractDiffRelease{}) {
			t.Fatal("foreign release returned", v, err)
		}
	}
	baseline, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, corrupt := range []func(*MemoryUnitOfWorkSnapshot){
		func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Evidence["tenant-sbom-source"]
			v.Type = "openapi_contract"
			s.Evidence[v.ID] = v
		},
		func(s *MemoryUnitOfWorkSnapshot) {
			v := s.SBOMs["tenant-sbom"]
			v.ReleaseID = "foreign-release"
			s.SBOMs[v.ID] = v
		},
		func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Evidence["tenant-sbom-source"]
			v.SubjectRefs = append(v.SubjectRefs, domain.SubjectRef{Type: "artifact", ID: "other"})
			s.Evidence[v.ID] = v
		},
		func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Artifacts["tenant-artifact"]
			v.TenantID = "foreign"
			s.Artifacts[v.ID] = v
		},
		func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Projects["tenant-project"]
			v.ProductID = "foreign-product"
			s.Projects[v.ID] = v
		},
	} {
		tx.state, err = cloneMemoryUnitOfWorkSnapshot(baseline)
		if err != nil {
			t.Fatal(err)
		}
		corrupt(&tx.state)
		if v, err := s.ReadSBOMDiffSubject(t.Context(), "tenant", "tenant-sbom"); err == nil || v != (evidenceapp.SBOMDiffSubject{}) {
			t.Fatal("incoherent SBOM returned", v, err)
		}
	}
	for _, corrupt := range []func(*MemoryUnitOfWorkSnapshot){
		func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Evidence["tenant-contract-source"]
			v.Type = "sbom"
			s.Evidence[v.ID] = v
		},
		func(s *MemoryUnitOfWorkSnapshot) {
			v := s.OpenAPIContracts["tenant-contract"]
			v.ProductID = "foreign-product"
			s.OpenAPIContracts[v.ID] = v
		},
		func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Evidence["tenant-contract-source"]
			v.ReleaseID = "foreign-release"
			s.Evidence[v.ID] = v
		},
		func(s *MemoryUnitOfWorkSnapshot) { delete(s.Products, "tenant-product") },
	} {
		tx.state, err = cloneMemoryUnitOfWorkSnapshot(baseline)
		if err != nil {
			t.Fatal(err)
		}
		corrupt(&tx.state)
		if v, err := c.ReadContractDiffSubject(t.Context(), "tenant", "tenant-contract"); err == nil || v != (evidenceapp.ContractDiffSubject{}) {
			t.Fatal("incoherent contract returned", v, err)
		}
	}
	tx.state, err = cloneMemoryUnitOfWorkSnapshot(baseline)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", " padded ", strings.Repeat("x", 1025), "bad\x00"} {
		if v, err := s.ReadSBOMDiffSubject(t.Context(), "tenant", id); !errors.Is(err, ErrValidation) || v != (evidenceapp.SBOMDiffSubject{}) {
			t.Fatal("invalid identity accepted", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := c.ReadContractDiffProjection(ctx, "tenant", "tenant-contract"); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, evidencedomain.OpenAPIContract{}) {
		t.Fatal("cancelled projection returned", err)
	}
	var nilCtx context.Context // Deliberately test rejection of the zero context.
	if v, err := s.ReadSBOMDiffSubject(nilCtx, "tenant", "tenant-sbom"); !errors.Is(err, ErrValidation) || v != (evidenceapp.SBOMDiffSubject{}) {
		t.Fatal("nil context accepted", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReadContractDiffRelease(t.Context(), "tenant", "tenant-release"); !errors.Is(err, ErrConflict) {
		t.Fatal("closed transaction read", err)
	}
}
