package app

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func memoryCustomerCatalogFixture(t *testing.T) *memoryUnitOfWork {
	t.Helper()
	_, tx := memoryMembershipReadFixture(t)
	s := &tx.state
	for id, p := range s.Products {
		p.Name, p.Slug, p.CreatedAt = "Product", "product", fixedNow()
		s.Products[id] = p
	}
	for id, r := range s.Releases {
		r.Version, r.State, r.CreatedAt = "1", "draft", fixedNow()
		s.Releases[id] = r
	}
	for id, o := range s.Organizations {
		o.Name, o.Status, o.CreatedAt = "Organization", "active", fixedNow()
		s.Organizations[id] = o
	}
	s.Products["sibling"] = domain.Product{ID: "sibling", TenantID: "tenant", CreatedAt: fixedNow()}
	s.Projects["sibling-project"] = domain.Project{ID: "sibling-project", TenantID: "tenant", ProductID: "sibling"}
	s.Releases["other-release"] = domain.Release{ID: "other-release", TenantID: "tenant", ProductID: "tenant-product", State: "draft", CreatedAt: fixedNow()}
	s.Releases["sibling-release"] = domain.Release{ID: "sibling-release", TenantID: "tenant", ProductID: "sibling", State: "draft", CreatedAt: fixedNow()}
	for _, id := range []string{"artifact-build", "artifact-evidence", "artifact-sbom", "artifact-vex", "artifact-wrong", "artifact-sibling", "artifact-foreign"} {
		tenant := "tenant"
		if id == "artifact-foreign" {
			tenant = "foreign"
		}
		s.Artifacts[id] = domain.Artifact{ID: id, TenantID: tenant, Name: id, MediaType: "application/json", Size: 4611686018427387907, Digest: "sha256:" + id, CreatedAt: fixedNow()}
	}
	e := domain.EvidenceItem{ID: "selected", TenantID: "tenant", ProductID: "tenant-product", ProjectID: "tenant-project", ReleaseID: "tenant-release", Type: "document", Title: "private-title-marker", PayloadRef: "private-object-marker", Metadata: map[string]any{"token": "private-token-marker"}, SubjectRefs: []domain.SubjectRef{{Type: "artifact", ID: "artifact-evidence"}, {Type: "artifact", ID: "artifact-foreign"}}}
	s.Evidence[e.ID] = e
	for _, change := range []struct{ id, tenant, product, project, release string }{
		{"product-only", "tenant", "tenant-product", "", ""},
		{"other", "tenant", "tenant-product", "", "other-release"},
		{"bad-project", "tenant", "tenant-product", "sibling-project", "tenant-release"},
		{"bad-release", "tenant", "tenant-product", "", "sibling-release"},
		{"foreign-evidence", "foreign", "tenant-product", "", "tenant-release"},
		{"unscoped", "tenant", "", "", ""},
	} {
		v := e
		v.ID, v.TenantID, v.ProductID, v.ProjectID, v.ReleaseID = change.id, change.tenant, change.product, change.project, change.release
		s.Evidence[v.ID] = v
	}
	s.SBOMs["sbom"] = domain.SBOM{ID: "sbom", TenantID: "tenant", EvidenceID: "selected", ReleaseID: "tenant-release", ArtifactID: "artifact-sbom"}
	s.VEXDocuments["vex"] = domain.VEXDocument{ID: "vex", TenantID: "tenant", EvidenceID: "selected", ReleaseID: "tenant-release", ArtifactID: "artifact-vex"}
	s.SBOMs["bad-sbom"] = domain.SBOM{ID: "bad-sbom", TenantID: "tenant", EvidenceID: "bad-project", ReleaseID: "tenant-release", ArtifactID: "artifact-sibling"}
	s.BuildRuns["build"] = domain.BuildRun{ID: "build", TenantID: "tenant", ProjectID: "tenant-project", ReleaseID: "tenant-release", EnvironmentHash: "private-environment-marker", Outputs: []domain.BuildOutput{{ArtifactID: "artifact-build", Digest: "sha256:artifact-build"}, {ArtifactID: "artifact-wrong", Digest: "sha256:not-matching"}, {ArtifactID: "artifact-foreign", Digest: "sha256:artifact-foreign"}}}
	b := s.BuildRuns["build"]
	b.ID, b.ProjectID, b.Outputs = "bad-build", "sibling-project", []domain.BuildOutput{{ArtifactID: "artifact-sibling", Digest: "sha256:artifact-sibling"}}
	s.BuildRuns[b.ID] = b
	return tx
}

func TestMemoryCustomerPackageCatalogSelectsCoherentPublicMetadata(t *testing.T) {
	tx := memoryCustomerCatalogFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	budget := &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	v, err := readMemoryCustomerPackageCatalog(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", budget)
	if err != nil {
		t.Fatal(err)
	}
	if v.Tenant["id"] != "tenant" || v.Product["id"] != "tenant-product" || v.Release["id"] != "tenant-release" || v.Release["created_at"] != fixedNow().UTC().Format(time.RFC3339) || !reflect.DeepEqual(v.Evidence, []packageapp.EvidenceReference{{ID: "selected", Type: "document"}}) {
		t.Fatal("catalog coordinates or evidence changed", v)
	}
	if _, exists := v.Release["approved_at"]; exists {
		t.Fatal("absent time was not omitted")
	}
	var ids []string
	for _, a := range v.Artifacts {
		ids = append(ids, a["id"].(string))
		if a["size"] != int64(4611686018427387907) {
			t.Fatal("artifact size lost integer precision", a)
		}
	}
	if strings.Join(ids, ",") != "artifact-build,artifact-evidence,artifact-sbom,artifact-vex" {
		t.Fatal("artifact ownership/digest selection changed", ids)
	}
	orgs := v.Organization["records"].([]map[string]any)
	if len(orgs) != 1 || orgs[0]["id"] != "tenant-org" || len(v.Organization["limitations"].([]string)) != 1 || budget.remainingBytes >= packageapp.MaxCustomerPackageManifestBytes {
		t.Fatal("organization selection, limitation or shared budget missing", v.Organization)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, excluded := range []string{"private-", "foreign", "sibling", "artifact-wrong", "bad-"} {
		if strings.Contains(string(raw), excluded) {
			t.Fatal("out-of-scope/private metadata projected", excluded)
		}
	}
	v.Tenant["name"], v.Product["name"], v.Release["version"], v.Artifacts[0]["name"], orgs[0]["name"] = "changed", "changed", "changed", "changed", "changed"
	if !reflect.DeepEqual(tx.state, before) {
		t.Fatal("read or caller mutation changed repository rows")
	}
	product, err := readMemoryCustomerPackageCatalog(t.Context(), &tx.state, "tenant", "tenant-product", "", &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || !reflect.DeepEqual(product.Evidence, []packageapp.EvidenceReference{{ID: "other", Type: "document"}, {ID: "product-only", Type: "document"}, {ID: "selected", Type: "document"}}) || len(product.Artifacts) != 0 || len(product.Release) != 0 {
		t.Fatal("product-only scope or compatibility changed", product, err)
	}
}

func TestMemoryCustomerPackageCatalogRejectsScopeBudgetAndCancellationWithoutPartialResults(t *testing.T) {
	tx := memoryCustomerCatalogFixture(t)
	for _, coordinates := range [][3]string{{"tenant", "foreign-product", ""}, {"foreign", "tenant-product", "tenant-release"}, {"tenant", "tenant-product", "sibling-release"}, {"unknown", "tenant-product", ""}} {
		budget := &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
		v, err := readMemoryCustomerPackageCatalog(t.Context(), &tx.state, coordinates[0], coordinates[1], coordinates[2], budget)
		if !errors.Is(err, ErrNotFound) || !reflect.DeepEqual(v, memoryCustomerPackageCatalog{}) || budget.remainingBytes != packageapp.MaxCustomerPackageManifestBytes {
			t.Fatal("foreign/unknown scope returned partial data or spent budget", coordinates, err)
		}
	}
	for _, change := range []struct {
		name string
		edit func(*MemoryUnitOfWorkSnapshot)
	}{
		{"root text", func(s *MemoryUnitOfWorkSnapshot) {
			p := s.Products["tenant-product"]
			p.Name = strings.Repeat("x", packageapp.MaxCustomerPackageManifestBytes+1)
			s.Products[p.ID] = p
		}},
		{"artifact time", func(s *MemoryUnitOfWorkSnapshot) {
			a := s.Artifacts["artifact-evidence"]
			a.CreatedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			s.Artifacts[a.ID] = a
		}},
		{"negative size", func(s *MemoryUnitOfWorkSnapshot) {
			a := s.Artifacts["artifact-evidence"]
			a.Size = -1
			s.Artifacts[a.ID] = a
		}},
		{"reference limit", func(s *MemoryUnitOfWorkSnapshot) {
			e := s.Evidence["selected"]
			e.SubjectRefs = make([]domain.SubjectRef, packageapp.MaxSecurityReviewEvidenceIDs+1)
			s.Evidence[e.ID] = e
		}},
		{"output limit", func(s *MemoryUnitOfWorkSnapshot) {
			b := s.BuildRuns["build"]
			b.Outputs = make([]domain.BuildOutput, packageapp.MaxSecurityReviewEvidenceIDs+1)
			s.BuildRuns[b.ID] = b
		}},
		{"invalid UTF8", func(s *MemoryUnitOfWorkSnapshot) {
			p := s.Products["tenant-product"]
			p.Name = "\xff"
			s.Products[p.ID] = p
		}},
		{"reference bytes", func(s *MemoryUnitOfWorkSnapshot) {
			e := s.Evidence["selected"]
			e.SubjectRefs = []domain.SubjectRef{{Type: "artifact", ID: strings.Repeat("x", packageapp.MaxCustomerPackageManifestBytes+1)}}
			s.Evidence[e.ID] = e
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			tx := memoryCustomerCatalogFixture(t)
			change.edit(&tx.state)
			budget := &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
			v, err := readMemoryCustomerPackageCatalog(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", budget)
			if !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, memoryCustomerPackageCatalog{}) || budget.remainingBytes != packageapp.MaxCustomerPackageManifestBytes {
				t.Fatal("invalid selected metadata returned partial data or spent budget", err)
			}
		})
	}
	baseline := &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	if _, err := readMemoryCustomerPackageCatalog(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", baseline); err != nil {
		t.Fatal(err)
	}
	budget := &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes - baseline.remainingBytes - 1}
	initial := budget.remainingBytes
	if v, err := readMemoryCustomerPackageCatalog(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", budget); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, memoryCustomerPackageCatalog{}) || budget.remainingBytes != initial {
		t.Fatal("budget reset between sections or partial budget publication", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := readMemoryCustomerPackageCatalog(ctx, &tx.state, "tenant", "tenant-product", "tenant-release", baseline); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, memoryCustomerPackageCatalog{}) {
		t.Fatal("cancelled snapshot returned", err)
	}
}
