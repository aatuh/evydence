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

func memoryCustomerAccessFixture(t *testing.T) *memoryUnitOfWork {
	t.Helper()
	_, tx := memoryMembershipReadFixture(t)
	p := domain.CustomerSecurityPackage{ID: "package", TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", RedactionProfileID: "profile", Title: "Review", State: "generated", Manifest: map[string]any{"evidence_ids": []string{"evidence"}, "exact": json.Number("9007199254740993"), "internal_notes": "private-frozen-marker"}, ManifestHash: "sha256:" + strings.Repeat("a", 64), ExpiresAt: fixedNow().Add(time.Hour), AccessCount: 4, SchemaVersion: "package.v1", CreatedAt: fixedNow()}
	tx.state.CustomerPackages[p.ID] = p
	return tx
}

func TestMemoryCustomerPackageAccessReadsDetachedBoundedCurrentRowsAndPreservesExactNumbers(t *testing.T) {
	tx := memoryCustomerAccessFixture(t)
	r := tx.Repositories().Packages
	p, err := r.GetCustomerSecurityPackageForUpdate(t.Context(), "tenant", "package")
	if err != nil {
		t.Fatal(err)
	}
	if n, ok := p.Manifest["exact"].(json.Number); !ok || n.String() != "9007199254740993" {
		t.Fatal("access rounded frozen manifest number", p.Manifest)
	}
	p.Manifest["internal_notes"] = "changed"
	if tx.state.CustomerPackages[p.ID].Manifest["internal_notes"] != "private-frozen-marker" {
		t.Fatal("point read aliases frozen manifest")
	}
	for _, change := range []func(*MemoryUnitOfWorkSnapshot){
		func(s *MemoryUnitOfWorkSnapshot) {
			p := s.CustomerPackages["package"]
			p.ProductID = "foreign-product"
			s.CustomerPackages[p.ID] = p
		},
		func(s *MemoryUnitOfWorkSnapshot) {
			p := s.Products["tenant-product"]
			p.ID = "wrong-identity"
			s.Products["tenant-product"] = p
		},
		func(s *MemoryUnitOfWorkSnapshot) {
			p := s.Releases["tenant-release"]
			p.ProductID = "foreign-product"
			s.Releases[p.ID] = p
		},
		func(s *MemoryUnitOfWorkSnapshot) {
			p := s.CustomerPackages["package"]
			p.ID = "wrong-identity"
			s.CustomerPackages["package"] = p
		},
	} {
		tx := memoryCustomerAccessFixture(t)
		change(&tx.state)
		p, err := tx.Repositories().Packages.GetCustomerSecurityPackageForUpdate(t.Context(), "tenant", "package")
		if !errors.Is(err, ErrNotFound) || !reflect.DeepEqual(p, domain.CustomerSecurityPackage{}) {
			t.Fatal("incoherent current ownership accepted", p, err)
		}
	}
	if p, err := r.GetCustomerSecurityPackageForUpdate(t.Context(), "foreign", "package"); !errors.Is(err, ErrNotFound) || !reflect.DeepEqual(p, domain.CustomerSecurityPackage{}) {
		t.Fatal("foreign package read returned data", err)
	}
}

func TestMemoryCustomerPackageAccessCounterUpdateNeverRewritesFrozenFields(t *testing.T) {
	tx := memoryCustomerAccessFixture(t)
	r := tx.Repositories().Packages
	previous, err := r.GetCustomerSecurityPackageForUpdate(t.Context(), "tenant", "package")
	if err != nil {
		t.Fatal(err)
	}
	current := previous
	current.AccessCount++
	current.Title, current.ProductID, current.RedactionProfileID, current.DistributionWatermark, current.SchemaVersion = "changed", "foreign-product", "changed", "changed", "changed"
	current.Manifest = map[string]any{"evidence_ids": []string{"sanitized"}}
	if err := r.UpdateCustomerSecurityPackageAccess(t.Context(), previous, current); err != nil {
		t.Fatal(err)
	}
	want := tx.state.CustomerPackages["package"]
	if want.AccessCount != 5 || want.Title != "Review" || want.ProductID != "tenant-product" || want.RedactionProfileID != "profile" || want.DistributionWatermark != "" || want.SchemaVersion != "package.v1" || want.Manifest["internal_notes"] != "private-frozen-marker" {
		t.Fatal("counter write replaced frozen fields", want)
	}
	if err := r.UpdateCustomerSecurityPackageAccess(t.Context(), previous, current); !errors.Is(err, ErrConflict) {
		t.Fatal("stale counter accepted", err)
	}
}

func TestMemoryCustomerPackageAccessKeepsFrozenNumbersThroughInsertCommitAndSnapshot(t *testing.T) {
	factory, tx := memoryMembershipReadFixture(t)
	tx.state.RedactionProfiles["profile"] = domain.RedactionProfile{ID: "profile", TenantID: "tenant"}
	p := domain.CustomerSecurityPackage{ID: "package", TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", RedactionProfileID: "profile", Title: "Review", State: "generated", Manifest: map[string]any{"exact": json.Number("9007199254740993"), "nested": map[string]any{"decimal": json.Number("123456789.123456789")}}, ManifestHash: "sha256:" + strings.Repeat("a", 64), ExpiresAt: fixedNow().Add(time.Hour), SchemaVersion: "package.v1", CreatedAt: fixedNow()}
	if err := tx.Repositories().Packages.InsertCustomerSecurityPackage(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	p.Manifest["exact"] = "caller mutation"
	p.Manifest["nested"].(map[string]any)["decimal"] = "caller mutation"
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	check := func(p domain.CustomerSecurityPackage) {
		t.Helper()
		if n, ok := p.Manifest["exact"].(json.Number); !ok || n.String() != "9007199254740993" {
			t.Fatal("stored integer was rounded or aliased", p.Manifest)
		}
		if n, ok := p.Manifest["nested"].(map[string]any)["decimal"].(json.Number); !ok || n.String() != "123456789.123456789" {
			t.Fatal("stored decimal was rounded or aliased", p.Manifest)
		}
	}
	check(snapshot.CustomerPackages["package"])
	snapshot.CustomerPackages["package"].Manifest["exact"] = "snapshot mutation"
	unit, err := factory.BeginUnitOfWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unit.Rollback(t.Context()) }()
	read, err := unit.Repositories().Packages.GetCustomerSecurityPackageForUpdate(t.Context(), "tenant", "package")
	if err != nil {
		t.Fatal(err)
	}
	check(read)
}

func TestMemoryCustomerPackageAccessRejectsInvalidMetadataAndClosedViewsWithoutPartialData(t *testing.T) {
	for _, change := range []func(*domain.CustomerSecurityPackage){
		func(p *domain.CustomerSecurityPackage) { p.Title = strings.Repeat("x", 4097) },
		func(p *domain.CustomerSecurityPackage) {
			p.Manifest = map[string]any{"large": strings.Repeat("x", packageapp.MaxCustomerPackageManifestBytes+1)}
		},
		func(p *domain.CustomerSecurityPackage) { p.Manifest = nil },
	} {
		tx := memoryCustomerAccessFixture(t)
		p := tx.state.CustomerPackages["package"]
		change(&p)
		tx.state.CustomerPackages[p.ID] = p
		got, err := tx.Repositories().Packages.GetCustomerSecurityPackageForUpdate(t.Context(), "tenant", p.ID)
		if !errors.Is(err, ErrConflict) || !reflect.DeepEqual(got, domain.CustomerSecurityPackage{}) {
			t.Fatal("invalid selected projection returned data", err)
		}
	}
	tx := memoryCustomerAccessFixture(t)
	r := tx.Repositories().Packages
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if p, err := r.GetCustomerSecurityPackageForUpdate(ctx, "tenant", "package"); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(p, domain.CustomerSecurityPackage{}) {
		t.Fatal("cancelled read returned package", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if p, err := r.GetCustomerSecurityPackageForUpdate(t.Context(), "tenant", "package"); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(p, domain.CustomerSecurityPackage{}) {
		t.Fatal("closed reader returned data", err)
	}
}
