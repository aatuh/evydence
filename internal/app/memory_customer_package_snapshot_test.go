package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func TestMemoryCustomerPackageSnapshotUsesOneCurrentTypedViewAndPreservesAllSections(t *testing.T) {
	tx := memoryCustomerGovernanceFixture(t)
	p := domain.RedactionProfile{ID: "profile", TenantID: "tenant", Name: "Customer", AllowedTypes: []string{"sbom", "vex", "vulnerability_decision"}, ExcludedFields: []string{"internal_notes"}, SchemaVersion: "historical.v1", CreatedAt: fixedNow()}
	tx.state.RedactionProfiles[p.ID] = p
	reader, ok := tx.Repositories().Packages.(packageapp.CustomerPackageSnapshotReader)
	if !ok {
		t.Fatal("memory packages lack complete focused snapshot capability")
	}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	v, err := reader.ReadCustomerPackageCreationSnapshot(t.Context(), "tenant", "tenant-product", "tenant-release", p.ID, fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	s := v.Snapshot
	if s.SnapshotVersion != packageapp.CustomerPackageSnapshotVersion || s.TenantID != "tenant" || s.ProductID != "tenant-product" || s.ReleaseID != "tenant-release" || !reflect.DeepEqual(v.Profile, packagedomain.RedactionProfile(p)) {
		t.Fatal("snapshot roots/policy changed", v)
	}
	if s.Organization == nil || s.Artifacts == nil || len(s.Evidence) == 0 || len(s.SBOMs) != 1 || len(s.VulnerabilityScans) != 1 || len(s.VEXDocuments) != 1 || s.APIContracts == nil || len(s.Decisions) != 1 || len(s.Approvals) != 2 || len(s.Exceptions) != 1 || len(s.Waivers) != 2 || len(s.AnswerLibrary) != 3 || len(s.ReadinessChecks) == 0 || s.Provenance == nil || s.ObjectLockProofs == nil || s.VerificationMaterial["audit_chain"].(map[string]any)["result"] != "passed" {
		t.Fatal("complete public sections missing", s)
	}
	v.Profile.AllowedTypes[0] = "changed"
	s.Product["name"] = "changed"
	s.VulnerabilityScans[0]["summary"].(map[string]int)["critical"] = 99
	s.AnswerLibrary[2]["evidence_ids"].([]string)[0] = "changed"
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("snapshot/caller mutation changed current rows")
	}
	product := tx.state.Products["tenant-product"]
	product.Name = "Fresh"
	tx.state.Products[product.ID] = product
	profile := tx.state.RedactionProfiles[p.ID]
	profile.Description = "Fresh policy"
	tx.state.RedactionProfiles[p.ID] = profile
	fresh, err := reader.ReadCustomerPackageCreationSnapshot(t.Context(), "tenant", "tenant-product", "tenant-release", p.ID, fixedNow())
	if err != nil || fresh.Snapshot.Product["name"] != "Fresh" || fresh.Profile.Description != "Fresh policy" {
		t.Fatal("snapshot used a stale aggregate/profile cache", err)
	}
}

func TestMemoryCustomerPackageSnapshotRejectsIncompleteInvalidOrClosedViewsWithoutPartialResults(t *testing.T) {
	tx := memoryCustomerCatalogFixture(t)
	p := domain.RedactionProfile{ID: "profile", TenantID: "tenant", Name: "Customer", AllowedTypes: []string{"sbom"}, SchemaVersion: "profile.v1", CreatedAt: fixedNow()}
	tx.state.RedactionProfiles[p.ID] = p
	reader, ok := tx.Repositories().Packages.(packageapp.CustomerPackageSnapshotReader)
	if !ok {
		t.Fatal("complete snapshot capability missing")
	}
	for _, scope := range [][4]string{{"tenant", "foreign-product", "", p.ID}, {"foreign", "tenant-product", "tenant-release", p.ID}, {"tenant", "tenant-product", "sibling-release", p.ID}, {"tenant", "tenant-product", "tenant-release", "missing"}} {
		v, err := reader.ReadCustomerPackageCreationSnapshot(t.Context(), scope[0], scope[1], scope[2], scope[3], fixedNow())
		if !errors.Is(err, ErrNotFound) || !reflect.DeepEqual(v, packageapp.CustomerPackageCreationSnapshot{}) {
			t.Fatal("foreign/missing snapshot returned partial data", scope, err)
		}
	}
	product := tx.state.Products["tenant-product"]
	product.Name = strings.Repeat("x", packageapp.MaxCustomerPackageManifestBytes+1)
	tx.state.Products[product.ID] = product
	if v, err := reader.ReadCustomerPackageCreationSnapshot(t.Context(), "tenant", product.ID, "tenant-release", p.ID, fixedNow()); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, packageapp.CustomerPackageCreationSnapshot{}) {
		t.Fatal("oversized selected metadata returned partial snapshot", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := reader.ReadCustomerPackageCreationSnapshot(ctx, "tenant", product.ID, "tenant-release", p.ID, fixedNow()); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, packageapp.CustomerPackageCreationSnapshot{}) {
		t.Fatal("cancelled complete snapshot returned", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if v, err := reader.ReadCustomerPackageCreationSnapshot(t.Context(), "tenant", product.ID, "tenant-release", p.ID, fixedNow()); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, packageapp.CustomerPackageCreationSnapshot{}) {
		t.Fatal("closed snapshot reader returned data", err)
	}
}
