package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func TestMemoryCustomerPackageCreationReadsCurrentScopeAndDetachedHistoricalPolicy(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	reader, ok := tx.Repositories().Packages.(interface {
		LockCustomerPackageCreationScope(context.Context, string, string, string) error
		GetCustomerPackageRedactionProfile(context.Context, string, string) (packagedomain.RedactionProfile, error)
	})
	if !ok {
		t.Fatal("memory packages lack focused customer creation scope/policy reads")
	}
	p := domain.RedactionProfile{ID: "profile", TenantID: "tenant", Name: "Customer", Description: "Historical", AllowedTypes: []string{"vex", "sbom", "sbom"}, ExcludedFields: []string{"token", "api_key"}, SchemaVersion: "historical-profile.v1", CreatedAt: fixedNow()}
	tx.state.RedactionProfiles[p.ID] = p
	// Descriptive catalog metadata is not part of the write guard.
	product := tx.state.Products["tenant-product"]
	product.Name = strings.Repeat("private", 100000)
	tx.state.Products[product.ID] = product
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, release := range []string{"", "tenant-release"} {
		if err := reader.LockCustomerPackageCreationScope(t.Context(), "tenant", "tenant-product", release); err != nil {
			t.Fatal("current ownership guard selected metadata", err)
		}
	}
	got, err := reader.GetCustomerPackageRedactionProfile(t.Context(), "tenant", p.ID)
	if err != nil || !reflect.DeepEqual(got, packagedomain.RedactionProfile(p)) {
		t.Fatal("historical policy normalized or lost fields", got, err)
	}
	got.AllowedTypes[0], got.ExcludedFields[0] = "mutated", "mutated"
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("customer scope/policy read or caller mutation changed storage")
	}
	for _, scope := range []struct{ tenant, product, release string }{{"tenant", "foreign-product", ""}, {"tenant", "tenant-product", "foreign-release"}, {"foreign", "tenant-product", "tenant-release"}, {"unknown", "tenant-product", ""}} {
		if err := reader.LockCustomerPackageCreationScope(t.Context(), scope.tenant, scope.product, scope.release); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign/incoherent scope accepted", err)
		}
	}
	if v, err := reader.GetCustomerPackageRedactionProfile(t.Context(), "foreign", p.ID); !errors.Is(err, ErrNotFound) || !reflect.DeepEqual(v, packagedomain.RedactionProfile{}) {
		t.Fatal("foreign policy returned", err)
	}
	bad := p
	bad.Name = strings.Repeat("x", 65537)
	tx.state.RedactionProfiles[p.ID] = bad
	if v, err := reader.GetCustomerPackageRedactionProfile(t.Context(), "tenant", p.ID); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, packagedomain.RedactionProfile{}) {
		t.Fatal("oversized policy transferred", err)
	}
	tx.state.RedactionProfiles[p.ID] = p
	// Bounds apply to the UTC instant, not its caller-supplied local year.
	bad = p
	bad.CreatedAt = time.Date(1, time.January, 1, 0, 0, 0, 0, time.FixedZone("fixture", 3600))
	tx.state.RedactionProfiles[p.ID] = bad
	if v, err := reader.GetCustomerPackageRedactionProfile(t.Context(), "tenant", p.ID); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, packagedomain.RedactionProfile{}) {
		t.Fatal("out-of-range UTC profile returned", err)
	}
	tx.state.RedactionProfiles[p.ID] = p
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := reader.GetCustomerPackageRedactionProfile(ctx, "tenant", p.ID); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, packagedomain.RedactionProfile{}) {
		t.Fatal("cancelled profile returned", err)
	}
	if err := reader.LockCustomerPackageCreationScope(t.Context(), "tenant", "tenant-product", " padded "); !errors.Is(err, ErrValidation) {
		t.Fatal("malformed release accepted", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := reader.LockCustomerPackageCreationScope(t.Context(), "tenant", "tenant-product", ""); !errors.Is(err, ErrConflict) {
		t.Fatal("closed customer transaction accepted", err)
	}
}
