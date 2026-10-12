package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func TestMemoryFocusedRedactionWriterRejectsNoncanonicalRowsAndDetachesImmutablePolicy(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	writer, ok := tx.Repositories().Packages.(interface {
		InsertFocusedRedactionProfile(context.Context, packagedomain.RedactionProfile) error
	})
	if !ok {
		t.Fatal("memory packages lack focused redaction writer")
	}
	v := packagedomain.RedactionProfile{ID: "profile", TenantID: "tenant", Name: "Customer", Description: "Review", AllowedTypes: []string{"sbom", "vex"}, ExcludedFields: []string{"api_key", "internal_notes"}, SchemaVersion: packagedomain.RedactionProfileSchemaVersion, CreatedAt: fixedNow()}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, corrupt := range []func(*packagedomain.RedactionProfile){
		func(v *packagedomain.RedactionProfile) { v.Name = " Customer " },
		func(v *packagedomain.RedactionProfile) { v.AllowedTypes = []string{"vex", "sbom"} },
		func(v *packagedomain.RedactionProfile) { v.ExcludedFields = []string{"api_key", "api_key"} },
		func(v *packagedomain.RedactionProfile) { v.Description = "private\x00" },
		func(v *packagedomain.RedactionProfile) {
			v.Name = strings.Repeat("x", packageapp.MaxRedactionProfileTextBytes+1)
		},
		func(v *packagedomain.RedactionProfile) { v.SchemaVersion = "unknown" },
	} {
		bad := v
		corrupt(&bad)
		if err := writer.InsertFocusedRedactionProfile(t.Context(), bad); !errors.Is(err, ErrValidation) {
			t.Fatal("noncanonical redaction accepted", err)
		}
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("invalid profile mutated any state")
	}
	ghost := v
	ghost.TenantID = "unknown"
	if err := writer.InsertFocusedRedactionProfile(t.Context(), ghost); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown tenant profile accepted", err)
	}
	if err := writer.InsertFocusedRedactionProfile(t.Context(), v); err != nil {
		t.Fatal(err)
	}
	v.AllowedTypes[0], v.ExcludedFields[0] = "mutated", "mutated"
	stored := tx.state.RedactionProfiles[v.ID]
	if stored.TenantID != "tenant" || stored.AllowedTypes[0] != "sbom" || stored.ExcludedFields[0] != "api_key" || stored.Description != "Review" || stored.SchemaVersion != packagedomain.RedactionProfileSchemaVersion || stored.CreatedAt != fixedNow() {
		t.Fatal("focused redaction lost or aliased policy")
	}
	valid := packagedomain.RedactionProfile(stored)
	if err := writer.InsertFocusedRedactionProfile(t.Context(), valid); !errors.Is(err, ErrConflict) {
		t.Fatal("profile overwritten", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	valid.ID = "cancelled"
	if err := writer.InsertFocusedRedactionProfile(ctx, valid); !errors.Is(err, context.Canceled) {
		t.Fatal("profile write ignored cancellation", err)
	}
	if _, exists := tx.state.RedactionProfiles[valid.ID]; exists {
		t.Fatal("cancelled profile committed")
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := writer.InsertFocusedRedactionProfile(t.Context(), valid); !errors.Is(err, ErrConflict) {
		t.Fatal("closed profile transaction accepted", err)
	}
}
