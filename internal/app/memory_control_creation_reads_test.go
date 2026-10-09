package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func TestMemoryControlCreationReadsUseCurrentExistenceAndNaturalKeysOnly(t *testing.T) {
	tx, _ := memoryControlsQueryFixture(t)
	reader, ok := tx.Repositories().Controls.(riskapp.ControlCreationReader)
	if !ok {
		t.Fatal("memory control repository lacks focused creation reads")
	}
	templates, ok := tx.Repositories().Controls.(riskapp.ControlTemplateReader)
	if !ok {
		t.Fatal("memory control repository lacks focused template reads")
	}
	f := tx.state.ControlFrameworks["tenant-framework"]
	f.Description = strings.Repeat("unselected", 100000)
	tx.state.ControlFrameworks[f.ID] = f
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.LockControlCreationTenant(t.Context(), "tenant"); err != nil {
		t.Fatal(err)
	}
	if err := templates.LockControlTemplateTenant(t.Context(), "tenant"); err != nil {
		t.Fatal(err)
	}
	if found, err := reader.FrameworkVersionExists(t.Context(), "tenant", f.Slug, f.Version); err != nil || !found {
		t.Fatal("version key missed current framework", err)
	}
	if found, err := reader.ControlFrameworkExists(t.Context(), "tenant", f.ID); err != nil || !found {
		t.Fatal("framework identity missed current parent", err)
	}
	if found, err := reader.ControlFrameworkExists(t.Context(), "tenant", "foreign-framework"); err != nil || found {
		t.Fatal("foreign framework identity accepted", err)
	}
	if found, err := reader.SecurityControlCodeExists(t.Context(), "tenant", f.ID, "BUILD"); err != nil || !found {
		t.Fatal("control natural key missed", err)
	}
	if found, err := reader.SecurityControlCodeExists(t.Context(), "tenant", "foreign-framework", "BUILD"); err != nil || found {
		t.Fatal("foreign code key accepted", err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("existence reads changed state")
	}
	f.TenantID = "foreign"
	tx.state.ControlFrameworks[f.ID] = f
	if found, err := reader.SecurityControlCodeExists(t.Context(), "tenant", f.ID, "BUILD"); err != nil || found {
		t.Fatal("code accepted foreign current framework", err)
	}
	if found, err := reader.FrameworkVersionExists(t.Context(), "tenant", strings.Repeat("s", 1024), "v"); !errors.Is(err, ErrValidation) || found {
		t.Fatal("oversized version key accepted", err)
	}
	var nilContext context.Context
	if err := reader.LockControlCreationTenant(nilContext, "tenant"); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reader.ControlFrameworkExists(ctx, "tenant", f.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := templates.LockControlTemplateTenant(t.Context(), "tenant"); err == nil {
		t.Fatal("closed creation transaction accepted")
	}
}
