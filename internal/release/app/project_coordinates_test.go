package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// This fake intentionally cannot load product metadata or unrelated catalogs.
type coordinateOnlyProject struct {
	parent  ProductCoordinates
	current ProductCoordinates
	reads   int
	project releasedomain.Project
	audit   application.AuditEvent
}

func (f *coordinateOnlyProject) ReadProductCoordinates(context.Context, string, string) (ProductCoordinates, error) {
	f.reads++
	if f.reads == 1 {
		return f.parent, nil
	}
	return f.current, nil
}
func (f *coordinateOnlyProject) ExecuteProject(ctx context.Context, fn func(context.Context, ProjectTransaction) error) error {
	return fn(ctx, f)
}
func (f *coordinateOnlyProject) InsertProject(_ context.Context, v releasedomain.Project) error {
	f.project = v
	return nil
}
func (f *coordinateOnlyProject) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	f.audit = v
	return application.AuditReceipt{ID: v.ID}, nil
}

func TestProjectCreationNeedsOnlyCurrentProductCoordinates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*ProductCoordinates)
		want   error
	}{
		{"same coordinates", func(*ProductCoordinates) {}, nil},
		{"slug drift", func(v *ProductCoordinates) { v.Slug = "changed" }, ErrConflict},
		{"foreign tenant", func(v *ProductCoordinates) { v.TenantID = "other" }, ErrNotFound},
		{"wrong product", func(v *ProductCoordinates) { v.ID = "other" }, ErrNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newServiceFixture(t)
			coords := ProductCoordinates{ID: "product", TenantID: f.actor.TenantID, Slug: "product"}
			current := coords
			tc.change(&current)
			tx := &coordinateOnlyProject{parent: coords, current: current}
			commands, err := NewProjectCommands(ProjectCommandConfig{Reader: tx, Transactions: tx, Authorizer: f.authorizer, Clock: application.ClockFunc(func() time.Time { return f.now }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_coordinate" })})
			if err != nil {
				t.Fatal(err)
			}
			v, err := commands.CreateProject(t.Context(), f.actor, CreateProjectInput{ProductID: "product", Name: " Child "})
			if tx.reads != 2 || !errors.Is(err, tc.want) {
				t.Fatal("coordinate check changed", tx.reads, err)
			}
			if tc.want != nil {
				if v.ID != "" || tx.project.ID != "" || tx.audit.ID != "" {
					t.Fatal("invalid parent committed effects", v, tx)
				}
			} else if v.Name != "Child" || v.ProductID != "product" || v != tx.project || tx.audit.SubjectID != v.ID || tx.audit.TenantID != v.TenantID || tx.audit.EntryType != "project.created" || !tx.audit.OccurredAt.Equal(v.CreatedAt) {
				t.Fatal("project or atomic audit mapping changed", v, tx)
			}
		})
	}
}
