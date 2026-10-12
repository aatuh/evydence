package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type coordinateOnlyRelease struct {
	parent              ProductCoordinates
	current             ProductCoordinates
	exists              bool
	reads, versionReads int
	release             releasedomain.Release
	audit               application.AuditEvent
}

func (f *coordinateOnlyRelease) ReadProductCoordinates(context.Context, string, string) (ProductCoordinates, error) {
	f.reads++
	if f.reads == 1 {
		return f.parent, nil
	}
	return f.current, nil
}
func (f *coordinateOnlyRelease) ReleaseVersionExists(context.Context, string, string, string) (bool, error) {
	f.versionReads++
	return f.exists, nil
}
func (f *coordinateOnlyRelease) ExecuteReleaseCreation(ctx context.Context, fn func(context.Context, ReleaseCreationTransaction) error) error {
	return fn(ctx, f)
}
func (f *coordinateOnlyRelease) InsertRelease(_ context.Context, v releasedomain.Release) error {
	f.release = v
	return nil
}
func (f *coordinateOnlyRelease) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	f.audit = v
	return application.AuditReceipt{ID: v.ID}, nil
}

func TestReleaseCreationNeedsOnlyProductCoordinatesAndVersionExistence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*ProductCoordinates)
		exists bool
		want   error
	}{
		{"valid", func(*ProductCoordinates) {}, false, nil},
		{"slug drift", func(v *ProductCoordinates) { v.Slug = "changed" }, false, ErrConflict},
		{"foreign tenant", func(v *ProductCoordinates) { v.TenantID = "other" }, false, ErrNotFound},
		{"wrong product", func(v *ProductCoordinates) { v.ID = "other" }, false, ErrNotFound},
		{"duplicate version", func(*ProductCoordinates) {}, true, ErrConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newServiceFixture(t)
			coords := ProductCoordinates{ID: "product", TenantID: f.actor.TenantID, Slug: "product"}
			current := coords
			tc.change(&current)
			tx := &coordinateOnlyRelease{parent: coords, current: current, exists: tc.exists}
			commands, err := NewReleaseCommands(ReleaseCommandConfig{Reader: tx, Transactions: tx, Authorizer: f.authorizer, Clock: application.ClockFunc(func() time.Time { return f.now }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_coordinate" })})
			if err != nil {
				t.Fatal(err)
			}
			v, err := commands.CreateRelease(t.Context(), f.actor, CreateReleaseInput{ProductID: "product", Version: " 1 "})
			if tx.reads != 2 || !errors.Is(err, tc.want) {
				t.Fatal("coordinate checks changed", tx.reads, err)
			}
			if tc.want != nil {
				if v.ID != "" || tx.release.ID != "" || tx.audit.ID != "" {
					t.Fatal("invalid release committed effects", v, tx)
				}
			} else if v.Version != "1" || v.ProductID != "product" || v.State.String() != "draft" || v.Revision != 1 || v.ID != tx.release.ID || tx.audit.SubjectID != v.ID || tx.audit.EntryType != "release.created" || !tx.audit.OccurredAt.Equal(v.CreatedAt) || tx.versionReads != 1 {
				t.Fatal("release or atomic audit mapping changed", v, tx)
			}
		})
	}
}
