package query

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type instanceCountsReaderFake struct {
	counts InstanceCounts
	calls  int
	err    error
}

func (f *instanceCountsReaderFake) ReadInstanceCounts(context.Context) (InstanceCounts, error) {
	f.calls++
	return f.counts, f.err
}

func TestInstanceAdminSnapshotRequiresExplicitScopeBeforeReading(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	reader := &instanceCountsReaderFake{counts: InstanceCounts{Tenants: 2, Users: 3, Collectors: 4, Evidence: 5}}
	service, err := NewInstanceAdmin(reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	for _, actor := range []identitydomain.Actor{
		{},
		{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"*"}},
		{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"admin"}},
		{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"*"}},
	} {
		_, err := service.Snapshot(t.Context(), actor)
		if actor.TenantID == "" && !errors.Is(err, application.ErrUnauthorized) || actor.TenantID != "" && !errors.Is(err, application.ErrForbidden) || reader.calls != 0 {
			t.Fatalf("actor=%#v err=%v read calls=%d", actor, err, reader.calls)
		}
	}
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"instance:admin"}}
	snapshot, err := service.Snapshot(t.Context(), actor)
	if err != nil || snapshot.TenantCount != 2 || snapshot.ResourceCounts["users"] != 3 || snapshot.ResourceCounts["collectors"] != 4 || snapshot.ResourceCounts["evidence"] != 5 || !snapshot.GeneratedAt.Equal(now) || reader.calls != 1 {
		t.Fatalf("snapshot=%#v error=%v calls=%d", snapshot, err, reader.calls)
	}
	reader.counts.Evidence = -1
	if _, err := service.Snapshot(t.Context(), actor); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("negative projection error=%v", err)
	}
	reader.counts.Evidence = 5
	actor = identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"instance:admin"}}
	if _, err := service.Snapshot(t.Context(), actor); err != nil {
		t.Fatalf("explicit human scope error=%v", err)
	}
}

func TestInstanceAdminSnapshotRejectsMissingDependencies(t *testing.T) {
	if _, err := NewInstanceAdmin(nil, time.Now); !errors.Is(err, ErrValidation) {
		t.Fatalf("nil reader error=%v", err)
	}
	if _, err := NewInstanceAdmin(&instanceCountsReaderFake{}, nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("nil clock error=%v", err)
	}
}
