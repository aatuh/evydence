package query

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

type readinessReaderFake struct {
	snapshot riskapp.ReadinessSnapshot
	calls    int
}

func (f *readinessReaderFake) ReadReleaseReadinessSnapshot(context.Context, string, string) (riskapp.ReadinessSnapshot, error) {
	f.calls++
	return f.snapshot, nil
}

func TestReleaseReadinessQueryAuthorizesBeforeAndAfterScopedRead(t *testing.T) {
	reader := &readinessReaderFake{snapshot: riskapp.ReadinessSnapshot{SnapshotVersion: riskapp.ReadinessSnapshotVersion, TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", HasArtifact: true}}
	query, err := NewReleaseReadinessQuery(reader, func() time.Time { return time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "user_1", Scopes: []string{"verify:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "rel_1", Scopes: []string{"verify:read"}}}}
	evaluation, err := query.Preview(context.Background(), actor, "rel_1")
	if err != nil || evaluation.ReleaseID != "rel_1" || evaluation.ID != "" || len(evaluation.Checks) == 0 {
		t.Fatalf("evaluation=%#v err=%v", evaluation, err)
	}
	actor.ResourceGrants[0].ResourceID = "rel_other"
	before := reader.calls
	if _, err := query.Preview(context.Background(), actor, "rel_1"); !errors.Is(err, application.ErrForbidden) || reader.calls != before {
		t.Fatalf("foreign grant err=%v calls=%d", err, reader.calls)
	}
	actor.ResourceGrants[0].ResourceID = "rel_1"
	reader.snapshot.TenantID = "ten_other"
	if _, err := query.Preview(context.Background(), actor, "rel_1"); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("foreign snapshot err=%v", err)
	}
	reader.snapshot.TenantID = "ten_1"
	reader.snapshot.ProductID = ""
	if _, err := query.Preview(context.Background(), actor, "rel_1"); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("incomplete snapshot err=%v", err)
	}
}
