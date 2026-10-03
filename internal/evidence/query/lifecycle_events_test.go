package query

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type lifecyclePageReaderStub struct {
	result LifecyclePage
	err    error
	calls  int
}

func TestLifecycleEventsRejectMalformedIDBeforeStorage(t *testing.T) {
	reader := &lifecyclePageReaderStub{}
	service, err := NewLifecycleEvents(reader)
	if err != nil {
		t.Fatal(err)
	}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	for _, id := range []string{"ev\x00bad", string([]byte{0xff}), strings.Repeat("x", 1025)} {
		if _, err := service.ListPage(t.Context(), evidenceKeyActor(), id, page, nil); !errors.Is(err, ErrValidation) || reader.calls != 0 {
			t.Fatalf("malformed ID error=%v reader calls=%d", err, reader.calls)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := service.ListPage(ctx, evidenceKeyActor(), "ev_1", page, nil); !errors.Is(err, context.Canceled) || reader.calls != 0 {
		t.Fatalf("cancelled page error=%v reader calls=%d", err, reader.calls)
	}
}

func (r *lifecyclePageReaderStub) PageLifecycleEvents(_ context.Context, _, _ string, _ appquery.PageRequest, _ *appquery.SortKey, guard EvidenceReadGuard) (LifecyclePage, error) {
	r.calls++
	if err := guard(application.ResourceReferences{ProductID: r.result.Point.ProductID, ProjectID: r.result.Point.ProjectID, ReleaseID: r.result.Point.ReleaseID}); err != nil {
		return LifecyclePage{}, err
	}
	return r.result, r.err
}

func TestLifecycleEventsPageAuthorizesParentAndValidatesRows(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	action, err := evidencedomain.ParseEvidenceLifecycleState("amendment")
	if err != nil {
		t.Fatal(err)
	}
	point := EvidencePoint{Item: evidencedomain.EvidenceItem{ID: "ev_1", TenantID: "ten_1", Type: "document", ProductID: "prod_1", ReleaseID: "rel_1"}, ProductID: "prod_1", ReleaseID: "rel_1"}
	event := evidencedomain.EvidenceLifecycleEvent{ID: "life_1", TenantID: "ten_1", EvidenceID: "ev_1", Action: action, Reason: "amended", ActorID: "usr_1", SchemaVersion: "evidence-lifecycle.v1", CreatedAt: now}
	key := appquery.RecordSortKey(event.ID, event.CreatedAt, appquery.SortCreatedAt)
	reader := &lifecyclePageReaderStub{result: LifecyclePage{Point: point, Page: appquery.Result[evidencedomain.EvidenceLifecycleEvent]{Items: []evidencedomain.EvidenceLifecycleEvent{event}, Next: &key}}}
	service, err := NewLifecycleEvents(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"evidence:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "rel_1", Scopes: []string{"evidence:read"}}}}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	result, err := service.ListPage(context.Background(), actor, "ev_1", page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "life_1" || result.Next == nil {
		t.Fatalf("authorized page=%#v error=%v", result, err)
	}
	actor.ResourceGrants[0].ResourceID = "rel_2"
	if _, err := service.ListPage(context.Background(), actor, "ev_1", page, nil); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("wrong release grant error=%v", err)
	}
	actor.TenantID = "ten_2"
	actor.ResourceGrants[0].ResourceID = "rel_1"
	if _, err := service.ListPage(context.Background(), actor, "ev_1", page, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong-tenant projection error=%v", err)
	}
	actor.TenantID = "ten_1"
	actor.ResourceGrants[0].ResourceID = "rel_1"
	reader.result.Page.Items[0].EvidenceID = "ev_other"
	if _, err := service.ListPage(context.Background(), actor, "ev_1", page, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("foreign event error=%v", err)
	}
	reader.err = ErrConflict
	if _, err := service.ListPage(context.Background(), actor, "ev_1", page, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("unproven worker projection error=%v", err)
	}
	reader.err = nil
	actor.Scopes = nil
	before := reader.calls
	if _, err := service.ListPage(context.Background(), actor, "ev_1", page, nil); !errors.Is(err, application.ErrForbidden) || reader.calls != before {
		t.Fatalf("missing scope error=%v reader calls=%d", err, reader.calls)
	}
}
