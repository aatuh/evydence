package query

import (
	"context"
	"errors"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type candidateReaderFake struct {
	point      ReleaseCandidatePoint
	page       appquery.Result[ReleaseCandidatePoint]
	request    ReleaseCandidatePageRequest
	pointCalls int
	pageCalls  int
}

func (f *candidateReaderFake) GetReleaseCandidatePoint(_ context.Context, _, _ string) (ReleaseCandidatePoint, error) {
	f.pointCalls++
	return f.point, nil
}

func (f *candidateReaderFake) PageReleaseCandidates(_ context.Context, request ReleaseCandidatePageRequest) (appquery.Result[ReleaseCandidatePoint], error) {
	f.pageCalls++
	f.request = request
	return f.page, nil
}

func TestReleaseCandidateQueryChecksCurrentParentAndGrant(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	state, _ := releasedomain.ParseReleaseCandidateState(releasedomain.ReleaseCandidateStateOpenValue)
	point := ReleaseCandidatePoint{Candidate: releasedomain.ReleaseCandidate{ID: "cand_1", TenantID: "ten_1", ReleaseID: "rel_1", State: state, CreatedAt: now}, ProductID: "prod_1"}
	reader := &candidateReaderFake{point: point}
	service, err := NewReleaseCandidates(reader, NewCatalogAuthorizer())
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"release:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"release:read"}}}}
	got, err := service.GetReleaseCandidate(t.Context(), actor, "cand_1")
	if err != nil || got.ID != point.Candidate.ID {
		t.Fatalf("authorized point=%#v error=%v", got, err)
	}
	actor.ResourceGrants[0].ResourceID = "prod_other"
	if _, err := service.GetReleaseCandidate(t.Context(), actor, "cand_1"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("wrong grant error=%v", err)
	}
	reader.point.ProductID = ""
	if _, err := service.GetReleaseCandidate(t.Context(), actor, "cand_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing parent error=%v", err)
	}
	reader.point = point
	reader.point.Candidate.TenantID = "ten_other"
	if _, err := service.GetReleaseCandidate(t.Context(), actor, "cand_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign tenant error=%v", err)
	}
	actor.Scopes = nil
	if _, err := service.GetReleaseCandidate(t.Context(), actor, "cand_1"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("missing scope error=%v", err)
	}
	if reader.pointCalls != 4 {
		t.Fatalf("unauthorized point reached reader: %d calls", reader.pointCalls)
	}
}

func TestReleaseCandidatePageFiltersGrantsBeforeLimitAndValidatesProjection(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	state, _ := releasedomain.ParseReleaseCandidateState(releasedomain.ReleaseCandidateStateOpenValue)
	point := ReleaseCandidatePoint{Candidate: releasedomain.ReleaseCandidate{ID: "cand_1", TenantID: "ten_1", ReleaseID: "rel_1", State: state, CreatedAt: now}, ProductID: "prod_1"}
	reader := &candidateReaderFake{page: appquery.Result[ReleaseCandidatePoint]{Items: []ReleaseCandidatePoint{point}}}
	service, err := NewReleaseCandidates(reader, NewCatalogAuthorizer())
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"release:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "rel_1", Scopes: []string{"release:read"}}}}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}
	result, err := service.ListPage(t.Context(), actor, "rel_1", page, nil)
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != "cand_1" || reader.request.TenantWide || len(reader.request.AllowedReleaseIDs) != 1 || reader.request.AllowedReleaseIDs[0] != "rel_1" {
		t.Fatalf("release-granted page=%#v request=%#v error=%v", result, reader.request, err)
	}
	actor.ResourceGrants[0].ResourceType = "project"
	actor.ResourceGrants[0].ResourceID = "proj_1"
	result, err = service.ListPage(t.Context(), actor, "", page, nil)
	if err != nil || len(result.Items) != 0 || reader.pageCalls != 1 {
		t.Fatalf("unexpected fake projection=%#v calls=%d error=%v", result, reader.pageCalls, err)
	}
	reader.page.Items[0].Candidate.TenantID = "ten_other"
	actor.ResourceGrants[0].ResourceType = "release"
	actor.ResourceGrants[0].ResourceID = "rel_1"
	if _, err := service.ListPage(t.Context(), actor, "", page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("foreign projection error=%v", err)
	}
	reader.page.Items[0] = point
	reader.page.Next = &appquery.SortKey{ID: "cand_other", Value: now.Format(time.RFC3339Nano)}
	if _, err := service.ListPage(t.Context(), actor, "", page, nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatalf("wrong next cursor error=%v", err)
	}
	reader.page.Next = nil
	actor.ResourceGrants = nil
	if result, err := service.ListPage(t.Context(), actor, "", page, nil); err != nil || len(result.Items) != 0 || reader.pageCalls != 3 {
		t.Fatalf("ungranted page=%#v calls=%d error=%v", result, reader.pageCalls, err)
	}
}
