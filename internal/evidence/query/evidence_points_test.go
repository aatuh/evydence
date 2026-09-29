package query

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type evidencePointReaderStub struct {
	point EvidencePoint
	err   error
	calls int
}

func (r *evidencePointReaderStub) GetEvidencePoint(_ context.Context, _, _ string) (EvidencePoint, error) {
	r.calls++
	return r.point, r.err
}

func TestEvidencePointsAuthorizeVerifiedCoordinates(t *testing.T) {
	base := EvidencePoint{
		Item:      evidencedomain.EvidenceItem{ID: "ev_1", TenantID: "ten_1", ProductID: "prod_1", ProjectID: "proj_1", ReleaseID: "rel_1", BuildID: "bld_1", Type: "document"},
		ProductID: "prod_1", ProjectID: "proj_1", ReleaseID: "rel_1",
	}
	for _, test := range []struct {
		name  string
		actor identitydomain.Actor
		point EvidencePoint
		want  error
	}{
		{name: "key scope", actor: evidenceKeyActor(), point: base},
		{name: "product grant", actor: evidenceHumanActor("product", "prod_1"), point: base},
		{name: "project grant", actor: evidenceHumanActor("project", "proj_1"), point: base},
		{name: "release grant", actor: evidenceHumanActor("release", "rel_1"), point: base},
		{name: "tenant grant", actor: evidenceHumanActor("tenant", "ten_1"), point: base},
		{name: "wrong product grant", actor: evidenceHumanActor("product", "prod_other"), point: base, want: application.ErrForbidden},
		{name: "wrong project grant", actor: evidenceHumanActor("project", "proj_other"), point: base, want: application.ErrForbidden},
		{name: "wrong release grant", actor: evidenceHumanActor("release", "rel_other"), point: base, want: application.ErrForbidden},
		{name: "wrong tenant grant", actor: evidenceHumanActor("tenant", "ten_other"), point: base, want: application.ErrForbidden},
		{name: "wrong tenant row", actor: evidenceKeyActor(), point: EvidencePoint{Item: evidencedomain.EvidenceItem{ID: "ev_1", TenantID: "ten_other", ProductID: "prod_1"}, ProductID: "prod_1"}, want: ErrConflict},
		{name: "mismatched product", actor: evidenceKeyActor(), point: EvidencePoint{Item: base.Item, ProductID: "prod_other", ProjectID: "proj_1", ReleaseID: "rel_1"}, want: ErrConflict},
		{name: "malformed reference", actor: evidenceKeyActor(), point: EvidencePoint{Item: evidencedomain.EvidenceItem{ID: "ev_1", TenantID: "ten_1", Type: "document", RelatedEvidenceRefs: []evidencedomain.EvidenceRef{{Type: "evidence_item", ID: " ev_2"}}}}, want: ErrConflict},
		{name: "detached tenant grant", actor: evidenceHumanActor("tenant", "ten_1"), point: EvidencePoint{Item: evidencedomain.EvidenceItem{ID: "ev_1", TenantID: "ten_1", Type: "document"}}},
		{name: "detached product grant denied", actor: evidenceHumanActor("product", "prod_1"), point: EvidencePoint{Item: evidencedomain.EvidenceItem{ID: "ev_1", TenantID: "ten_1", Type: "document"}}, want: application.ErrForbidden},
		{name: "project from build", actor: evidenceHumanActor("project", "proj_1"), point: EvidencePoint{Item: evidencedomain.EvidenceItem{ID: "ev_1", TenantID: "ten_1", BuildID: "bld_1", Type: "document"}, ProductID: "prod_1", ProjectID: "proj_1", ReleaseID: "rel_1"}},
		{name: "release from deployment", actor: evidenceHumanActor("release", "rel_1"), point: EvidencePoint{Item: evidencedomain.EvidenceItem{ID: "ev_1", TenantID: "ten_1", DeploymentID: "dep_1", Type: "document"}, ProductID: "prod_1", ReleaseID: "rel_1"}},
		{name: "project cannot use release only", actor: evidenceHumanActor("project", "proj_1"), point: EvidencePoint{Item: evidencedomain.EvidenceItem{ID: "ev_1", TenantID: "ten_1", ReleaseID: "rel_1", Type: "document"}, ProductID: "prod_1", ReleaseID: "rel_1"}, want: application.ErrForbidden},
		{name: "worker-owned record requires provenance projection", actor: evidenceKeyActor(), point: EvidencePoint{Item: evidencedomain.EvidenceItem{ID: "ev_1", TenantID: "ten_1", Type: "parser_normalization"}}, want: ErrRequiresProjection},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &evidencePointReaderStub{point: test.point}
			query, err := NewEvidencePoints(reader)
			if err != nil {
				t.Fatal(err)
			}
			item, err := query.GetEvidence(t.Context(), test.actor, "ev_1")
			if test.want == nil && err != nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("GetEvidence error=%v, want %v", err, test.want)
			}
			if test.want == nil && item.ID != "ev_1" || test.want != nil && item.ID != "" {
				t.Fatalf("GetEvidence item=%#v", item)
			}
			if reader.calls != 1 {
				t.Fatalf("reader calls=%d", reader.calls)
			}
		})
	}
}

func TestEvidencePointsRejectScopeAndInputBeforeStorage(t *testing.T) {
	reader := &evidencePointReaderStub{}
	query, err := NewEvidencePoints(reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		actor identitydomain.Actor
		id    string
		want  error
	}{
		{actor: identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1"}, id: "ev_1", want: application.ErrForbidden},
		{actor: identitydomain.Actor{TenantID: "ten_1", Scopes: []string{"evidence:read"}}, id: "ev_1", want: application.ErrUnauthorized},
		{actor: evidenceKeyActor(), id: " ", want: ErrNotFound},
	} {
		if _, err := query.GetEvidence(t.Context(), test.actor, test.id); !errors.Is(err, test.want) || reader.calls != 0 {
			t.Fatalf("GetEvidence error=%v, want %v; reader calls=%d", err, test.want, reader.calls)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := query.GetEvidence(ctx, evidenceKeyActor(), "ev_1"); !errors.Is(err, context.Canceled) || reader.calls != 0 {
		t.Fatalf("canceled read error=%v reader calls=%d", err, reader.calls)
	}
}

func evidenceKeyActor() identitydomain.Actor {
	return identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"evidence:read"}}
}

func evidenceHumanActor(resourceType, resourceID string) identitydomain.Actor {
	return identitydomain.Actor{
		TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"evidence:read"},
		ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: resourceType, ResourceID: resourceID, Scopes: []string{"evidence:read"}}},
	}
}
