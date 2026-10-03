package query

import (
	"errors"
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestCandidateAuthorizerChecksCurrentArtifactGrantsForReleaseWrites(t *testing.T) {
	reader := &buildArtifactPointReaderFake{point: ArtifactPoint{Artifact: releasedomain.Artifact{ID: "artifact", TenantID: "ten_1"}, Visible: true}}
	auth, err := NewCandidateAuthorizer(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := catalogActor("release:write", "release", "release", "release:write")
	parent := application.AuthorizationRequest{Scope: "release:write", Resources: application.ResourceReferences{ProductID: "product", ReleaseID: "release"}}
	if err := auth.Authorize(t.Context(), actor, parent); err != nil {
		t.Fatal("matching parent grant denied", err)
	}
	artifact := application.AuthorizationRequest{Scope: "release:write", Resources: application.ResourceReferences{ArtifactID: "artifact"}}
	if err := auth.Authorize(t.Context(), actor, artifact); err != nil {
		t.Fatal("linked artifact denied", err)
	}
	if reader.request.TenantID != "ten_1" || reader.request.ID != "artifact" || reader.request.TenantWide || !reflect.DeepEqual(reader.request.AllowedReleaseIDs, []string{"release"}) {
		t.Fatal("artifact grant query changed", reader.request)
	}
	reader.point.Visible = false
	if err := auth.Authorize(t.Context(), actor, artifact); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("unlinked artifact accepted", err)
	}
	reader.point.Visible = true
	reader.point.Artifact.TenantID = "other"
	if err := auth.Authorize(t.Context(), actor, artifact); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("foreign artifact accepted", err)
	}
	actor.ResourceGrants = nil
	if err := auth.Authorize(t.Context(), actor, parent); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("removed parent grant accepted", err)
	}
	if err := auth.Authorize(t.Context(), actor, artifact); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("removed artifact grant accepted", err)
	}
	actor = catalogActor("release:write", "release", "release", "evidence:read")
	if err := auth.Authorize(t.Context(), actor, artifact); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("wrong grant scope accepted", err)
	}
	if _, err := NewCandidateAuthorizer(nil); err == nil {
		t.Fatal("nil grant reader accepted")
	}
}
