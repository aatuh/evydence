package app

import (
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestGenericArtifactReadUsesOnlyItsTypedActionAndResolvedArtifact(t *testing.T) {
	f := newServiceFixture(t)
	f.reader.artifacts["artifact"] = releasedomain.Artifact{ID: "artifact", TenantID: f.actor.TenantID, Digest: "sha256:" + strings.Repeat("a", 64)}
	artifact, err := f.service.GetArtifact(t.Context(), f.actor, "artifact")
	want := []application.AuthorizationRequest{{Action: authz.ActionArtifactsRead, ScopeOnly: true}, {Action: authz.ActionArtifactsRead, Resources: application.ResourceReferences{ArtifactID: "artifact"}}}
	if err != nil || artifact.ID != "artifact" || !reflect.DeepEqual(f.authorizer.requests, want) {
		t.Fatal("generic artifact read did not bind typed preflight and resolved authority", err, f.authorizer.requests)
	}
}
