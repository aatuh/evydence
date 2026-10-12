package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type guardedArtifactMetadata struct {
	artifact releasedomain.Artifact
	metadata *releasedomain.Artifact
	steps    []string
	deny     error
}

func (g *guardedArtifactMetadata) ExecuteArtifact(ctx context.Context, fn func(context.Context, ArtifactTransaction) error) error {
	return fn(ctx, g)
}
func (g *guardedArtifactMetadata) ArtifactIdentityByDigest(context.Context, string, string) (ArtifactRegistrationIdentity, bool, error) {
	g.steps = append(g.steps, "identity")
	return ArtifactRegistrationIdentity{ID: g.artifact.ID, TenantID: g.artifact.TenantID, Digest: g.artifact.Digest}, true, nil
}
func (g *guardedArtifactMetadata) ReadArtifactMetadata(context.Context, string, string) (releasedomain.Artifact, error) {
	g.steps = append(g.steps, "metadata")
	if g.metadata != nil {
		return *g.metadata, nil
	}
	return g.artifact, nil
}

func TestArtifactReuseRejectsMetadataIdentityDrift(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*releasedomain.Artifact)
		want   error
	}{
		{"foreign tenant", func(a *releasedomain.Artifact) { a.TenantID = "other" }, ErrNotFound},
		{"wrong ID", func(a *releasedomain.Artifact) { a.ID = "other" }, ErrNotFound},
		{"changed digest", func(a *releasedomain.Artifact) { a.Digest = testSHA256('b') }, ErrConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newServiceFixture(t)
			original := releasedomain.Artifact{ID: "artifact", TenantID: f.actor.TenantID, Digest: testSHA256('a')}
			changed := original
			tc.change(&changed)
			g := &guardedArtifactMetadata{artifact: original, metadata: &changed}
			commands, err := NewArtifactCommands(ArtifactCommandConfig{Authorizer: f.authorizer, Transactions: g, Clock: application.ClockFunc(func() time.Time { return f.now }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_unused" })})
			if err != nil {
				t.Fatal(err)
			}
			v, err := commands.RegisterArtifact(t.Context(), f.actor, RegisterArtifactInput{Name: "Ignored", MediaType: "text/plain", Digest: original.Digest, Size: 1})
			if !errors.Is(err, tc.want) || v.ID != "" || !reflect.DeepEqual(g.steps, []string{"identity", "authorize", "metadata"}) {
				t.Fatal("changed metadata identity was returned", v, err, g.steps)
			}
		})
	}
}
func (g *guardedArtifactMetadata) AuthorizeExisting(context.Context, identitydomain.Actor, string) error {
	g.steps = append(g.steps, "authorize")
	return g.deny
}
func (g *guardedArtifactMetadata) InsertArtifact(context.Context, releasedomain.Artifact) error {
	return errors.New("unexpected artifact insert")
}
func (g *guardedArtifactMetadata) AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error) {
	return application.AuditReceipt{}, errors.New("unexpected audit")
}

func TestArtifactReuseAuthorizesIdentityBeforePrivateMetadata(t *testing.T) {
	for _, denied := range []bool{false, true} {
		f := newServiceFixture(t)
		g := &guardedArtifactMetadata{artifact: releasedomain.Artifact{ID: "artifact", TenantID: f.actor.TenantID, Name: "Private original", MediaType: "application/octet-stream", Digest: testSHA256('a'), Size: 1, CreatedAt: f.now}}
		if denied {
			g.deny = application.ErrForbidden
		}
		commands, err := NewArtifactCommands(ArtifactCommandConfig{Authorizer: f.authorizer, Transactions: g, Clock: application.ClockFunc(func() time.Time { return f.now }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_unused" })})
		if err != nil {
			t.Fatal(err)
		}
		v, err := commands.RegisterArtifact(t.Context(), f.actor, RegisterArtifactInput{Name: "Ignored", MediaType: "text/plain", Digest: g.artifact.Digest, Size: 99})
		if denied {
			if !errors.Is(err, application.ErrForbidden) || v.ID != "" || !reflect.DeepEqual(g.steps, []string{"identity", "authorize"}) {
				t.Fatal("denial loaded private metadata", v.ID, err, g.steps)
			}
		} else if err != nil || v != g.artifact || !reflect.DeepEqual(g.steps, []string{"identity", "authorize", "metadata"}) {
			t.Fatal("reuse order or original metadata changed", v, err, g.steps)
		}
	}
}
