package app

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestStandaloneContainerImageCommandsPreserveIdentityAndAtomicAudit(t *testing.T) {
	f := newServiceFixture(t)
	digest := testSHA256('a')
	artifact := releasedomain.Artifact{ID: "artifact", TenantID: f.actor.TenantID, Digest: digest}
	f.reader.artifacts[artifact.ID] = artifact
	f.transactions.state.artifacts[artifact.ID] = artifact
	commands, err := NewContainerImageCommands(ContainerImageCommandConfig{
		Reader: f.reader, Authorizer: f.authorizer,
		Transactions: releaseContainerImageTransactions{f.transactions},
		Clock:        application.ClockFunc(func() time.Time { return f.now }),
		IDs:          application.IDGeneratorFunc(func(prefix string) string { return prefix + "_focused" }),
	})
	if err != nil {
		t.Fatal(err)
	}
	in := RegisterContainerImageInput{ArtifactID: artifact.ID, Repository: " registry.example.test/api ", Tag: " v1 ", Digest: " " + digest + " ", Platform: " linux/amd64 "}
	v, err := commands.RegisterContainerImage(t.Context(), f.actor, in)
	if err != nil || v.ID != "img_focused" || v.ArtifactID != artifact.ID || v.Repository != "registry.example.test/api" || v.Tag != "v1" || v.Platform != "linux/amd64" || len(f.transactions.state.audit) != 1 || !v.CreatedAt.Equal(f.transactions.state.audit[0].OccurredAt) {
		t.Fatal("focused creation identity or audit", v, err, f.transactions.state.audit)
	}
	in.Tag = "ignored-on-reuse"
	reused, err := commands.RegisterContainerImage(t.Context(), f.actor, in)
	if err != nil || !reflect.DeepEqual(reused, v) || len(f.transactions.state.images) != 1 || len(f.transactions.state.audit) != 1 {
		t.Fatal("reuse changed image or audit", reused, err)
	}
	in.Repository = "registry.example.test/rollback"
	commands.ids = application.IDGeneratorFunc(func(prefix string) string { return prefix + "_rollback" })
	f.transactions.auditErr = errAudit
	if failed, err := commands.RegisterContainerImage(t.Context(), f.actor, in); !errors.Is(err, errAudit) || failed.ID != "" || len(f.transactions.state.images) != 1 || len(f.transactions.state.audit) != 1 {
		t.Fatal("audit failure published image", failed, err)
	}
}

func TestContainerImageReauthorizesArtifactBeforeInsertion(t *testing.T) {
	f := newServiceFixture(t)
	digest := testSHA256('a')
	artifact := releasedomain.Artifact{ID: "artifact", TenantID: f.actor.TenantID, Digest: digest}
	f.reader.artifacts[artifact.ID] = artifact
	f.transactions.state.artifacts[artifact.ID] = artifact
	f.transactions.beforeCommand = func(_ *fakeState) {
		f.authorizer.authorize = func(r application.AuthorizationRequest) error {
			if r.Resources.ArtifactID != "" {
				return application.ErrForbidden
			}
			return nil
		}
	}
	v, err := f.service.RegisterContainerImage(t.Context(), f.actor, RegisterContainerImageInput{ArtifactID: artifact.ID, Repository: "registry.example.test/api", Digest: digest})
	if !errors.Is(err, application.ErrForbidden) || v.ID != "" || len(f.transactions.state.images) != 0 || len(f.transactions.state.audit) != 0 || f.transactions.commits != 0 || f.transactions.rollbacks != 1 {
		t.Fatal("revoked artifact authority committed image", v, err, f.transactions)
	}
}
