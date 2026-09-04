package app

import (
	"context"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestReleaseDuplicateAuthorizationDoesNotReenterLedgerMutex(t *testing.T) {
	ctx := context.Background()
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	actor, _, artifact := setupReleaseRiskFixture(t, ledger)

	t.Run("artifact", func(t *testing.T) {
		result := make(chan struct {
			artifact domain.Artifact
			err      error
		}, 1)
		go func() {
			duplicate, err := ledger.RegisterArtifact(ctx, actor, "retry-name.tar.gz", artifact.MediaType, artifact.Digest, artifact.Size)
			result <- struct {
				artifact domain.Artifact
				err      error
			}{artifact: duplicate, err: err}
		}()
		select {
		case got := <-result:
			if got.err != nil || got.artifact.ID != artifact.ID {
				t.Fatalf("duplicate artifact = (%#v, %v), want %s", got.artifact, got.err, artifact.ID)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("duplicate artifact registration deadlocked")
		}
	})

	t.Run("container image", func(t *testing.T) {
		created, err := ledger.RegisterContainerImage(ctx, actor, RegisterContainerImageInput{
			ArtifactID: artifact.ID, Repository: "registry.example.test/projection", Tag: "v1", Digest: artifact.Digest,
		})
		if err != nil {
			t.Fatalf("RegisterContainerImage: %v", err)
		}
		result := make(chan struct {
			image domain.ContainerImage
			err   error
		}, 1)
		go func() {
			duplicate, err := ledger.RegisterContainerImage(ctx, actor, RegisterContainerImageInput{
				ArtifactID: artifact.ID, Repository: created.Repository, Tag: "retry", Digest: artifact.Digest,
			})
			result <- struct {
				image domain.ContainerImage
				err   error
			}{image: duplicate, err: err}
		}()
		select {
		case got := <-result:
			if got.err != nil || got.image.ID != created.ID {
				t.Fatalf("duplicate image = (%#v, %v), want %s", got.image, got.err, created.ID)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("duplicate container-image registration deadlocked")
		}
	})
}
