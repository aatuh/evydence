package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type memoryImageRegistrationTestReader interface {
	releaseapp.ContainerImageIdentityReader
	ContainerImageRegistrationIdentityByKey(context.Context, string, string, string) (releaseapp.ContainerImageRegistrationIdentity, bool, error)
}

func TestMemoryRegistrationReadersSelectOnlyCurrentOwnedIdentityBeforeMetadata(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	a, ok := tx.Repositories().ReleaseCatalog.(releaseapp.ArtifactRegistrationReader)
	if !ok {
		t.Fatal("focused artifact registration reader missing")
	}
	i, ok := tx.Repositories().SupplyChain.(memoryImageRegistrationTestReader)
	if !ok {
		t.Fatal("focused image registration reader missing")
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	artifact := domain.Artifact{ID: "artifact", TenantID: "tenant", Digest: digest, Name: strings.Repeat("p", 65537), MediaType: "application/octet-stream", Size: 9007199254740993, CreatedAt: fixedNow()}
	image := domain.ContainerImage{ID: "image", TenantID: "tenant", ArtifactID: artifact.ID, Repository: "registry.test/product", Digest: digest, Tag: strings.Repeat("p", 65537), SchemaVersion: domain.ContainerImageSchemaVersion, CreatedAt: fixedNow()}
	tx.state.Artifacts[artifact.ID], tx.state.ContainerImages[image.ID] = artifact, image
	identity, found, err := a.ArtifactIdentityByDigest(t.Context(), "tenant", digest)
	if err != nil || !found || identity != (releaseapp.ArtifactRegistrationIdentity{ID: artifact.ID, TenantID: "tenant", Digest: digest}) {
		t.Fatal("artifact guard inspected private metadata", identity, found, err)
	}
	imageIdentity, found, err := i.ContainerImageRegistrationIdentityByKey(t.Context(), "tenant", image.Repository, digest)
	if err != nil || !found || imageIdentity != (releaseapp.ContainerImageRegistrationIdentity{ID: image.ID, TenantID: "tenant", ArtifactID: artifact.ID}) {
		t.Fatal("image guard inspected private metadata", imageIdentity, found, err)
	}
	if v, err := a.ReadArtifactMetadata(t.Context(), "tenant", artifact.ID); !errors.Is(err, ErrConflict) || v != (releasedomain.Artifact{}) {
		t.Fatal("artifact metadata budget ignored or returned partial data", err)
	}
	if v, found, err := i.ContainerImageByRepositoryDigest(t.Context(), "tenant", image.Repository, digest); !errors.Is(err, ErrConflict) || found || v != (releasedomain.ContainerImage{}) {
		t.Fatal("image metadata budget ignored or returned partial data", found, err)
	}
	artifact.Name, image.Tag = "original", "original"
	tx.state.Artifacts[artifact.ID], tx.state.ContainerImages[image.ID] = artifact, image
	metadata, err := a.ReadArtifactMetadata(t.Context(), "tenant", artifact.ID)
	if err != nil || metadata.Size != 9007199254740993 || metadata.Name != artifact.Name || !metadata.CreatedAt.Equal(artifact.CreatedAt) {
		t.Fatal("artifact metadata lost exact size or original fields", metadata, err)
	}
	stored, found, err := i.ContainerImageByRepositoryDigest(t.Context(), "tenant", image.Repository, digest)
	if err != nil || !found || stored.Tag != image.Tag || stored.ArtifactID != artifact.ID || !stored.CreatedAt.Equal(image.CreatedAt) {
		t.Fatal("image metadata lost original fields", stored, found, err)
	}
	if v, found, err := a.ArtifactIdentityByDigest(t.Context(), "foreign", digest); err != nil || found || v != (releaseapp.ArtifactRegistrationIdentity{}) {
		t.Fatal("artifact identity crossed tenant boundary", found, err)
	}
	if v, err := a.ReadArtifactMetadata(t.Context(), "foreign", artifact.ID); !errors.Is(err, ErrNotFound) || v != (releasedomain.Artifact{}) {
		t.Fatal("artifact metadata crossed tenant boundary", err)
	}
	if v, found, err := i.ContainerImageByRepositoryDigest(t.Context(), "foreign", image.Repository, digest); err != nil || found || v != (releasedomain.ContainerImage{}) {
		t.Fatal("image metadata crossed tenant boundary", found, err)
	}
	if v, found, err := i.ContainerImageRegistrationIdentityByKey(t.Context(), "missing-tenant", image.Repository, digest); !errors.Is(err, ErrNotFound) || found || v != (releaseapp.ContainerImageRegistrationIdentity{}) {
		t.Fatal("absent image lookup ignored tenant ownership", found, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, found, err := a.ArtifactIdentityByDigest(ctx, "tenant", digest); !errors.Is(err, context.Canceled) || found || v != (releaseapp.ArtifactRegistrationIdentity{}) {
		t.Fatal("cancelled artifact identity returned data", found, err)
	}
	if v, found, err := i.ContainerImageByRepositoryDigest(ctx, "tenant", image.Repository, digest); !errors.Is(err, context.Canceled) || found || v != (releasedomain.ContainerImage{}) {
		t.Fatal("cancelled image identity returned data", found, err)
	}
	image.ArtifactID = strings.Repeat("a", 1025)
	tx.state.ContainerImages[image.ID] = image
	if v, found, err := i.ContainerImageRegistrationIdentityByKey(t.Context(), "tenant", image.Repository, digest); !errors.Is(err, ErrConflict) || found || !reflect.DeepEqual(v, releaseapp.ContainerImageRegistrationIdentity{}) {
		t.Fatal("image ownership projection budget ignored", found, err)
	}
}
