package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func NormalizeArtifactRegistrationInput(in RegisterArtifactInput) (RegisterArtifactInput, error) {
	var err error
	if in.Name, err = normalizeCatalogCreationText(in.Name, 65536); err != nil {
		return RegisterArtifactInput{}, err
	}
	if in.MediaType, err = normalizeCatalogCreationText(in.MediaType, 65536); err != nil {
		return RegisterArtifactInput{}, err
	}
	if in.Digest, err = normalizeCatalogCreationText(in.Digest, 128); err != nil {
		return RegisterArtifactInput{}, err
	}
	if !validDigest(in.Digest) || in.Size < 0 {
		return RegisterArtifactInput{}, ErrValidation
	}
	return in, nil
}
func NormalizeContainerImageRegistrationInput(in RegisterContainerImageInput) (RegisterContainerImageInput, error) {
	for _, field := range []struct {
		text  string
		limit int
	}{{in.ArtifactID, 1024}, {in.Repository, 65536}, {in.Tag, 65536}, {in.Digest, 128}, {in.Platform, 65536}} {
		if len(field.text) > field.limit || !validBuildText(field.text) {
			return RegisterContainerImageInput{}, ErrValidation
		}
	}
	in.ArtifactID = strings.TrimSpace(in.ArtifactID)
	in.Repository = strings.TrimSpace(in.Repository)
	in.Tag = strings.TrimSpace(in.Tag)
	in.Digest = strings.TrimSpace(in.Digest)
	in.Platform = strings.TrimSpace(in.Platform)
	if in.Repository == "" || !validDigest(in.Digest) {
		return RegisterContainerImageInput{}, ErrValidation
	}
	return in, nil
}

func (s *ArtifactCommands) AuthorizeArtifactRegistration(ctx context.Context, a identitydomain.Actor, in RegisterArtifactInput) error {
	if s == nil {
		return ErrValidation
	}
	if err := validateCatalogCreationActor(ctx, a); err != nil {
		return err
	}
	if err := s.authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, ScopeOnly: true}); err != nil {
		return err
	}
	input, err := NormalizeArtifactRegistrationInput(in)
	if err != nil {
		return err
	}
	return s.transactions.ExecuteArtifact(ctx, func(ctx context.Context, tx ArtifactTransaction) error {
		v, found, err := tx.ArtifactIdentityByDigest(ctx, a.TenantID, input.Digest)
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
		if v.TenantID != a.TenantID || v.ID == "" {
			return ErrNotFound
		}
		if len(v.ID) > 1024 || !validBuildText(v.ID) || v.Digest != input.Digest {
			return ErrConflict
		}
		return tx.AuthorizeExisting(ctx, a, v.ID)
	})
}

type ContainerImageRegistrationIdentity struct{ ID, TenantID, ArtifactID string }

// This ownership-only projection excludes tags, platforms, schema and time.
type ContainerImageRegistrationGuardReader interface {
	ContainerImageRegistrationIdentityByKey(context.Context, string, string, string) (ContainerImageRegistrationIdentity, bool, error)
	ReadContainerImageRegistrationArtifact(context.Context, string, string) (releasedomain.Artifact, error)
}

func authorizeContainerImageRegistrationScope(ctx context.Context, tx ContainerImageTransaction, a identitydomain.Actor, in RegisterContainerImageInput) error {
	reader, ok := tx.(ContainerImageRegistrationGuardReader)
	if !ok {
		return ErrValidation
	}
	if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, ScopeOnly: true}); err != nil {
		return err
	}
	v, found, err := reader.ContainerImageRegistrationIdentityByKey(ctx, a.TenantID, in.Repository, in.Digest)
	if err != nil {
		return err
	}
	if found && (v.TenantID != a.TenantID || v.ID == "") {
		return ErrNotFound
	}
	if found && (len(v.ID) > 1024 || len(v.ArtifactID) > 1024 || !validBuildText(v.ID) || !validBuildText(v.ArtifactID)) {
		return ErrConflict
	}
	seen := map[string]bool{}
	for _, id := range []string{in.ArtifactID, v.ArtifactID} {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		artifact, err := reader.ReadContainerImageRegistrationArtifact(ctx, a.TenantID, id)
		if err != nil {
			return err
		}
		if artifact.TenantID != a.TenantID || artifact.ID != id {
			return ErrNotFound
		}
		if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, Resources: application.ResourceReferences{ArtifactID: id}}); err != nil {
			return err
		}
	}
	return nil
}

func (s *ContainerImageCommands) AuthorizeContainerImageRegistration(ctx context.Context, a identitydomain.Actor, in RegisterContainerImageInput) error {
	if s == nil {
		return ErrValidation
	}
	if err := validateCatalogCreationActor(ctx, a); err != nil {
		return err
	}
	if err := s.authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceWrite, ScopeOnly: true}); err != nil {
		return err
	}
	input, err := NormalizeContainerImageRegistrationInput(in)
	if err != nil {
		return err
	}
	return s.transactions.ExecuteContainerImage(ctx, func(ctx context.Context, tx ContainerImageTransaction) error {
		return authorizeContainerImageRegistrationScope(ctx, tx, a, input)
	})
}
