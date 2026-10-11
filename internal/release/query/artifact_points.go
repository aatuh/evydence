package query

import (
	"context"
	"encoding/hex"
	"slices"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// ArtifactReadRequest contains grant coordinates from the authenticated actor,
// never caller-supplied resource IDs. The database verifies the associations.
type ArtifactReadRequest struct {
	TenantID          string
	ID                string
	TenantWide        bool
	AllowedProductIDs []string
	AllowedProjectIDs []string
	AllowedReleaseIDs []string
}

type ArtifactPoint struct {
	Artifact releasedomain.Artifact
	Visible  bool
}

type ArtifactPointReader interface {
	GetArtifactPoint(context.Context, ArtifactReadRequest) (ArtifactPoint, error)
}

type ArtifactPoints struct{ reader ArtifactPointReader }

func NewArtifactPoints(reader ArtifactPointReader) (*ArtifactPoints, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return &ArtifactPoints{reader: reader}, nil
}

func (s *ArtifactPoints) GetArtifact(ctx context.Context, actor identitydomain.Actor, id string) (releasedomain.Artifact, error) {
	if s == nil || ctx == nil {
		return releasedomain.Artifact{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return releasedomain.Artifact{}, err
	}
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return releasedomain.Artifact{}, application.ErrUnauthorized
	}
	visibility, err := authz.ReadVisibility(ctx, actor, authz.ActionArtifactsRead)
	if err != nil {
		return releasedomain.Artifact{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return releasedomain.Artifact{}, ErrNotFound
	}
	if !visibility.TenantWide && len(visibility.ProductIDs)+len(visibility.ProjectIDs)+len(visibility.ReleaseIDs) == 0 {
		return releasedomain.Artifact{}, application.ErrForbidden
	}
	request := ArtifactReadRequest{
		TenantID: visibility.TenantID, ID: id, TenantWide: visibility.TenantWide,
		AllowedProductIDs: visibility.ProductIDs, AllowedProjectIDs: visibility.ProjectIDs, AllowedReleaseIDs: visibility.ReleaseIDs,
	}
	point, err := s.reader.GetArtifactPoint(ctx, request)
	if err != nil {
		return releasedomain.Artifact{}, err
	}
	artifact := point.Artifact
	if artifact.ID != id || artifact.TenantID != actor.TenantID {
		return releasedomain.Artifact{}, ErrNotFound
	}
	if !validArtifactPoint(artifact) {
		return releasedomain.Artifact{}, ErrInvalidProjection
	}
	proof := authz.ArtifactVisibilityFunc(func(_ context.Context, r authz.ArtifactVisibilityRequest) (bool, error) {
		// A proof is valid only for the exact filters applied by this read, not
		// a later or differently scoped policy evaluation.
		return point.Visible && !r.TenantWide && r.TenantID == request.TenantID && r.ArtifactID == request.ID &&
			r.ProductID == "" && r.ReleaseID == "" &&
			slices.Equal(r.AllowedProductIDs, request.AllowedProductIDs) &&
			slices.Equal(r.AllowedProjectIDs, request.AllowedProjectIDs) &&
			slices.Equal(r.AllowedReleaseIDs, request.AllowedReleaseIDs), nil
	})
	if err := authz.AuthorizeWithArtifactVisibility(ctx, actor, authz.Request{Action: authz.ActionArtifactsRead, Resources: authz.ResourceReferences{ArtifactID: id}}, proof); err != nil {
		return releasedomain.Artifact{}, err
	}
	return artifact, nil
}

func validArtifactPoint(artifact releasedomain.Artifact) bool {
	if artifact.Name == "" || artifact.MediaType == "" || artifact.Size < 0 || artifact.CreatedAt.IsZero() ||
		!strings.HasPrefix(artifact.Digest, "sha256:") || len(artifact.Digest) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(artifact.Digest, "sha256:"))
	return err == nil
}
