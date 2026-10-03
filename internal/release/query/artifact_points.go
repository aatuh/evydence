package query

import (
	"context"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/aatuh/evydence/internal/application"
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
	if !actor.HasScope("evidence:read") && !actor.HasScope("admin") {
		return releasedomain.Artifact{}, application.ErrForbidden
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return releasedomain.Artifact{}, ErrNotFound
	}
	tenantWide, products, projects, releases := artifactVisibility(actor)
	if !tenantWide && len(products) == 0 && len(projects) == 0 && len(releases) == 0 {
		return releasedomain.Artifact{}, application.ErrForbidden
	}
	point, err := s.reader.GetArtifactPoint(ctx, ArtifactReadRequest{
		TenantID: actor.TenantID, ID: id, TenantWide: tenantWide,
		AllowedProductIDs: products, AllowedProjectIDs: projects, AllowedReleaseIDs: releases,
	})
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
	if !tenantWide && !point.Visible {
		return releasedomain.Artifact{}, application.ErrForbidden
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

func artifactVisibility(actor identitydomain.Actor) (bool, []string, []string, []string) {
	return artifactVisibilityForScope(actor, "evidence:read")
}

func artifactVisibilityForScope(actor identitydomain.Actor, scope string) (bool, []string, []string, []string) {
	if actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" {
		return true, nil, nil, nil
	}
	products, projects, releases := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	for _, grant := range actor.ResourceGrants {
		if !catalogGrantHasScope(grant, scope) {
			continue
		}
		switch grant.ResourceType {
		case "", "tenant":
			if grant.ResourceID == "" || grant.ResourceID == actor.TenantID {
				return true, nil, nil, nil
			}
		case "product":
			if grant.ResourceID != "" {
				products[grant.ResourceID] = struct{}{}
			}
		case "project":
			if grant.ResourceID != "" {
				projects[grant.ResourceID] = struct{}{}
			}
		case "release":
			if grant.ResourceID != "" {
				releases[grant.ResourceID] = struct{}{}
			}
		}
	}
	return false, sortedArtifactGrantIDs(products), sortedArtifactGrantIDs(projects), sortedArtifactGrantIDs(releases)
}

func sortedArtifactGrantIDs(set map[string]struct{}) []string {
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
