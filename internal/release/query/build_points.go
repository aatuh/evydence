package query

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

const scopeBuildRead = "build:read"

// BuildPoint carries only the tenant-verified coordinates needed to authorize
// one build read. The reader must get them from one consistent database view.
type BuildPoint struct {
	Build     releasedomain.BuildRun
	ProductID string
}

type BuildPointReader interface {
	GetBuildPoint(context.Context, string, string) (BuildPoint, error)
}

type BuildPoints struct {
	reader     BuildPointReader
	authorizer application.Authorizer
}

func NewBuildPoints(reader BuildPointReader, authorizer application.Authorizer) (*BuildPoints, error) {
	if reader == nil || authorizer == nil {
		return nil, ErrValidation
	}
	return &BuildPoints{reader: reader, authorizer: authorizer}, nil
}

func (s *BuildPoints) GetBuildRun(ctx context.Context, actor identitydomain.Actor, id string) (releasedomain.BuildRun, error) {
	if s == nil || ctx == nil || strings.TrimSpace(actor.TenantID) == "" {
		return releasedomain.BuildRun{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return releasedomain.BuildRun{}, err
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: scopeBuildRead, ScopeOnly: true}); err != nil {
		return releasedomain.BuildRun{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return releasedomain.BuildRun{}, ErrNotFound
	}
	point, err := s.reader.GetBuildPoint(ctx, actor.TenantID, id)
	if err != nil {
		return releasedomain.BuildRun{}, err
	}
	build := point.Build
	if build.ID != id || build.TenantID != actor.TenantID || strings.TrimSpace(point.ProductID) == "" || strings.TrimSpace(build.ProjectID) == "" || strings.TrimSpace(build.ReleaseID) == "" {
		return releasedomain.BuildRun{}, ErrNotFound
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{
		Scope: scopeBuildRead,
		Resources: application.ResourceReferences{
			ProductID: point.ProductID, ProjectID: build.ProjectID,
			ReleaseID: build.ReleaseID, BuildID: build.ID,
		},
	}); err != nil {
		return releasedomain.BuildRun{}, err
	}
	return build, nil
}
