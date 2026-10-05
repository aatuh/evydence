package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type ProjectCommands interface {
	AuthorizeProjectCreation(context.Context, identitydomain.Actor, releaseapp.CreateProjectInput) error
	CreateProject(context.Context, identitydomain.Actor, releaseapp.CreateProjectInput) (releasedomain.Project, error)
}

func projectFromCommand(v releasedomain.Project) domain.Project {
	return domain.Project{ID: v.ID, TenantID: v.TenantID, ProductID: v.ProductID, Name: v.Name, CreatedAt: v.CreatedAt}
}
