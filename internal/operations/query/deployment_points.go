// Package query owns bounded, authorized operations read services.
package query

import (
	"context"
	"errors"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

const scopeDeploymentRead = "deployment:read"

var (
	ErrValidation = errors.New("invalid deployment query")
	ErrNotFound   = errors.New("deployment not found")
)

// DeploymentPoint contains one deployment and the product verified through its
// tenant-owned release and environment in the same database statement.
type DeploymentPoint struct {
	Deployment operationsdomain.DeploymentEvent
	ProductID  string
}

type DeploymentPointReader interface {
	GetDeploymentPoint(context.Context, string, string) (DeploymentPoint, error)
}

type DeploymentPoints struct {
	reader DeploymentPointReader
}

func NewDeploymentPoints(reader DeploymentPointReader) (*DeploymentPoints, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return &DeploymentPoints{reader: reader}, nil
}

func (s *DeploymentPoints) GetDeployment(ctx context.Context, actor identitydomain.Actor, id string) (operationsdomain.DeploymentEvent, error) {
	if s == nil || ctx == nil || strings.TrimSpace(actor.TenantID) == "" {
		return operationsdomain.DeploymentEvent{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return operationsdomain.DeploymentEvent{}, err
	}
	if err := authorizeDeploymentRead(actor, "", ""); err != nil {
		return operationsdomain.DeploymentEvent{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return operationsdomain.DeploymentEvent{}, ErrNotFound
	}
	point, err := s.reader.GetDeploymentPoint(ctx, actor.TenantID, id)
	if err != nil {
		return operationsdomain.DeploymentEvent{}, err
	}
	deployment := point.Deployment
	if deployment.ID != id || deployment.TenantID != actor.TenantID ||
		strings.TrimSpace(point.ProductID) == "" || strings.TrimSpace(deployment.ReleaseID) == "" || strings.TrimSpace(deployment.EnvironmentID) == "" {
		return operationsdomain.DeploymentEvent{}, ErrNotFound
	}
	if err := authorizeDeploymentRead(actor, point.ProductID, deployment.ReleaseID); err != nil {
		return operationsdomain.DeploymentEvent{}, err
	}
	return deployment, nil
}

// authorizeDeploymentRead mirrors the legacy point-read boundary: credential
// scopes are sufficient for keys/collectors, while human sessions require a
// current tenant, product, or release grant. A project grant does not cover a
// deployment, even when a build on that project belongs to its release.
func authorizeDeploymentRead(actor identitydomain.Actor, productID, releaseID string) error {
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return application.ErrUnauthorized
	}
	if !actor.HasScope(scopeDeploymentRead) && !actor.HasScope("admin") {
		return application.ErrForbidden
	}
	if productID == "" && releaseID == "" || actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" {
		return nil
	}
	for _, grant := range actor.ResourceGrants {
		if !deploymentGrantHasScope(grant) {
			continue
		}
		switch grant.ResourceType {
		case "", "tenant":
			if grant.ResourceID == "" || grant.ResourceID == actor.TenantID {
				return nil
			}
		case "product":
			if grant.ResourceID == productID {
				return nil
			}
		case "release":
			if grant.ResourceID == releaseID {
				return nil
			}
		}
	}
	return application.ErrForbidden
}

func deploymentGrantHasScope(grant identitydomain.ResourceGrant) bool {
	for _, scope := range grant.Scopes {
		if scope == scopeDeploymentRead || scope == "admin" || scope == "*" {
			return true
		}
	}
	return false
}
