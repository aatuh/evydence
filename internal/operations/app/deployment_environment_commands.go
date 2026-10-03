package app

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

var (
	ErrNotFound = errors.New("operations resource not found")
	ErrConflict = errors.New("operations resource conflict")
)

const MaxEnvironmentTextBytes = 64 << 10

// Keep the unique tenant/product/name key below the PostgreSQL B-tree tuple
// limit on supported 8 KiB-page deployments, without relying on compression.
const MaxEnvironmentKeyBytes = 2304

type EnvironmentProduct struct{ ID, TenantID string }
type DeploymentEnvironmentReader interface {
	LockEnvironmentProduct(context.Context, string, string) (EnvironmentProduct, error)
	EnvironmentByName(context.Context, string, string, string) (operationsdomain.DeploymentEnvironment, bool, error)
}
type DeploymentEnvironmentTransaction interface {
	DeploymentEnvironmentReader
	application.Authorizer
	application.AuditAppender
	InsertEnvironment(context.Context, operationsdomain.DeploymentEnvironment) error
}
type DeploymentEnvironmentTransactions interface {
	ExecuteEnvironment(context.Context, func(context.Context, DeploymentEnvironmentTransaction) error) error
}
type DeploymentEnvironmentConfig struct {
	Transactions DeploymentEnvironmentTransactions
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type DeploymentEnvironmentCommands struct{ config DeploymentEnvironmentConfig }
type CreateEnvironmentInput struct{ ProductID, Name, Kind string }

func NewDeploymentEnvironmentCommands(c DeploymentEnvironmentConfig) (*DeploymentEnvironmentCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &DeploymentEnvironmentCommands{c}, nil
}
func validEnvironmentText(v string, limit int) bool {
	return v != "" && len(v) <= limit && utf8.ValidString(v) && !strings.ContainsRune(v, 0)
}
func (s *DeploymentEnvironmentCommands) CreateDeploymentEnvironment(ctx context.Context, a identitydomain.Actor, in CreateEnvironmentInput) (operationsdomain.DeploymentEnvironment, error) {
	if ctx == nil {
		return operationsdomain.DeploymentEnvironment{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return operationsdomain.DeploymentEnvironment{}, err
	}
	scope := application.AuthorizationRequest{Scope: "deployment:write", ScopeOnly: true}
	if err := s.config.Authorizer.Authorize(ctx, a, scope); err != nil {
		return operationsdomain.DeploymentEnvironment{}, err
	}
	in.ProductID, in.Name, in.Kind = strings.TrimSpace(in.ProductID), strings.TrimSpace(in.Name), strings.TrimSpace(in.Kind)
	if !validEnvironmentText(a.TenantID, 1024) || !validEnvironmentText(in.ProductID, 1024) || !validEnvironmentText(in.Name, MaxEnvironmentTextBytes) || !validEnvironmentText(in.Kind, MaxEnvironmentTextBytes) || len(a.TenantID)+len(in.ProductID)+len(in.Name) > MaxEnvironmentKeyBytes {
		return operationsdomain.DeploymentEnvironment{}, ErrValidation
	}
	var result operationsdomain.DeploymentEnvironment
	err := s.config.Transactions.ExecuteEnvironment(ctx, func(ctx context.Context, tx DeploymentEnvironmentTransaction) error {
		if err := tx.Authorize(ctx, a, scope); err != nil {
			return err
		}
		p, err := tx.LockEnvironmentProduct(ctx, a.TenantID, in.ProductID)
		if err != nil {
			return err
		}
		if p.ID != in.ProductID || p.TenantID != a.TenantID {
			return ErrNotFound
		}
		if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: "deployment:write", Resources: application.ResourceReferences{ProductID: p.ID}}); err != nil {
			return err
		}
		v, found, err := tx.EnvironmentByName(ctx, a.TenantID, p.ID, in.Name)
		if err != nil {
			return err
		}
		if found {
			if v.TenantID != a.TenantID || v.ProductID != p.ID || v.Name != in.Name || !validEnvironmentText(v.ID, 1024) || !validEnvironmentText(v.Kind, MaxEnvironmentTextBytes) || v.CreatedAt.IsZero() || v.SchemaVersion != operationsdomain.DeploymentEnvironmentVersion {
				return ErrConflict
			}
			result = v
			return nil
		}
		at := s.config.Clock.Now().UTC()
		v = operationsdomain.DeploymentEnvironment{ID: s.config.IDs.NewID("env"), TenantID: a.TenantID, ProductID: p.ID, Name: in.Name, Kind: in.Kind, SchemaVersion: operationsdomain.DeploymentEnvironmentVersion, CreatedAt: at}
		if err := tx.InsertEnvironment(ctx, v); err != nil {
			return err
		}
		actorType, actorID := "api_key", a.KeyID
		if a.CollectorID != "" {
			actorType, actorID = "collector", a.CollectorID
		} else if a.UserID != "" {
			actorType, actorID = "human_user", a.UserID
		}
		if _, err := tx.AppendAudit(ctx, application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "deployment_environment.created", SubjectType: "deployment_environment", SubjectID: v.ID, ActorType: actorType, ActorID: actorID, OccurredAt: at}); err != nil {
			return err
		}
		result = v
		return nil
	})
	if err != nil {
		return operationsdomain.DeploymentEnvironment{}, err
	}
	return result, nil
}
