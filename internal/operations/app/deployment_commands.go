package app

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

const MaxDeploymentArtifacts = 1024

type DeploymentEnvironmentIdentity struct{ ID, TenantID, ProductID string }
type DeploymentReleaseIdentity struct{ ID, TenantID, ProductID string }
type DeploymentRollbackIdentity struct{ ID, TenantID, EnvironmentID string }
type DeploymentReader interface {
	LockDeploymentEnvironment(context.Context, string, string) (DeploymentEnvironmentIdentity, error)
	LockDeploymentRelease(context.Context, string, string) (DeploymentReleaseIdentity, error)
	CheckDeploymentArtifacts(context.Context, string, []string) error
	LockDeploymentRollback(context.Context, string, string) (DeploymentRollbackIdentity, error)
}

// DeploymentEvidenceInput is the ADR 0003 fixed-shape compatibility capability.
// It cannot accept arbitrary evidence fields or update existing evidence.
type DeploymentEvidenceInput struct {
	ProductID, ReleaseID, EnvironmentID, DeploymentID, Status string
	ArtifactIDs                                               []string
	ObservedAt, CreatedAt                                     time.Time
}
type DeploymentTransaction interface {
	DeploymentReader
	application.Authorizer
	application.AuditAppender
	WriteDeploymentEvidence(context.Context, identitydomain.Actor, DeploymentEvidenceInput) (string, error)
	InsertDeployment(context.Context, operationsdomain.DeploymentEvent) error
}
type DeploymentTransactions interface {
	ExecuteDeployment(context.Context, func(context.Context, DeploymentTransaction) error) error
}
type DeploymentConfig struct {
	Transactions DeploymentTransactions
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type DeploymentCommands struct{ config DeploymentConfig }
type RecordDeploymentInput struct {
	EnvironmentID, ReleaseID, Status, RollbackOf string
	ArtifactIDs                                  []string
	StartedAt                                    time.Time
	FinishedAt                                   *time.Time
}

func NewDeploymentCommands(c DeploymentConfig) (*DeploymentCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &DeploymentCommands{c}, nil
}
func validDeploymentTime(t time.Time) bool { return t.Year() >= 1 && t.Year() <= 9999 }
func (s *DeploymentCommands) RecordDeployment(ctx context.Context, a identitydomain.Actor, in RecordDeploymentInput) (operationsdomain.DeploymentEvent, error) {
	if ctx == nil {
		return operationsdomain.DeploymentEvent{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return operationsdomain.DeploymentEvent{}, err
	}
	scope := application.AuthorizationRequest{Scope: "deployment:write", ScopeOnly: true}
	if err := s.config.Authorizer.Authorize(ctx, a, scope); err != nil {
		return operationsdomain.DeploymentEvent{}, err
	}
	in.EnvironmentID, in.ReleaseID, in.Status, in.RollbackOf = strings.TrimSpace(in.EnvironmentID), strings.TrimSpace(in.ReleaseID), strings.TrimSpace(in.Status), strings.TrimSpace(in.RollbackOf)
	if !validEnvironmentText(a.TenantID, 1024) || !validEnvironmentText(in.EnvironmentID, 1024) || !validEnvironmentText(in.ReleaseID, 1024) || in.RollbackOf != "" && !validEnvironmentText(in.RollbackOf, 1024) || len(in.ArtifactIDs) > MaxDeploymentArtifacts {
		return operationsdomain.DeploymentEvent{}, ErrValidation
	}
	switch in.Status {
	case "started", "succeeded", "failed", "rolled_back":
	default:
		return operationsdomain.DeploymentEvent{}, ErrValidation
	}
	if !validDeploymentTime(in.StartedAt) || in.FinishedAt != nil && !validDeploymentTime(*in.FinishedAt) {
		return operationsdomain.DeploymentEvent{}, ErrValidation
	}
	ids := append([]string(nil), in.ArtifactIDs...)
	for i, id := range ids {
		id = strings.TrimSpace(id)
		if !validEnvironmentText(id, 1024) {
			return operationsdomain.DeploymentEvent{}, ErrValidation
		}
		ids[i] = id
	}
	sort.Strings(ids)
	in.ArtifactIDs = ids
	var result operationsdomain.DeploymentEvent
	err := s.config.Transactions.ExecuteDeployment(ctx, func(ctx context.Context, tx DeploymentTransaction) error {
		if err := tx.Authorize(ctx, a, scope); err != nil {
			return err
		}
		env, err := tx.LockDeploymentEnvironment(ctx, a.TenantID, in.EnvironmentID)
		if err != nil {
			return err
		}
		if env.ID != in.EnvironmentID || env.TenantID != a.TenantID || !validEnvironmentText(env.ProductID, 1024) {
			return ErrNotFound
		}
		r, err := tx.LockDeploymentRelease(ctx, a.TenantID, in.ReleaseID)
		if err != nil {
			return err
		}
		if r.ID != in.ReleaseID || r.TenantID != a.TenantID || r.ProductID != env.ProductID {
			return ErrNotFound
		}
		if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: "deployment:write", Resources: application.ResourceReferences{ProductID: env.ProductID, ReleaseID: r.ID, EnvironmentID: env.ID}}); err != nil {
			return err
		}
		if err := tx.CheckDeploymentArtifacts(ctx, a.TenantID, in.ArtifactIDs); err != nil {
			return err
		}
		if in.RollbackOf != "" {
			prior, err := tx.LockDeploymentRollback(ctx, a.TenantID, in.RollbackOf)
			if err != nil {
				return err
			}
			if prior.ID != in.RollbackOf || prior.TenantID != a.TenantID || prior.EnvironmentID != env.ID {
				return ErrNotFound
			}
		}
		at := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		started := in.StartedAt.UTC().Truncate(time.Microsecond)
		if in.StartedAt.IsZero() {
			started = at
		}
		var finished *time.Time
		if in.FinishedAt != nil {
			v := in.FinishedAt.UTC().Truncate(time.Microsecond)
			finished = &v
		}
		v := operationsdomain.DeploymentEvent{ID: s.config.IDs.NewID("dep"), TenantID: a.TenantID, EnvironmentID: env.ID, ReleaseID: r.ID, ArtifactIDs: append([]string(nil), in.ArtifactIDs...), Status: in.Status, StartedAt: started, FinishedAt: finished, RollbackOf: in.RollbackOf, SchemaVersion: operationsdomain.DeploymentEventSchemaVersion, CreatedAt: at}
		v.EvidenceID, err = tx.WriteDeploymentEvidence(ctx, a, DeploymentEvidenceInput{ProductID: env.ProductID, ReleaseID: r.ID, EnvironmentID: env.ID, DeploymentID: v.ID, Status: v.Status, ArtifactIDs: append([]string{}, v.ArtifactIDs...), ObservedAt: started, CreatedAt: at})
		if err != nil {
			return err
		}
		if !validEnvironmentText(v.EvidenceID, 1024) {
			return ErrConflict
		}
		actorType, actorID := "api_key", a.KeyID
		if a.CollectorID != "" {
			actorType, actorID = "collector", a.CollectorID
		} else if a.UserID != "" {
			actorType, actorID = "human_user", a.UserID
		}
		if _, err := tx.AppendAudit(ctx, application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "deployment.recorded", SubjectType: "deployment", SubjectID: v.ID, ActorType: actorType, ActorID: actorID, OccurredAt: at}); err != nil {
			return err
		}
		if err := tx.InsertDeployment(ctx, v); err != nil {
			return err
		}
		result = v
		return nil
	})
	if err != nil {
		return operationsdomain.DeploymentEvent{}, err
	}
	return result, nil
}
