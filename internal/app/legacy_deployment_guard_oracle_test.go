package app

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
)

func validateLocalDeploymentActor(ctx context.Context, a domain.Actor) error {
	if ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := require(a, ScopeDeploymentWrite); err != nil {
		return err
	}
	if a.TenantID == "" || len(a.TenantID) > 1024 || !utf8.ValidString(a.TenantID) || strings.ContainsRune(a.TenantID, 0) || strings.TrimSpace(a.TenantID) != a.TenantID {
		return ErrValidation
	}
	return nil
}
func (l *Ledger) AuthorizeEnvironmentCreation(ctx context.Context, a domain.Actor, in operationsapp.CreateEnvironmentInput) error {
	if err := validateLocalDeploymentActor(ctx, a); err != nil {
		return err
	}
	in, err := operationsapp.NormalizeEnvironmentCreationInput(in)
	if err != nil || len(a.TenantID)+len(in.ProductID)+len(in.Name) > operationsapp.MaxEnvironmentKeyBytes {
		return ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[a.TenantID]; !ok {
		return ErrNotFound
	}
	p, ok := l.products[in.ProductID]
	if !ok || p.TenantID != a.TenantID {
		return ErrNotFound
	}
	return l.authorizeResourceLocked(a, ScopeDeploymentWrite, resourceRefs{ProductID: p.ID})
}
func (l *Ledger) AuthorizeDeploymentRecording(ctx context.Context, a domain.Actor, in operationsapp.RecordDeploymentInput) error {
	if err := validateLocalDeploymentActor(ctx, a); err != nil {
		return err
	}
	in, err := operationsapp.NormalizeDeploymentRecordingInput(in)
	if err != nil {
		return ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[a.TenantID]; !ok {
		return ErrNotFound
	}
	e, ok := l.environments[in.EnvironmentID]
	if !ok || e.TenantID != a.TenantID {
		return ErrNotFound
	}
	r, ok := l.releases[in.ReleaseID]
	if !ok || r.TenantID != a.TenantID || r.ProductID != e.ProductID {
		return ErrNotFound
	}
	p, ok := l.products[e.ProductID]
	if !ok || p.TenantID != a.TenantID {
		return ErrNotFound
	}
	if err := l.authorizeResourceLocked(a, ScopeDeploymentWrite, resourceRefs{ProductID: p.ID, ReleaseID: r.ID, EnvironmentID: e.ID}); err != nil {
		return err
	}
	for _, id := range in.ArtifactIDs {
		v, ok := l.artifacts[id]
		if !ok || v.TenantID != a.TenantID {
			return ErrNotFound
		}
	}
	if in.RollbackOf != "" {
		v, ok := l.deployments[in.RollbackOf]
		if !ok || v.TenantID != a.TenantID || v.EnvironmentID != e.ID {
			return ErrNotFound
		}
	}
	return nil
}
