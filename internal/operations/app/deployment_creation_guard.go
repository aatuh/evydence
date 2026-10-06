package app

import (
	"context"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// LockDeploymentTenant acquires the shared writer fence before ownership rows.
type DeploymentTenantLocker interface {
	LockDeploymentTenant(context.Context, string) error
}

func validateDeploymentActor(ctx context.Context, a identitydomain.Actor) error {
	if ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validEnvironmentText(a.TenantID, 1024) || strings.TrimSpace(a.TenantID) != a.TenantID {
		return ErrValidation
	}
	return nil
}
func NormalizeEnvironmentCreationInput(in CreateEnvironmentInput) (CreateEnvironmentInput, error) {
	if !validEnvironmentText(in.ProductID, 1024) || !validEnvironmentText(in.Name, MaxEnvironmentTextBytes) || !validEnvironmentText(in.Kind, MaxEnvironmentTextBytes) {
		return CreateEnvironmentInput{}, ErrValidation
	}
	in.ProductID = strings.TrimSpace(in.ProductID)
	in.Name = strings.TrimSpace(in.Name)
	in.Kind = strings.TrimSpace(in.Kind)
	if in.ProductID == "" || in.Name == "" || in.Kind == "" {
		return CreateEnvironmentInput{}, ErrValidation
	}
	return in, nil
}
func NormalizeDeploymentRecordingInput(in RecordDeploymentInput) (RecordDeploymentInput, error) {
	for _, f := range []struct {
		text  string
		limit int
	}{{in.EnvironmentID, 1024}, {in.ReleaseID, 1024}, {in.RollbackOf, 1024}, {in.Status, 64}} {
		if len(f.text) > f.limit || !utf8.ValidString(f.text) || strings.ContainsRune(f.text, 0) {
			return RecordDeploymentInput{}, ErrValidation
		}
	}
	if len(in.ArtifactIDs) > MaxDeploymentArtifacts {
		return RecordDeploymentInput{}, ErrValidation
	}
	in.EnvironmentID = strings.TrimSpace(in.EnvironmentID)
	in.ReleaseID = strings.TrimSpace(in.ReleaseID)
	in.RollbackOf = strings.TrimSpace(in.RollbackOf)
	in.Status = strings.TrimSpace(in.Status)
	if in.EnvironmentID == "" || in.ReleaseID == "" {
		return RecordDeploymentInput{}, ErrValidation
	}
	switch in.Status {
	case "started", "succeeded", "failed", "rolled_back":
	default:
		return RecordDeploymentInput{}, ErrValidation
	}
	if !in.StartedAt.IsZero() {
		in.StartedAt = in.StartedAt.UTC()
	}
	if !validDeploymentTime(in.StartedAt) {
		return RecordDeploymentInput{}, ErrValidation
	}
	if in.FinishedAt != nil {
		v := in.FinishedAt.UTC()
		if !validDeploymentTime(v) {
			return RecordDeploymentInput{}, ErrValidation
		}
		in.FinishedAt = &v
	}
	for _, id := range in.ArtifactIDs {
		if !validEnvironmentText(id, 1024) || strings.TrimSpace(id) == "" {
			return RecordDeploymentInput{}, ErrValidation
		}
	}
	in.ArtifactIDs = append([]string(nil), in.ArtifactIDs...)
	for n := range in.ArtifactIDs {
		in.ArtifactIDs[n] = strings.TrimSpace(in.ArtifactIDs[n])
	}
	sort.Strings(in.ArtifactIDs)
	return in, nil
}
func authorizeEnvironmentCreationScope(ctx context.Context, tx DeploymentEnvironmentTransaction, a identitydomain.Actor, in CreateEnvironmentInput) (EnvironmentProduct, error) {
	if len(a.TenantID)+len(in.ProductID)+len(in.Name) > MaxEnvironmentKeyBytes {
		return EnvironmentProduct{}, ErrValidation
	}
	if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: "deployment:write", ScopeOnly: true}); err != nil {
		return EnvironmentProduct{}, err
	}
	if err := tx.LockDeploymentTenant(ctx, a.TenantID); err != nil {
		return EnvironmentProduct{}, err
	}
	p, err := tx.LockEnvironmentProduct(ctx, a.TenantID, in.ProductID)
	if err != nil {
		return EnvironmentProduct{}, err
	}
	if p.ID != in.ProductID || p.TenantID != a.TenantID {
		return EnvironmentProduct{}, ErrNotFound
	}
	if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: "deployment:write", Resources: application.ResourceReferences{ProductID: p.ID}}); err != nil {
		return EnvironmentProduct{}, err
	}
	return p, nil
}
func authorizeDeploymentRecordingScope(ctx context.Context, tx DeploymentTransaction, a identitydomain.Actor, in RecordDeploymentInput) (DeploymentEnvironmentIdentity, DeploymentReleaseIdentity, error) {
	var env DeploymentEnvironmentIdentity
	var release DeploymentReleaseIdentity
	if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: "deployment:write", ScopeOnly: true}); err != nil {
		return env, release, err
	}
	if err := tx.LockDeploymentTenant(ctx, a.TenantID); err != nil {
		return env, release, err
	}
	env, err := tx.LockDeploymentEnvironment(ctx, a.TenantID, in.EnvironmentID)
	if err != nil {
		return env, release, err
	}
	if env.ID != in.EnvironmentID || env.TenantID != a.TenantID || !validEnvironmentText(env.ProductID, 1024) {
		return env, release, ErrNotFound
	}
	release, err = tx.LockDeploymentRelease(ctx, a.TenantID, in.ReleaseID)
	if err != nil {
		return env, release, err
	}
	if release.ID != in.ReleaseID || release.TenantID != a.TenantID || release.ProductID != env.ProductID {
		return env, release, ErrNotFound
	}
	if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: "deployment:write", Resources: application.ResourceReferences{ProductID: env.ProductID, ReleaseID: release.ID, EnvironmentID: env.ID}}); err != nil {
		return env, release, err
	}
	if err := tx.CheckDeploymentArtifacts(ctx, a.TenantID, in.ArtifactIDs); err != nil {
		return env, release, err
	}
	if in.RollbackOf != "" {
		v, err := tx.LockDeploymentRollback(ctx, a.TenantID, in.RollbackOf)
		if err != nil {
			return env, release, err
		}
		if v.ID != in.RollbackOf || v.TenantID != a.TenantID || v.EnvironmentID != env.ID {
			return env, release, ErrNotFound
		}
	}
	return env, release, nil
}
func (s *DeploymentEnvironmentCommands) AuthorizeEnvironmentCreation(ctx context.Context, a identitydomain.Actor, in CreateEnvironmentInput) error {
	if s == nil {
		return ErrValidation
	}
	if err := validateDeploymentActor(ctx, a); err != nil {
		return err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: "deployment:write", ScopeOnly: true}); err != nil {
		return err
	}
	in, err := NormalizeEnvironmentCreationInput(in)
	if err != nil {
		return err
	}
	if len(a.TenantID)+len(in.ProductID)+len(in.Name) > MaxEnvironmentKeyBytes {
		return ErrValidation
	}
	return s.config.Transactions.ExecuteEnvironment(ctx, func(ctx context.Context, tx DeploymentEnvironmentTransaction) error {
		_, err := authorizeEnvironmentCreationScope(ctx, tx, a, in)
		return err
	})
}
func (s *DeploymentCommands) AuthorizeDeploymentRecording(ctx context.Context, a identitydomain.Actor, in RecordDeploymentInput) error {
	if s == nil {
		return ErrValidation
	}
	if err := validateDeploymentActor(ctx, a); err != nil {
		return err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: "deployment:write", ScopeOnly: true}); err != nil {
		return err
	}
	in, err := NormalizeDeploymentRecordingInput(in)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecuteDeployment(ctx, func(ctx context.Context, tx DeploymentTransaction) error {
		_, _, err := authorizeDeploymentRecordingScope(ctx, tx, a, in)
		return err
	})
}
