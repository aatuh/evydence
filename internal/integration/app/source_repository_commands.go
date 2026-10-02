// Package app owns focused integration commands without provider or storage adapters.
package app

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

var (
	ErrValidation = errors.New("invalid integration command")
	ErrNotFound   = errors.New("integration resource not found")
	ErrConflict   = errors.New("integration resource conflict")
)

const MaxSourceTextBytes = 64 << 10
const MaxSourceRepositoryKeyBytes = 2304

type SourceProjectIdentity struct{ ID, TenantID, ProductID string }
type SourceRepositoryIdentity struct{ ID, TenantID, ProjectID, ProductID string }
type SourceRepositoryCreationReader interface {
	LockRepositoryCreation(context.Context, string) error
	LockRepositoryProject(context.Context, string, string) (SourceProjectIdentity, error)
	RepositoryIdentityByName(context.Context, string, string, string) (SourceRepositoryIdentity, bool, error)
	ReadSourceRepository(context.Context, string, string) (integrationdomain.SourceRepository, error)
}
type SourceRepositoryCreationTransaction interface {
	SourceRepositoryCreationReader
	application.Authorizer
	application.AuditAppender
	InsertSourceRepository(context.Context, integrationdomain.SourceRepository) error
}
type SourceRepositoryCreationTransactions interface {
	ExecuteSourceRepository(context.Context, func(context.Context, SourceRepositoryCreationTransaction) error) error
}
type SourceRepositoryCreationConfig struct {
	Transactions SourceRepositoryCreationTransactions
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type SourceRepositoryCommands struct {
	config SourceRepositoryCreationConfig
}
type CreateSourceRepositoryInput struct{ ProjectID, Provider, FullName, CloneURL, DefaultBranch string }

func NewSourceRepositoryCommands(c SourceRepositoryCreationConfig) (*SourceRepositoryCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &SourceRepositoryCommands{c}, nil
}
func validSourceText(v string, limit int, optional bool) bool {
	return (optional || v != "") && len(v) <= limit && utf8.ValidString(v) && !strings.ContainsRune(v, 0)
}
func sourceRepositoryAuthorization(project, product string) application.AuthorizationRequest {
	r := application.AuthorizationRequest{Scope: "source:write", TenantWide: project == ""}
	if project != "" {
		r.Resources = application.ResourceReferences{ProductID: product, ProjectID: project}
	}
	return r
}
func (s *SourceRepositoryCommands) CreateSourceRepository(ctx context.Context, a identitydomain.Actor, in CreateSourceRepositoryInput) (integrationdomain.SourceRepository, error) {
	if ctx == nil {
		return integrationdomain.SourceRepository{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return integrationdomain.SourceRepository{}, err
	}
	scope := application.AuthorizationRequest{Scope: "source:write", ScopeOnly: true}
	if err := s.config.Authorizer.Authorize(ctx, a, scope); err != nil {
		return integrationdomain.SourceRepository{}, err
	}
	in.ProjectID, in.Provider, in.FullName, in.CloneURL, in.DefaultBranch = strings.TrimSpace(in.ProjectID), strings.TrimSpace(in.Provider), strings.TrimSpace(in.FullName), strings.TrimSpace(in.CloneURL), strings.TrimSpace(in.DefaultBranch)
	if !validSourceText(a.TenantID, 1024, false) || !validSourceText(in.ProjectID, 1024, true) || !validSourceText(in.Provider, MaxSourceTextBytes, false) || !validSourceText(in.FullName, MaxSourceTextBytes, false) || !validSourceText(in.CloneURL, MaxSourceTextBytes, true) || !validSourceText(in.DefaultBranch, MaxSourceTextBytes, true) || len(a.TenantID)+len(in.Provider)+len(in.FullName) > MaxSourceRepositoryKeyBytes {
		return integrationdomain.SourceRepository{}, ErrValidation
	}
	var result integrationdomain.SourceRepository
	err := s.config.Transactions.ExecuteSourceRepository(ctx, func(ctx context.Context, tx SourceRepositoryCreationTransaction) error {
		if err := tx.Authorize(ctx, a, scope); err != nil {
			return err
		}
		if err := tx.LockRepositoryCreation(ctx, a.TenantID); err != nil {
			return err
		}
		product := ""
		if in.ProjectID != "" {
			p, err := tx.LockRepositoryProject(ctx, a.TenantID, in.ProjectID)
			if err != nil {
				return err
			}
			if p.ID != in.ProjectID || p.TenantID != a.TenantID || !validSourceText(p.ProductID, 1024, false) {
				return ErrNotFound
			}
			product = p.ProductID
		}
		if err := tx.Authorize(ctx, a, sourceRepositoryAuthorization(in.ProjectID, product)); err != nil {
			return err
		}
		identity, found, err := tx.RepositoryIdentityByName(ctx, a.TenantID, in.Provider, in.FullName)
		if err != nil {
			return err
		}
		if found {
			if !validSourceText(identity.ID, 1024, false) || identity.TenantID != a.TenantID || !validSourceText(identity.ProjectID, 1024, true) || identity.ProjectID != "" && !validSourceText(identity.ProductID, 1024, false) || identity.ProjectID == "" && identity.ProductID != "" {
				return ErrNotFound
			}
			if err := tx.Authorize(ctx, a, sourceRepositoryAuthorization(identity.ProjectID, identity.ProductID)); err != nil {
				return err
			}
			v, err := tx.ReadSourceRepository(ctx, a.TenantID, identity.ID)
			if err != nil {
				return err
			}
			if v.ID != identity.ID || v.TenantID != a.TenantID || v.ProjectID != identity.ProjectID || v.Provider != in.Provider || v.FullName != in.FullName || !validSourceText(v.CloneURL, MaxSourceTextBytes, true) || !validSourceText(v.DefaultBranch, MaxSourceTextBytes, true) || v.CreatedAt.IsZero() || v.SchemaVersion != integrationdomain.SourceRepositorySchemaVersion {
				return ErrConflict
			}
			result = v
			return nil
		}
		v := integrationdomain.SourceRepository{ID: s.config.IDs.NewID("repo"), TenantID: a.TenantID, ProjectID: in.ProjectID, Provider: in.Provider, FullName: in.FullName, CloneURL: in.CloneURL, DefaultBranch: in.DefaultBranch, SchemaVersion: integrationdomain.SourceRepositorySchemaVersion, CreatedAt: s.config.Clock.Now().UTC().Truncate(time.Microsecond)}
		if err := tx.InsertSourceRepository(ctx, v); err != nil {
			return err
		}
		actorType, actorID := sourceAuditIdentity(a)
		if _, err := tx.AppendAudit(ctx, application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "source_repository.created", SubjectType: "source_repository", SubjectID: v.ID, ActorType: actorType, ActorID: actorID, OccurredAt: v.CreatedAt}); err != nil {
			return err
		}
		result = v
		return nil
	})
	if err != nil {
		return integrationdomain.SourceRepository{}, err
	}
	return result, nil
}
