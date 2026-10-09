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
type SourceRepositoryWriteReader interface {
	LockSourceRepositoryForWrite(context.Context, string, string) (SourceRepositoryIdentity, error)
}

func validateSourceRepositoryIdentity(v SourceRepositoryIdentity, tenant, id string) error {
	if v.ID != id || !validSourceText(v.ID, 1024, false) || v.TenantID != tenant || !validSourceText(v.ProjectID, 1024, true) || v.ProjectID != "" && !validSourceText(v.ProductID, 1024, false) || v.ProjectID == "" && v.ProductID != "" {
		return ErrNotFound
	}
	return nil
}

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

// NormalizeSourceRepositoryInput checks raw byte bounds before normalization.
// The natural-key budget is checked separately with the current tenant ID.
func NormalizeSourceRepositoryInput(in CreateSourceRepositoryInput) (CreateSourceRepositoryInput, error) {
	if !validSourceText(in.ProjectID, 1024, true) || !validSourceText(in.Provider, MaxSourceTextBytes, false) || !validSourceText(in.FullName, MaxSourceTextBytes, false) || !validSourceText(in.CloneURL, MaxSourceTextBytes, true) || !validSourceText(in.DefaultBranch, MaxSourceTextBytes, true) {
		return in, ErrValidation
	}
	in.ProjectID, in.Provider, in.FullName, in.CloneURL, in.DefaultBranch = strings.TrimSpace(in.ProjectID), strings.TrimSpace(in.Provider), strings.TrimSpace(in.FullName), strings.TrimSpace(in.CloneURL), strings.TrimSpace(in.DefaultBranch)
	if in.Provider == "" || in.FullName == "" {
		return in, ErrValidation
	}
	return in, nil
}

func ValidateSourceRepositoryKey(tenant string, in CreateSourceRepositoryInput) error {
	if !validSourceText(tenant, 1024, false) || strings.TrimSpace(tenant) != tenant || len(tenant)+len(in.Provider)+len(in.FullName) > MaxSourceRepositoryKeyBytes {
		return ErrValidation
	}
	return nil
}

func (s *SourceRepositoryCommands) prepareCreation(ctx context.Context, a identitydomain.Actor, in CreateSourceRepositoryInput) (CreateSourceRepositoryInput, error) {
	if s == nil || ctx == nil {
		return in, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return in, err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: "source:write", ScopeOnly: true}); err != nil {
		return in, err
	}
	in, err := NormalizeSourceRepositoryInput(in)
	if err != nil {
		return in, err
	}
	return in, ValidateSourceRepositoryKey(a.TenantID, in)
}

// authorizeSourceRepositoryCreation reads only current tenant/project and
// natural-key ownership. It never reads repository metadata or allocates IDs.
func authorizeSourceRepositoryCreation(ctx context.Context, tx SourceRepositoryCreationTransaction, a identitydomain.Actor, in CreateSourceRepositoryInput) (SourceRepositoryIdentity, bool, error) {
	if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: "source:write", ScopeOnly: true}); err != nil {
		return SourceRepositoryIdentity{}, false, err
	}
	if err := tx.LockRepositoryCreation(ctx, a.TenantID); err != nil {
		return SourceRepositoryIdentity{}, false, err
	}
	product := ""
	if in.ProjectID != "" {
		p, err := tx.LockRepositoryProject(ctx, a.TenantID, in.ProjectID)
		if err != nil {
			return SourceRepositoryIdentity{}, false, err
		}
		if p.ID != in.ProjectID || p.TenantID != a.TenantID || !validSourceText(p.ProductID, 1024, false) {
			return SourceRepositoryIdentity{}, false, ErrNotFound
		}
		product = p.ProductID
	}
	if err := tx.Authorize(ctx, a, sourceRepositoryAuthorization(in.ProjectID, product)); err != nil {
		return SourceRepositoryIdentity{}, false, err
	}
	identity, found, err := tx.RepositoryIdentityByName(ctx, a.TenantID, in.Provider, in.FullName)
	if err != nil {
		return identity, found, err
	}
	if found {
		if err := validateSourceRepositoryIdentity(identity, a.TenantID, identity.ID); err != nil {
			return identity, found, err
		}
		if err := tx.Authorize(ctx, a, sourceRepositoryAuthorization(identity.ProjectID, identity.ProductID)); err != nil {
			return identity, found, err
		}
	}
	return identity, found, nil
}

func (s *SourceRepositoryCommands) AuthorizeSourceRepositoryCreation(ctx context.Context, a identitydomain.Actor, in CreateSourceRepositoryInput) error {
	in, err := s.prepareCreation(ctx, a, in)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecuteSourceRepository(ctx, func(ctx context.Context, tx SourceRepositoryCreationTransaction) error {
		_, _, err := authorizeSourceRepositoryCreation(ctx, tx, a, in)
		return err
	})
}

func (s *SourceRepositoryCommands) CreateSourceRepository(ctx context.Context, a identitydomain.Actor, in CreateSourceRepositoryInput) (integrationdomain.SourceRepository, error) {
	in, err := s.prepareCreation(ctx, a, in)
	if err != nil {
		return integrationdomain.SourceRepository{}, err
	}
	var result integrationdomain.SourceRepository
	err = s.config.Transactions.ExecuteSourceRepository(ctx, func(ctx context.Context, tx SourceRepositoryCreationTransaction) error {
		identity, found, err := authorizeSourceRepositoryCreation(ctx, tx, a, in)
		if err != nil {
			return err
		}
		if found {
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
