package app

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

const MaxSourceBranchKeyBytes = 2304

type SourceCommitIdentity struct{ ID, TenantID, RepositoryID string }
type SourceBranchReader interface {
	SourceRepositoryWriteReader
	SourceCommitIdentityByID(context.Context, string, string, string) (SourceCommitIdentity, error)
	SourceBranchByName(context.Context, string, string, string) (integrationdomain.SourceBranch, bool, error)
}
type SourceBranchTransaction interface {
	SourceBranchReader
	application.Authorizer
	application.AuditAppender
	InsertSourceBranch(context.Context, integrationdomain.SourceBranch) error
	UpdateSourceBranch(context.Context, integrationdomain.SourceBranch) error
}
type SourceBranchTransactions interface {
	ExecuteSourceBranch(context.Context, func(context.Context, SourceBranchTransaction) error) error
}
type SourceBranchConfig struct {
	Transactions SourceBranchTransactions
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type SourceBranchCommands struct{ config SourceBranchConfig }
type UpsertSourceBranchInput struct {
	RepositoryID, Name, HeadCommitID, ProtectionHash string
	Protected                                        bool
}

func NewSourceBranchCommands(c SourceBranchConfig) (*SourceBranchCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &SourceBranchCommands{c}, nil
}
func (s *SourceBranchCommands) UpsertSourceBranch(ctx context.Context, a identitydomain.Actor, in UpsertSourceBranchInput) (integrationdomain.SourceBranch, error) {
	if ctx == nil {
		return integrationdomain.SourceBranch{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return integrationdomain.SourceBranch{}, err
	}
	scope := application.AuthorizationRequest{Scope: "source:write", ScopeOnly: true}
	if err := s.config.Authorizer.Authorize(ctx, a, scope); err != nil {
		return integrationdomain.SourceBranch{}, err
	}
	headProvided := in.HeadCommitID != ""
	in.RepositoryID, in.Name, in.HeadCommitID, in.ProtectionHash = strings.TrimSpace(in.RepositoryID), strings.TrimSpace(in.Name), strings.TrimSpace(in.HeadCommitID), strings.TrimSpace(in.ProtectionHash)
	if !validSourceText(a.TenantID, 1024, false) || !validSourceText(in.RepositoryID, 1024, false) || !validSourceText(in.Name, MaxSourceTextBytes, false) || !validSourceText(in.HeadCommitID, 1024, true) || !validSourceText(in.ProtectionHash, MaxSourceTextBytes, true) || len(a.TenantID)+len(in.RepositoryID)+len(in.Name) > MaxSourceBranchKeyBytes {
		return integrationdomain.SourceBranch{}, ErrValidation
	}
	now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
	if !validSourceTime(now) {
		return integrationdomain.SourceBranch{}, ErrValidation
	}
	var result integrationdomain.SourceBranch
	err := s.config.Transactions.ExecuteSourceBranch(ctx, func(ctx context.Context, tx SourceBranchTransaction) error {
		if err := tx.Authorize(ctx, a, scope); err != nil {
			return err
		}
		r, err := tx.LockSourceRepositoryForWrite(ctx, a.TenantID, in.RepositoryID)
		if err != nil {
			return err
		}
		if err := validateSourceRepositoryIdentity(r, a.TenantID, in.RepositoryID); err != nil {
			return err
		}
		if err := tx.Authorize(ctx, a, sourceRepositoryAuthorization(r.ProjectID, r.ProductID)); err != nil {
			return err
		}
		if headProvided {
			h, err := tx.SourceCommitIdentityByID(ctx, a.TenantID, r.ID, in.HeadCommitID)
			if err != nil {
				return err
			}
			if h.ID != in.HeadCommitID || h.ID == "" || h.TenantID != a.TenantID || h.RepositoryID != r.ID {
				return ErrNotFound
			}
		}
		v, found, err := tx.SourceBranchByName(ctx, a.TenantID, r.ID, in.Name)
		if err != nil {
			return err
		}
		entryType := "source_branch.created"
		if found {
			if !validSourceText(v.ID, 1024, false) || v.TenantID != a.TenantID || v.RepositoryID != r.ID || v.Name != in.Name || !validSourceText(v.HeadCommitID, 1024, true) || !validSourceText(v.ProtectionHash, MaxSourceTextBytes, true) || v.SchemaVersion != integrationdomain.SourceBranchSchemaVersion || !validSourceTime(v.CreatedAt) {
				return ErrConflict
			}
			entryType = "source_branch.updated"
		} else {
			v = integrationdomain.SourceBranch{ID: s.config.IDs.NewID("branch"), TenantID: a.TenantID, RepositoryID: r.ID, Name: in.Name, SchemaVersion: integrationdomain.SourceBranchSchemaVersion, CreatedAt: now}
		}
		v.HeadCommitID, v.Protected, v.ProtectionHash = in.HeadCommitID, in.Protected, in.ProtectionHash
		if found {
			err = tx.UpdateSourceBranch(ctx, v)
		} else {
			err = tx.InsertSourceBranch(ctx, v)
		}
		if err != nil {
			return err
		}
		actorType, actorID := sourceAuditIdentity(a)
		if _, err := tx.AppendAudit(ctx, application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: entryType, SubjectType: "source_branch", SubjectID: v.ID, ActorType: actorType, ActorID: actorID, PayloadHash: v.ProtectionHash, OccurredAt: now}); err != nil {
			return err
		}
		result = v
		return nil
	})
	if err != nil {
		return integrationdomain.SourceBranch{}, err
	}
	return result, nil
}
