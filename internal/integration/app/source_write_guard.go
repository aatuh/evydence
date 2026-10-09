package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func prepareSourceWrite(ctx context.Context, a identitydomain.Actor, auth application.Authorizer) error {
	if ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := auth.Authorize(ctx, a, application.AuthorizationRequest{Scope: "source:write", ScopeOnly: true}); err != nil {
		return err
	}
	if !validSourceText(a.TenantID, 1024, false) || strings.TrimSpace(a.TenantID) != a.TenantID {
		return ErrValidation
	}
	return nil
}

type sourceWriteScope interface {
	SourceRepositoryWriteReader
	application.Authorizer
}

func authorizeSourceWriteRepository(ctx context.Context, tx sourceWriteScope, a identitydomain.Actor, id string) (SourceRepositoryIdentity, error) {
	if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: "source:write", ScopeOnly: true}); err != nil {
		return SourceRepositoryIdentity{}, err
	}
	r, err := tx.LockSourceRepositoryForWrite(ctx, a.TenantID, id)
	if err != nil {
		return r, err
	}
	if err := validateSourceRepositoryIdentity(r, a.TenantID, id); err != nil {
		return r, err
	}
	return r, tx.Authorize(ctx, a, sourceRepositoryAuthorization(r.ProjectID, r.ProductID))
}

func authorizeSourceHead(ctx context.Context, tx SourceCommitIdentityReader, a identitydomain.Actor, repository, head string) error {
	if head == "" {
		return nil
	}
	h, err := tx.SourceCommitIdentityByID(ctx, a.TenantID, repository, head)
	if err != nil {
		return err
	}
	return validateSourceCommitIdentity(h, a.TenantID, repository, head)
}

func (s *SourceCommitCommands) AuthorizeSourceCommitRecording(ctx context.Context, a identitydomain.Actor, in RecordSourceCommitInput) error {
	if s == nil {
		return ErrValidation
	}
	if err := prepareSourceWrite(ctx, a, s.config.Authorizer); err != nil {
		return err
	}
	in, err := NormalizeSourceCommitInput(in)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecuteSourceCommit(ctx, func(ctx context.Context, tx SourceCommitTransaction) error {
		_, err := authorizeSourceWriteRepository(ctx, tx, a, in.RepositoryID)
		return err
	})
}

func (s *SourceBranchCommands) AuthorizeSourceBranchUpsert(ctx context.Context, a identitydomain.Actor, in UpsertSourceBranchInput) error {
	if s == nil {
		return ErrValidation
	}
	if err := prepareSourceWrite(ctx, a, s.config.Authorizer); err != nil {
		return err
	}
	in, err := NormalizeSourceBranchInput(in)
	if err != nil {
		return err
	}
	if err := ValidateSourceBranchKey(a.TenantID, in); err != nil {
		return err
	}
	return s.config.Transactions.ExecuteSourceBranch(ctx, func(ctx context.Context, tx SourceBranchTransaction) error {
		r, err := authorizeSourceWriteRepository(ctx, tx, a, in.RepositoryID)
		if err != nil {
			return err
		}
		return authorizeSourceHead(ctx, tx, a, r.ID, in.HeadCommitID)
	})
}

func (s *PullRequestCommands) AuthorizePullRequestRecording(ctx context.Context, a identitydomain.Actor, in RecordPullRequestInput) error {
	if s == nil {
		return ErrValidation
	}
	if err := prepareSourceWrite(ctx, a, s.config.Authorizer); err != nil {
		return err
	}
	in, err := NormalizePullRequestInput(in)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecutePullRequest(ctx, func(ctx context.Context, tx PullRequestTransaction) error {
		r, err := authorizeSourceWriteRepository(ctx, tx, a, in.RepositoryID)
		if err != nil {
			return err
		}
		return authorizeSourceHead(ctx, tx, a, r.ID, in.HeadCommitID)
	})
}
