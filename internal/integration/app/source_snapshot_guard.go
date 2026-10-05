package app

import (
	"context"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// ValidateSourceSnapshotRaw bounds every raw component before a composed
// transaction can write. Semantic rules remain in the owning child commands,
// including late failures for standalone callers of RecordSourceSnapshot.
func ValidateSourceSnapshotRaw(provider string, in SourceSnapshotInput) error {
	if provider != "github" && provider != "gitlab" {
		return ErrValidation
	}
	if !validSourceText(in.ProjectID, 1024, true) {
		return ErrValidation
	}
	for _, v := range []string{in.Repository.FullName, in.Repository.CloneURL, in.Repository.DefaultBranch} {
		if !validSourceText(v, MaxSourceTextBytes, true) {
			return ErrValidation
		}
	}
	if v := in.Commit; v != nil {
		if !validSourceText(v.SHA, 1024, true) || !validSourceText(v.Author, MaxSourceTextBytes, true) || len(v.Message) > MaxSourceTextBytes || !v.CommittedAt.IsZero() && !validSourceTime(v.CommittedAt) {
			return ErrValidation
		}
	}
	if v := in.Branch; v != nil {
		if !validSourceText(v.Name, MaxSourceTextBytes, true) || !validSourceText(v.ProtectionHash, MaxSourceTextBytes, true) {
			return ErrValidation
		}
	}
	if v := in.PullRequest; v != nil {
		for _, text := range []string{v.ProviderID, v.Title, v.State, v.SourceBranch, v.TargetBranch, v.ReviewDecision} {
			if !validSourceText(text, MaxSourceTextBytes, true) {
				return ErrValidation
			}
		}
	}
	return nil
}

// ValidateSourceSnapshotRequest checks the public nested request without
// looking up or allocating generated relationship IDs. The constant below is
// only a nonempty placeholder for pure child-input validation, never a query
// argument or a stored ID. Fresh children enforce their actual key budgets.
func ValidateSourceSnapshotRequest(provider string, in SourceSnapshotInput) error {
	if err := ValidateSourceSnapshotRaw(provider, in); err != nil {
		return err
	}
	if _, err := NormalizeSourceRepositoryInput(snapshotRepositoryInput(provider, in)); err != nil {
		return err
	}
	if v := in.Commit; v != nil {
		if _, err := NormalizeSourceCommitInput(RecordSourceCommitInput{RepositoryID: "_", SHA: v.SHA, Author: v.Author, Message: v.Message, CommittedAt: v.CommittedAt}); err != nil {
			return err
		}
	}
	if v := in.Branch; v != nil {
		if _, err := NormalizeSourceBranchInput(UpsertSourceBranchInput{RepositoryID: "_", Name: v.Name, Protected: v.Protected, ProtectionHash: v.ProtectionHash}); err != nil {
			return err
		}
	}
	if v := in.PullRequest; v != nil {
		if _, err := NormalizePullRequestInput(RecordPullRequestInput{RepositoryID: "_", Provider: provider, ProviderID: v.ProviderID, Title: v.Title, State: v.State, SourceBranch: v.SourceBranch, TargetBranch: v.TargetBranch, ReviewDecision: v.ReviewDecision}); err != nil {
			return err
		}
	}
	return nil
}

func snapshotRepositoryInput(provider string, in SourceSnapshotInput) CreateSourceRepositoryInput {
	return CreateSourceRepositoryInput{ProjectID: in.ProjectID, Provider: provider, FullName: in.Repository.FullName, CloneURL: in.Repository.CloneURL, DefaultBranch: in.Repository.DefaultBranch}
}

func ValidateSourceSnapshotKeys(tenant, provider string, in SourceSnapshotInput) error {
	repo, err := NormalizeSourceRepositoryInput(snapshotRepositoryInput(provider, in))
	if err != nil {
		return err
	}
	if err := ValidateSourceRepositoryKey(tenant, repo); err != nil {
		return err
	}
	if v := in.Branch; v != nil {
		branch, err := NormalizeSourceBranchInput(UpsertSourceBranchInput{RepositoryID: "_", Name: v.Name, Protected: v.Protected, ProtectionHash: v.ProtectionHash})
		if err != nil {
			return err
		}
		// A real repository ID is at least one byte. Reject impossible keys
		// before replay; fresh execution checks the actual returned ID as well.
		return ValidateSourceBranchKey(tenant, branch)
	}
	return nil
}

func (s *SourceSnapshotCommands) AuthorizeSourceSnapshot(ctx context.Context, a identitydomain.Actor, provider string, in SourceSnapshotInput) error {
	if s == nil {
		return ErrValidation
	}
	if err := prepareSourceWrite(ctx, a, s.config.Authorizer); err != nil {
		return err
	}
	if err := ValidateSourceSnapshotRequest(provider, in); err != nil {
		return err
	}
	if err := ValidateSourceSnapshotKeys(a.TenantID, provider, in); err != nil {
		return err
	}
	return s.config.Transactions.ExecuteSourceSnapshot(ctx, func(ctx context.Context, tx SourceSnapshotTransaction) error {
		return tx.AuthorizeSourceRepositoryCreation(ctx, a, snapshotRepositoryInput(provider, in))
	})
}
