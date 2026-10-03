package httpapi

import (
	"github.com/aatuh/evydence/internal/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

func pullRequestFromCommand(v integrationdomain.PullRequest) domain.PullRequest {
	return domain.PullRequest{ID: v.ID, TenantID: v.TenantID, RepositoryID: v.RepositoryID, Provider: v.Provider, ProviderID: v.ProviderID, Title: v.Title, State: v.State, SourceBranch: v.SourceBranch, TargetBranch: v.TargetBranch, HeadCommitID: v.HeadCommitID, ReviewDecision: v.ReviewDecision, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
