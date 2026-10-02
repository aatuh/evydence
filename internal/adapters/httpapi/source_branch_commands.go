package httpapi

import (
	"github.com/aatuh/evydence/internal/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

func sourceBranchFromCommand(v integrationdomain.SourceBranch) domain.SourceBranch {
	return domain.SourceBranch{ID: v.ID, TenantID: v.TenantID, RepositoryID: v.RepositoryID, Name: v.Name, HeadCommitID: v.HeadCommitID, Protected: v.Protected, ProtectionHash: v.ProtectionHash, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
