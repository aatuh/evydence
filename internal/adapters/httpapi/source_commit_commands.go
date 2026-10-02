package httpapi

import (
	"github.com/aatuh/evydence/internal/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

func sourceCommitFromCommand(v integrationdomain.SourceCommit) domain.SourceCommit {
	return domain.SourceCommit{ID: v.ID, TenantID: v.TenantID, RepositoryID: v.RepositoryID, SHA: v.SHA, Author: v.Author, MessageHash: v.MessageHash, CommittedAt: v.CommittedAt, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
