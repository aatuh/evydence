package app

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func (s *Service) relationshipCommands() (*RelationshipCommands, error) {
	return NewRelationshipCommands(RelationshipCommandConfig{Reader: serviceRelationshipReader{s.reader}, Transactions: serviceRelationshipTransactions{s.transactions}, Authorizer: s.authorizer, Canonicalizer: s.canonicalizer, LifecycleSanitizer: s.lifecycleSanitizer, CanonicalizationProfile: s.canonicalizationProfile, Clock: s.clock, IDs: s.ids})
}

type serviceRelationshipReader struct{ Reader }

func (r serviceRelationshipReader) ListRelationshipOrigins(ctx context.Context, tenant, id string) ([]evidencedomain.EvidenceLifecycleEvent, error) {
	return r.ListLifecycleEvents(ctx, tenant, id)
}

type serviceRelationshipTransactions struct{ runner TransactionRunner }

func (t serviceRelationshipTransactions) ExecuteEvidenceRelationships(ctx context.Context, fn func(context.Context, RelationshipTransaction) error) error {
	return t.runner.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		return fn(ctx, serviceRelationshipTransaction{tx.Evidence(), tx, tx.Audit()})
	})
}

type serviceRelationshipTransaction struct {
	Repository
	application.Authorizer
	application.AuditAppender
}
