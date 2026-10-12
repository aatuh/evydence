package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	"github.com/aatuh/evydence/internal/platform/redaction"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// BuildEvidenceRelationshipCommands shares the enclosing durable command UoW:
// current ownership locks, immutable-origin reads, writes, audit and replay are
// committed together, with no Ledger state loading or publication.
func BuildEvidenceRelationshipCommands(factory app.UnitOfWorkFactory) (*evidenceapp.RelationshipCommands, error) {
	if factory == nil {
		return nil, errors.New("evidence relationship transactions are required")
	}
	reads := evidenceRelationshipReads{evidenceCreationReads{factory}}
	artifacts, err := releasequery.NewArtifactWriteAuthorizer(reads)
	if err != nil {
		return nil, err
	}
	auth, err := evidencequery.NewEvidenceCreationAuthorizer(reads, artifacts)
	if err != nil {
		return nil, err
	}
	return evidenceapp.NewRelationshipCommands(evidenceapp.RelationshipCommandConfig{
		Reader: reads, Transactions: evidenceRelationshipTransactions{factory}, Authorizer: auth,
		Canonicalizer: evidenceCanonicalHasher{}, LifecycleSanitizer: evidenceRelationshipSanitizer{},
		CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion,
		Clock:                   application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }),
		IDs:                     application.IDGeneratorFunc(application.NewID),
	})
}

type evidenceRelationshipFacts interface {
	evidenceapp.RelationshipScopeTransaction
	ReadRelationshipEvidence(context.Context, string, string) (evidencedomain.EvidenceItem, error)
	ReadRelationshipOrigins(context.Context, string, string) ([]evidencedomain.EvidenceLifecycleEvent, error)
}
type evidenceRelationshipReads struct{ evidenceCreationReads }

func (r evidenceRelationshipReads) GetEvidence(ctx context.Context, tenant, id string) (evidencedomain.EvidenceItem, error) {
	var v evidencedomain.EvidenceItem
	err := app.ExecuteUnitOfWork(ctx, r.factory, func(ctx context.Context, repos app.Repositories) error {
		facts, ok := repos.Evidence.(evidenceRelationshipFacts)
		if !ok {
			return app.ErrValidation
		}
		if _, err := facts.LockRelationshipEvidence(ctx, tenant, id); err != nil {
			return err
		}
		var err error
		v, err = facts.ReadRelationshipEvidence(ctx, tenant, id)
		return err
	})
	return v, mapEvidenceCreationError(err)
}
func (r evidenceRelationshipReads) ValidateLinkTarget(ctx context.Context, tenant, kind, id string) error {
	return mapEvidenceCreationError(app.ExecuteUnitOfWork(ctx, r.factory, func(ctx context.Context, repos app.Repositories) error {
		facts, ok := repos.Evidence.(evidenceRelationshipFacts)
		if !ok {
			return app.ErrValidation
		}
		_, err := facts.LockRelationshipTarget(ctx, tenant, kind, id)
		return err
	}))
}
func (r evidenceRelationshipReads) ListRelationshipOrigins(ctx context.Context, tenant, id string) ([]evidencedomain.EvidenceLifecycleEvent, error) {
	var v []evidencedomain.EvidenceLifecycleEvent
	err := app.ExecuteUnitOfWork(ctx, r.factory, func(ctx context.Context, repos app.Repositories) error {
		facts, ok := repos.Evidence.(evidenceRelationshipFacts)
		if !ok {
			return app.ErrValidation
		}
		if _, err := facts.LockRelationshipEvidence(ctx, tenant, id); err != nil {
			return err
		}
		var err error
		v, err = facts.ReadRelationshipOrigins(ctx, tenant, id)
		return err
	})
	return v, mapEvidenceCreationError(err)
}

type evidenceRelationshipTransactions struct{ factory app.UnitOfWorkFactory }

func (r evidenceRelationshipTransactions) ExecuteEvidenceRelationships(ctx context.Context, fn func(context.Context, evidenceapp.RelationshipTransaction) error) error {
	return mapEvidenceCreationError(app.ExecuteUnitOfWork(ctx, r.factory, func(ctx context.Context, repos app.Repositories) error {
		facts, ok := repos.Evidence.(evidenceRelationshipFacts)
		scopes, valid := repos.Evidence.(evidencequery.EvidenceCreationScopeReader)
		artifacts, artifactOK := repos.ReleaseCatalog.(evidenceCreationArtifactReader)
		if !ok || !valid || !artifactOK || repos.Audit == nil {
			return app.ErrValidation
		}
		artifactPolicy, err := releasequery.NewArtifactWriteAuthorizer(creationArtifactGrants{artifacts})
		if err != nil {
			return err
		}
		auth, err := evidencequery.NewEvidenceCreationAuthorizer(scopes, artifactPolicy)
		if err != nil {
			return err
		}
		return fn(ctx, evidenceRelationshipTransaction{Authorizer: auth, facts: facts, scopes: scopes, evidence: repos.Evidence, audit: repos.Audit})
	}))
}

type evidenceRelationshipTransaction struct {
	application.Authorizer
	facts    evidenceRelationshipFacts
	scopes   evidencequery.EvidenceCreationScopeReader
	evidence app.EvidenceRepository
	audit    app.AuditRepository
}

func (t evidenceRelationshipTransaction) LockRelationshipTenant(ctx context.Context, tenant string) error {
	return mapEvidenceCreationError(t.facts.LockRelationshipTenant(ctx, tenant))
}
func (t evidenceRelationshipTransaction) LockRelationshipEvidence(ctx context.Context, tenant, id string) (application.ResourceReferences, error) {
	v, err := t.facts.LockRelationshipEvidence(ctx, tenant, id)
	return v, mapEvidenceCreationError(err)
}
func (t evidenceRelationshipTransaction) LockRelationshipTarget(ctx context.Context, tenant, kind, id string) (application.ResourceReferences, error) {
	v, err := t.facts.LockRelationshipTarget(ctx, tenant, kind, id)
	return v, mapEvidenceCreationError(err)
}
func (t evidenceRelationshipTransaction) GetEvidence(ctx context.Context, tenant, id string) (evidencedomain.EvidenceItem, error) {
	if _, err := t.LockRelationshipEvidence(ctx, tenant, id); err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	v, err := t.facts.ReadRelationshipEvidence(ctx, tenant, id)
	return v, mapEvidenceCreationError(err)
}
func (t evidenceRelationshipTransaction) ValidateScope(ctx context.Context, tenant string, scope evidenceapp.EvidenceScope) error {
	if scope.AllowPendingDeployment {
		return evidenceapp.ErrValidation
	}
	_, err := t.scopes.ResolveEvidenceCreationScope(ctx, tenant, evidenceCreationRefs(scope))
	return mapEvidenceCreationError(err)
}
func (t evidenceRelationshipTransaction) ValidateLinkTarget(ctx context.Context, tenant, kind, id string) error {
	_, err := t.LockRelationshipTarget(ctx, tenant, kind, id)
	return err
}
func (t evidenceRelationshipTransaction) RecordSupersession(ctx context.Context, first, replacement evidencedomain.EvidenceItem) error {
	return mapEvidenceCreationError(t.evidence.RecordSupersession(ctx, domain.EvidenceFromContextModel(first), domain.EvidenceFromContextModel(replacement)))
}
func (t evidenceRelationshipTransaction) CompareAndSwapEvidenceLinks(ctx context.Context, first, replacement evidencedomain.EvidenceItem) error {
	return mapEvidenceCreationError(t.evidence.CompareAndSwapEvidenceLinks(ctx, domain.EvidenceFromContextModel(first), domain.EvidenceFromContextModel(replacement)))
}
func (t evidenceRelationshipTransaction) AppendLifecycle(ctx context.Context, e evidencedomain.EvidenceLifecycleEvent) error {
	v := domain.EvidenceLifecycleEvent{ID: e.ID, TenantID: e.TenantID, EvidenceID: e.EvidenceID, Action: e.Action.String(), Reason: e.Reason, Details: e.Details, ReplacementID: e.ReplacementID, ActorID: e.ActorID, SchemaVersion: e.SchemaVersion, CreatedAt: e.CreatedAt}
	return mapEvidenceCreationError(t.evidence.AppendLifecycle(ctx, v))
}
func (t evidenceRelationshipTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	v, err := appendAuditEvent(ctx, t.audit, e)
	return v, mapEvidenceCreationError(err)
}

type evidenceRelationshipSanitizer struct{}

func (evidenceRelationshipSanitizer) SanitizeLifecycle(ctx context.Context, reason string, details map[string]any) (string, map[string]any, error) {
	if ctx == nil {
		return "", nil, evidenceapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	safe, _ := redaction.RemoveSensitive(details)
	result, _ := safe.(map[string]any)
	return redaction.RedactString(reason), result, nil
}

var _ evidenceapp.RelationshipScopeTransaction = evidenceRelationshipTransaction{}
