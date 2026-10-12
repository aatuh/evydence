package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	"github.com/aatuh/evydence/internal/platform/redaction"
)

type evidenceRelationshipFixtureFacts interface {
	evidenceapp.RelationshipScopeTransaction
	ReadRelationshipEvidence(context.Context, string, string) (evidencedomain.EvidenceItem, error)
	ReadRelationshipOrigins(context.Context, string, string) ([]evidencedomain.EvidenceLifecycleEvent, error)
}

// Reuse creation's current authorization and canonicalization, not its command
// implementation or any aggregate state. The core owns relationship behavior.
type evidenceRelationshipNativeFixture struct{ evidenceCreationNativeFixture }

func (f evidenceRelationshipNativeFixture) facts(ctx context.Context, run func(context.Context, evidenceRelationshipFixtureFacts) error) error {
	return fixtureIngestionError(f.read(ctx, func(ctx context.Context, r app.Repositories) error {
		facts, ok := r.Evidence.(evidenceRelationshipFixtureFacts)
		if !ok {
			return app.ErrValidation
		}
		return run(ctx, facts)
	}))
}
func (f evidenceRelationshipNativeFixture) LockRelationshipTenant(ctx context.Context, tenant string) error {
	return f.facts(ctx, func(ctx context.Context, r evidenceRelationshipFixtureFacts) error {
		return r.LockRelationshipTenant(ctx, tenant)
	})
}
func (f evidenceRelationshipNativeFixture) LockRelationshipEvidence(ctx context.Context, tenant, id string) (application.ResourceReferences, error) {
	var v application.ResourceReferences
	err := f.facts(ctx, func(ctx context.Context, r evidenceRelationshipFixtureFacts) error {
		var err error
		v, err = r.LockRelationshipEvidence(ctx, tenant, id)
		return err
	})
	if err != nil {
		return application.ResourceReferences{}, err
	}
	return v, nil
}
func (f evidenceRelationshipNativeFixture) LockRelationshipTarget(ctx context.Context, tenant, kind, id string) (application.ResourceReferences, error) {
	var v application.ResourceReferences
	err := f.facts(ctx, func(ctx context.Context, r evidenceRelationshipFixtureFacts) error {
		var err error
		v, err = r.LockRelationshipTarget(ctx, tenant, kind, id)
		return err
	})
	if err != nil {
		return application.ResourceReferences{}, err
	}
	return v, nil
}
func (f evidenceRelationshipNativeFixture) GetEvidence(ctx context.Context, tenant, id string) (evidencedomain.EvidenceItem, error) {
	if f.readOnly {
		panic("relationship replay read canonical evidence")
	}
	var v evidencedomain.EvidenceItem
	err := f.facts(ctx, func(ctx context.Context, r evidenceRelationshipFixtureFacts) error {
		if _, err := r.LockRelationshipEvidence(ctx, tenant, id); err != nil {
			return err
		}
		var err error
		v, err = r.ReadRelationshipEvidence(ctx, tenant, id)
		return err
	})
	if err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	return v, nil
}
func (f evidenceRelationshipNativeFixture) ValidateLinkTarget(ctx context.Context, tenant, kind, id string) error {
	_, err := f.LockRelationshipTarget(ctx, tenant, kind, id)
	return err
}
func (f evidenceRelationshipNativeFixture) ListRelationshipOrigins(ctx context.Context, tenant, id string) ([]evidencedomain.EvidenceLifecycleEvent, error) {
	if f.readOnly {
		panic("relationship replay read origin metadata")
	}
	var v []evidencedomain.EvidenceLifecycleEvent
	err := f.facts(ctx, func(ctx context.Context, r evidenceRelationshipFixtureFacts) error {
		var err error
		v, err = r.ReadRelationshipOrigins(ctx, tenant, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return v, nil
}
func (f evidenceRelationshipNativeFixture) ExecuteEvidenceRelationships(ctx context.Context, run func(context.Context, evidenceapp.RelationshipTransaction) error) error {
	if ctx == nil || run == nil {
		return evidenceapp.ErrValidation
	}
	return fixtureIngestionError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		if _, ok := r.Evidence.(evidenceRelationshipFixtureFacts); !ok || r.Audit == nil {
			return app.ErrValidation
		}
		bound := f
		bound.repositories = &r
		return run(ctx, bound)
	}))
}
func (f evidenceRelationshipNativeFixture) RecordSupersession(ctx context.Context, first, replacement evidencedomain.EvidenceItem) error {
	if f.readOnly || f.repositories == nil {
		panic("relationship replay/unbound supersession")
	}
	return fixtureIngestionError(f.repositories.Evidence.RecordSupersession(ctx, domain.EvidenceFromContextModel(first), domain.EvidenceFromContextModel(replacement)))
}
func (f evidenceRelationshipNativeFixture) CompareAndSwapEvidenceLinks(ctx context.Context, first, replacement evidencedomain.EvidenceItem) error {
	if f.readOnly || f.repositories == nil {
		panic("relationship replay/unbound link")
	}
	return fixtureIngestionError(f.repositories.Evidence.CompareAndSwapEvidenceLinks(ctx, domain.EvidenceFromContextModel(first), domain.EvidenceFromContextModel(replacement)))
}
func (f evidenceRelationshipNativeFixture) AppendLifecycle(ctx context.Context, e evidencedomain.EvidenceLifecycleEvent) error {
	if f.readOnly || f.repositories == nil {
		panic("relationship replay/unbound lifecycle")
	}
	return fixtureIngestionError(f.repositories.Evidence.AppendLifecycle(ctx, fixtureLifecycleRecord(e)))
}
func fixtureLifecycleRecord(e evidencedomain.EvidenceLifecycleEvent) domain.EvidenceLifecycleEvent {
	return domain.EvidenceLifecycleEvent{ID: e.ID, TenantID: e.TenantID, EvidenceID: e.EvidenceID, Action: e.Action.String(), Reason: e.Reason, Details: e.Details, ReplacementID: e.ReplacementID, ActorID: e.ActorID, SchemaVersion: e.SchemaVersion, CreatedAt: e.CreatedAt}
}
func (f evidenceRelationshipNativeFixture) SanitizeLifecycle(ctx context.Context, reason string, details map[string]any) (string, map[string]any, error) {
	if f.readOnly {
		panic("relationship replay sanitized metadata")
	}
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
func (f evidenceFixtureCommands) nativeRelationships(readOnly bool) (*evidenceapp.RelationshipCommands, error) {
	ports := evidenceRelationshipNativeFixture{evidenceCreationNativeFixture{catalogFixtureCommands: f.catalogFixtureCommands, readOnly: readOnly}}
	auth, err := ports.authorizer()
	if err != nil {
		return nil, err
	}
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	return evidenceapp.NewRelationshipCommands(evidenceapp.RelationshipCommandConfig{Reader: ports, Transactions: ports, Authorizer: auth, Canonicalizer: ports, LifecycleSanitizer: ports, CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion, Clock: clock, IDs: ids})
}

var _ evidenceapp.RelationshipScopeTransaction = evidenceRelationshipNativeFixture{}
