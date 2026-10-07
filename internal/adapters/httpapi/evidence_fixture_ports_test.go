package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// These adapters preserve existing local HTTP assertions with real ownership
// guards and isolated replay effects. They are not production runtime ports.
type evidenceFixtureCommands struct{ catalogFixtureCommands }

func (f evidenceFixtureCommands) AuthorizeEvidenceCreation(ctx context.Context, actor identitydomain.Actor, input evidenceapp.CreateEvidenceInput) error {
	return f.commandLedger(ctx).AuthorizeEvidenceCreation(ctx, actor, input)
}
func (f evidenceFixtureCommands) AuthorizeSupersedeEvidence(ctx context.Context, actor identitydomain.Actor, id, replacement, reason string) error {
	return f.commandLedger(ctx).AuthorizeSupersedeEvidence(ctx, actor, id, replacement, reason)
}
func (f evidenceFixtureCommands) AuthorizeLinkEvidence(ctx context.Context, actor identitydomain.Actor, id, kind, target string) error {
	return f.commandLedger(ctx).AuthorizeLinkEvidence(ctx, actor, id, kind, target)
}
func (f evidenceFixtureCommands) AuthorizeLifecycleEvent(ctx context.Context, actor identitydomain.Actor, id string, input evidenceapp.RecordLifecycleInput) error {
	return f.commandLedger(ctx).AuthorizeLifecycleEvent(ctx, actor, id, input)
}
func (f evidenceFixtureCommands) CreateEvidence(ctx context.Context, actor identitydomain.Actor, input evidenceapp.CreateEvidenceInput) (evidencedomain.EvidenceItem, error) {
	refs := make([]domain.SubjectRef, 0, len(input.SubjectRefs))
	for _, ref := range input.SubjectRefs {
		refs = append(refs, domain.SubjectRef{Type: ref.Type, ID: ref.ID, Digest: ref.Digest})
	}
	value, err := f.commandLedger(ctx).CreateEvidence(ctx, actor, app.CreateEvidenceInput{ProductID: input.ProductID, ProjectID: input.ProjectID, ReleaseID: input.ReleaseID, BuildID: input.BuildID, DeploymentID: input.DeploymentID, Type: input.Type, Subtype: input.Subtype, Title: input.Title, SourceSystem: input.SourceSystem, SourceIdentity: input.SourceIdentity, CollectorID: input.CollectorID, ObservedAt: input.ObservedAt, PayloadRef: input.PayloadRef, PayloadHash: input.PayloadHash, PayloadMediaType: input.PayloadMediaType, PayloadSize: input.PayloadSize, SubjectRefs: refs, Metadata: input.Metadata, Tags: input.Tags, Limitations: input.Limitations})
	return domain.EvidenceToContextModel(value), err
}
func (f evidenceFixtureCommands) SupersedeEvidence(ctx context.Context, actor identitydomain.Actor, id, replacement, reason string) (evidencedomain.EvidenceItem, error) {
	value, err := f.commandLedger(ctx).SupersedeEvidence(ctx, actor, id, replacement, reason)
	return domain.EvidenceToContextModel(value), err
}
func (f evidenceFixtureCommands) LinkEvidence(ctx context.Context, actor identitydomain.Actor, id, kind, target string) (evidencedomain.EvidenceItem, error) {
	value, err := f.commandLedger(ctx).LinkEvidence(ctx, actor, id, kind, target)
	return domain.EvidenceToContextModel(value), err
}
func (f evidenceFixtureCommands) RecordLifecycleEvent(ctx context.Context, actor identitydomain.Actor, id string, input evidenceapp.RecordLifecycleInput) (evidencedomain.EvidenceLifecycleEvent, error) {
	value, err := f.commandLedger(ctx).RecordEvidenceLifecycleEvent(ctx, actor, id, app.RecordEvidenceLifecycleInput{Action: input.Action, Reason: input.Reason, Details: input.Details, ReplacementID: input.ReplacementID})
	if err != nil {
		return evidencedomain.EvidenceLifecycleEvent{}, err
	}
	action, err := evidencedomain.ParseEvidenceLifecycleState(value.Action)
	if err != nil {
		return evidencedomain.EvidenceLifecycleEvent{}, evidenceapp.ErrConflict
	}
	return evidencedomain.EvidenceLifecycleEvent{ID: value.ID, TenantID: value.TenantID, EvidenceID: value.EvidenceID, Action: action, Reason: value.Reason, Details: value.Details, ReplacementID: value.ReplacementID, ActorID: value.ActorID, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt}, nil
}

func (s *Server) bindEvidenceFixturePorts(ledger *app.Ledger) {
	commands := evidenceFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.evidenceCreationCommands.(evidenceFixtureCommands); s.evidenceCreationCommands == nil || fixture {
		s.evidenceCreationCommands = commands
	}
	if _, fixture := s.evidenceRelationshipCommands.(evidenceFixtureCommands); s.evidenceRelationshipCommands == nil || fixture {
		s.evidenceRelationshipCommands = commands
	}
}

var (
	_ EvidenceCreationCommands     = evidenceFixtureCommands{}
	_ EvidenceRelationshipCommands = evidenceFixtureCommands{}
)
