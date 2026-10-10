package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// These adapters preserve existing local HTTP assertions with real ownership
// guards and isolated replay effects. They are not production runtime ports.
type evidenceFixtureCommands struct{ catalogFixtureCommands }

func (f evidenceFixtureCommands) AuthorizeEvidenceCreation(ctx context.Context, actor identitydomain.Actor, input evidenceapp.CreateEvidenceInput) error {
	return (evidenceCreationNativeFixture{catalogFixtureCommands: f.catalogFixtureCommands}).AuthorizeEvidenceCreation(ctx, actor, input)
}
func (f evidenceFixtureCommands) AuthorizeSupersedeEvidence(ctx context.Context, actor identitydomain.Actor, id, replacement, reason string) error {
	c, err := f.nativeRelationships(true)
	if err != nil {
		return err
	}
	return mapEvidenceCreationCommandError(c.AuthorizeSupersedeEvidence(ctx, actor, id, replacement, reason))
}
func (f evidenceFixtureCommands) AuthorizeLinkEvidence(ctx context.Context, actor identitydomain.Actor, id, kind, target string) error {
	c, err := f.nativeRelationships(true)
	if err != nil {
		return err
	}
	return mapEvidenceCreationCommandError(c.AuthorizeLinkEvidence(ctx, actor, id, kind, target))
}
func (f evidenceFixtureCommands) AuthorizeLifecycleEvent(ctx context.Context, actor identitydomain.Actor, id string, input evidenceapp.RecordLifecycleInput) error {
	c, err := f.nativeRelationships(true)
	if err != nil {
		return err
	}
	return mapEvidenceCreationCommandError(c.AuthorizeLifecycleEvent(ctx, actor, id, input))
}
func (f evidenceFixtureCommands) CreateEvidence(ctx context.Context, actor identitydomain.Actor, input evidenceapp.CreateEvidenceInput) (evidencedomain.EvidenceItem, error) {
	return (evidenceCreationNativeFixture{catalogFixtureCommands: f.catalogFixtureCommands}).CreateEvidence(ctx, actor, input)
}
func (f evidenceFixtureCommands) SupersedeEvidence(ctx context.Context, actor identitydomain.Actor, id, replacement, reason string) (evidencedomain.EvidenceItem, error) {
	c, err := f.nativeRelationships(false)
	if err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	value, err := c.SupersedeEvidence(ctx, actor, id, replacement, reason)
	return value, mapEvidenceCreationCommandError(err)
}
func (f evidenceFixtureCommands) LinkEvidence(ctx context.Context, actor identitydomain.Actor, id, kind, target string) (evidencedomain.EvidenceItem, error) {
	c, err := f.nativeRelationships(false)
	if err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	value, err := c.LinkEvidence(ctx, actor, id, kind, target)
	return value, mapEvidenceCreationCommandError(err)
}
func (f evidenceFixtureCommands) RecordLifecycleEvent(ctx context.Context, actor identitydomain.Actor, id string, input evidenceapp.RecordLifecycleInput) (evidencedomain.EvidenceLifecycleEvent, error) {
	c, err := f.nativeRelationships(false)
	if err != nil {
		return evidencedomain.EvidenceLifecycleEvent{}, err
	}
	value, err := c.RecordLifecycleEvent(ctx, actor, id, input)
	return value, mapEvidenceCreationCommandError(err)
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
