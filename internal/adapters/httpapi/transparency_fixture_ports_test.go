package httpapi

import (
	"context"
	"slices"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	e "github.com/aatuh/evydence/internal/experimental/app"
	d "github.com/aatuh/evydence/internal/experimental/domain"
)

// Only historical test setup uses these adapters. Actual preflight guards run
// before every receipt lookup; writes use the isolated command clone. Provider
// I/O is explicitly fake in tests and is not rolled back by a failed write.
// These fixtures do not prove native SQL locking, bounded reads or durability.
type transparencyFixtureCommands struct{ catalogFixtureCommands }

func legacyPublicTransparencyLogInput(v e.PublicTransparencyLogInput) app.CreatePublicTransparencyLogInput {
	return app.CreatePublicTransparencyLogInput{Name: v.Name, Endpoint: v.Endpoint, PublicKey: v.PublicKey}
}
func legacyPublicTransparencyPublicationInput(v e.PublicTransparencyPublicationInput) app.PublishPublicTransparencyLogEntryInput {
	return app.PublishPublicTransparencyLogEntryInput{LogID: v.LogID, CheckpointID: v.CheckpointID, ExternalID: v.ExternalID}
}
func legacyPublicTransparencyProofInput(v e.PublicTransparencyProofInput) app.VerifyPublicTransparencyLogEntryInput {
	return app.VerifyPublicTransparencyLogEntryInput{LeafHash: v.LeafHash, RootHash: v.RootHash, LeafIndex: v.LeafIndex, TreeSize: v.TreeSize, InclusionProof: slices.Clone(v.InclusionProof)}
}
func transparencyLogFixtureModel(v domain.PublicTransparencyLog) d.PublicTransparencyLog {
	return d.PublicTransparencyLog{ID: v.ID, TenantID: v.TenantID, Name: v.Name, Endpoint: v.Endpoint, PublicKey: v.PublicKey, State: v.State, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
func transparencyEntryFixtureModel(v domain.PublicTransparencyLogEntry) d.PublicTransparencyLogEntry {
	out := d.PublicTransparencyLogEntry{ID: v.ID, TenantID: v.TenantID, LogID: v.LogID, CheckpointID: v.CheckpointID, MerkleBatchID: v.MerkleBatchID, ExternalID: v.ExternalID, EntryHash: v.EntryHash, InclusionRootHash: v.InclusionRootHash, InclusionProofHash: v.InclusionProofHash, State: v.State, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt, VerificationLimitations: slices.Clone(v.VerificationLimitations)}
	if v.InclusionVerifiedAt != nil {
		at := *v.InclusionVerifiedAt
		out.InclusionVerifiedAt = &at
	}
	for _, c := range v.VerificationChecks {
		out.VerificationChecks = append(out.VerificationChecks, d.VerificationCheck{Name: c.Name, Result: c.Result, Detail: c.Detail})
	}
	return out
}
func (f transparencyFixtureCommands) AuthorizeCreatePublicTransparencyLog(ctx context.Context, a domain.Actor, in e.PublicTransparencyLogInput) error {
	return f.commandLedger(ctx).AuthorizeCreatePublicTransparencyLog(ctx, a, legacyPublicTransparencyLogInput(in))
}
func (f transparencyFixtureCommands) CreatePublicTransparencyLog(ctx context.Context, a domain.Actor, in e.PublicTransparencyLogInput) (d.PublicTransparencyLog, error) {
	v, err := f.commandLedger(ctx).CreatePublicTransparencyLog(ctx, a, legacyPublicTransparencyLogInput(in))
	return transparencyLogFixtureModel(v), err
}
func (f transparencyFixtureCommands) AuthorizePublishPublicTransparencyLogEntry(ctx context.Context, a domain.Actor, in e.PublicTransparencyPublicationInput) error {
	return f.commandLedger(ctx).AuthorizePublishPublicTransparencyLogEntry(ctx, a, legacyPublicTransparencyPublicationInput(in))
}
func (f transparencyFixtureCommands) PublishPublicTransparencyLogEntry(ctx context.Context, a domain.Actor, in e.PublicTransparencyPublicationInput) (d.PublicTransparencyLogEntry, error) {
	v, err := f.commandLedger(ctx).PublishPublicTransparencyLogEntry(ctx, a, legacyPublicTransparencyPublicationInput(in))
	return transparencyEntryFixtureModel(v), err
}
func (f transparencyFixtureCommands) AuthorizeVerifyPublicTransparencyLogEntry(ctx context.Context, a domain.Actor, id string, in e.PublicTransparencyProofInput) error {
	return f.commandLedger(ctx).AuthorizeVerifyPublicTransparencyLogEntry(ctx, a, id, legacyPublicTransparencyProofInput(in))
}
func (f transparencyFixtureCommands) VerifyPublicTransparencyLogEntry(ctx context.Context, a domain.Actor, id string, in e.PublicTransparencyProofInput) (d.PublicTransparencyLogEntry, error) {
	v, err := f.commandLedger(ctx).VerifyPublicTransparencyLogEntry(ctx, a, id, legacyPublicTransparencyProofInput(in))
	return transparencyEntryFixtureModel(v), err
}
func (f transparencyFixtureCommands) AuthorizeFetchPublicTransparencyLogEntryProof(ctx context.Context, a domain.Actor, id string) error {
	return f.commandLedger(ctx).AuthorizeFetchPublicTransparencyLogEntryProof(ctx, a, id)
}
func (f transparencyFixtureCommands) FetchAndVerifyPublicTransparencyLogEntry(ctx context.Context, a domain.Actor, id string) (d.PublicTransparencyLogEntry, error) {
	v, err := f.commandLedger(ctx).FetchAndVerifyPublicTransparencyLogEntry(ctx, a, id)
	return transparencyEntryFixtureModel(v), err
}
func (s *Server) bindTransparencyFixturePorts(ledger *app.Ledger) {
	f := transparencyFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.publicTransparencyMetadata.(transparencyFixtureCommands); s.publicTransparencyMetadata == nil || fixture {
		s.publicTransparencyMetadata = f
	}
	if _, fixture := s.publicTransparencyProofs.(transparencyFixtureCommands); s.publicTransparencyProofs == nil || fixture {
		s.publicTransparencyProofs = f
	}
	if _, fixture := s.publicTransparencyFetch.(transparencyFixtureCommands); s.publicTransparencyFetch == nil || fixture {
		s.publicTransparencyFetch = f
	}
}

var (
	_ PublicTransparencyMetadataCommands = transparencyFixtureCommands{}
	_ PublicTransparencyProofCommands    = transparencyFixtureCommands{}
	_ PublicTransparencyFetchCommands    = transparencyFixtureCommands{}
)
