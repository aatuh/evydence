package httpapi

import (
	"context"
	"slices"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	e "github.com/aatuh/evydence/internal/experimental/app"
	d "github.com/aatuh/evydence/internal/experimental/domain"
)

// Real focused services run on transaction repositories, not historical
// Ledger generators. Fake I/O is not undone by rollback; these tests do not
// establish SQL locking, durability or external public-log trust.
type transparencyFixtureCommands struct {
	catalogFixtureCommands
	fetcher app.TransparencyProofFetcher
	clock   application.Clock
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
	c, err := f.nativeMetadata(true)
	if err != nil {
		return err
	}
	return c.AuthorizeCreatePublicTransparencyLog(ctx, a, in)
}
func (f transparencyFixtureCommands) CreatePublicTransparencyLog(ctx context.Context, a domain.Actor, in e.PublicTransparencyLogInput) (d.PublicTransparencyLog, error) {
	c, err := f.nativeMetadata(false)
	if err != nil {
		return d.PublicTransparencyLog{}, err
	}
	return c.CreatePublicTransparencyLog(ctx, a, in)
}
func (f transparencyFixtureCommands) AuthorizePublishPublicTransparencyLogEntry(ctx context.Context, a domain.Actor, in e.PublicTransparencyPublicationInput) error {
	c, err := f.nativeMetadata(true)
	if err != nil {
		return err
	}
	return c.AuthorizePublishPublicTransparencyLogEntry(ctx, a, in)
}
func (f transparencyFixtureCommands) PublishPublicTransparencyLogEntry(ctx context.Context, a domain.Actor, in e.PublicTransparencyPublicationInput) (d.PublicTransparencyLogEntry, error) {
	c, err := f.nativeMetadata(false)
	if err != nil {
		return d.PublicTransparencyLogEntry{}, err
	}
	return c.PublishPublicTransparencyLogEntry(ctx, a, in)
}
func (f transparencyFixtureCommands) AuthorizeVerifyPublicTransparencyLogEntry(ctx context.Context, a domain.Actor, id string, in e.PublicTransparencyProofInput) error {
	c, err := f.nativeProof(true)
	if err != nil {
		return err
	}
	return c.AuthorizeVerifyPublicTransparencyLogEntry(ctx, a, id, in)
}
func (f transparencyFixtureCommands) VerifyPublicTransparencyLogEntry(ctx context.Context, a domain.Actor, id string, in e.PublicTransparencyProofInput) (d.PublicTransparencyLogEntry, error) {
	c, err := f.nativeProof(false)
	if err != nil {
		return d.PublicTransparencyLogEntry{}, err
	}
	return c.VerifyPublicTransparencyLogEntry(ctx, a, id, in)
}
func (f transparencyFixtureCommands) AuthorizeFetchPublicTransparencyLogEntryProof(ctx context.Context, a domain.Actor, id string) error {
	c, err := f.nativeFetch(true)
	if err != nil {
		return err
	}
	return c.AuthorizeFetchPublicTransparencyLogEntryProof(ctx, a, id)
}
func (f transparencyFixtureCommands) FetchAndVerifyPublicTransparencyLogEntry(ctx context.Context, a domain.Actor, id string) (d.PublicTransparencyLogEntry, error) {
	c, err := f.nativeFetch(false)
	if err != nil {
		return d.PublicTransparencyLogEntry{}, err
	}
	return c.FetchAndVerifyPublicTransparencyLogEntry(ctx, a, id)
}
func (s *Server) bindTransparencyFixturePorts(ledger *app.Ledger) {
	f := transparencyFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	if old, fixture := s.publicTransparencyMetadata.(transparencyFixtureCommands); fixture {
		old.ledger = ledger
		s.publicTransparencyMetadata = old
	} else if s.publicTransparencyMetadata == nil {
		s.publicTransparencyMetadata = f
	}
	if old, fixture := s.publicTransparencyProofs.(transparencyFixtureCommands); fixture {
		old.ledger = ledger
		s.publicTransparencyProofs = old
	} else if s.publicTransparencyProofs == nil {
		s.publicTransparencyProofs = f
	}
	if old, fixture := s.publicTransparencyFetch.(transparencyFixtureCommands); fixture {
		old.ledger = ledger
		s.publicTransparencyFetch = old
	} else if s.publicTransparencyFetch == nil {
		s.publicTransparencyFetch = f
	}
}

var (
	_ PublicTransparencyMetadataCommands = transparencyFixtureCommands{}
	_ PublicTransparencyProofCommands    = transparencyFixtureCommands{}
	_ PublicTransparencyFetchCommands    = transparencyFixtureCommands{}
)
