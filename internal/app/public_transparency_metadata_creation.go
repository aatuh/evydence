package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	d "github.com/aatuh/evydence/internal/experimental/domain"
)

func publicTransparencyLogInput(in CreatePublicTransparencyLogInput) experimentalapp.PublicTransparencyLogInput {
	return experimentalapp.PublicTransparencyLogInput{Name: in.Name, Endpoint: in.Endpoint, PublicKey: in.PublicKey}
}
func publicTransparencyPublicationInput(in PublishPublicTransparencyLogEntryInput) experimentalapp.PublicTransparencyPublicationInput {
	return experimentalapp.PublicTransparencyPublicationInput{LogID: in.LogID, CheckpointID: in.CheckpointID, ExternalID: in.ExternalID}
}
func PublicTransparencyLogLegacyRecord(v d.PublicTransparencyLog) domain.PublicTransparencyLog {
	return domain.PublicTransparencyLog{ID: v.ID, TenantID: v.TenantID, Name: v.Name, Endpoint: v.Endpoint, PublicKey: v.PublicKey, State: v.State, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}

// Creation-only mapper deliberately carries no inclusion-verification fields.
func PublicTransparencyPublicationLegacyRecord(v d.PublicTransparencyLogEntry) domain.PublicTransparencyLogEntry {
	return domain.PublicTransparencyLogEntry{ID: v.ID, TenantID: v.TenantID, LogID: v.LogID, CheckpointID: v.CheckpointID, MerkleBatchID: v.MerkleBatchID, ExternalID: v.ExternalID, EntryHash: v.EntryHash, State: v.State, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
func (l *Ledger) AuthorizeCreatePublicTransparencyLog(ctx context.Context, a domain.Actor, in CreatePublicTransparencyLogInput) error {
	if err := experimentalapp.AuthorizePublicTransparencyMetadataActor(ctx, a); err != nil {
		return fromExperimentalCommandError(err)
	}
	if _, err := experimentalapp.NormalizePublicTransparencyLogInput(publicTransparencyLogInput(in)); err != nil {
		return fromExperimentalCommandError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[a.TenantID]; !ok {
		return ErrNotFound
	}
	return ctx.Err()
}
func (l *Ledger) AuthorizePublishPublicTransparencyLogEntry(ctx context.Context, a domain.Actor, in PublishPublicTransparencyLogEntryInput) error {
	if err := experimentalapp.AuthorizePublicTransparencyMetadataActor(ctx, a); err != nil {
		return fromExperimentalCommandError(err)
	}
	v, err := experimentalapp.NormalizePublicTransparencyPublicationInput(publicTransparencyPublicationInput(in))
	if err != nil {
		return fromExperimentalCommandError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.publicTransparencyPublicationSourceLocked(ctx, a.TenantID, v)
	return err
}
func (l *Ledger) publicTransparencyPublicationSourceLocked(ctx context.Context, tenant string, in experimentalapp.PublicTransparencyPublicationInput) (experimentalapp.PublicTransparencyPublicationSource, error) {
	if _, ok := l.tenants[tenant]; !ok {
		return experimentalapp.PublicTransparencyPublicationSource{}, ErrNotFound
	}
	log, ok := l.publicLogs[in.LogID]
	if !ok || log.TenantID != tenant {
		return experimentalapp.PublicTransparencyPublicationSource{}, ErrNotFound
	}
	checkpoint, ok := l.transparency[in.CheckpointID]
	if !ok || checkpoint.TenantID != tenant {
		return experimentalapp.PublicTransparencyPublicationSource{}, ErrNotFound
	}
	batch, ok := l.merkleBatches[checkpoint.BatchID]
	if !ok || batch.TenantID != tenant {
		return experimentalapp.PublicTransparencyPublicationSource{}, ErrNotFound
	}
	s := experimentalapp.PublicTransparencyPublicationSource{TenantID: tenant, LogID: log.ID, CheckpointID: checkpoint.ID, BatchID: batch.ID, RootHash: batch.RootHash}
	if err := experimentalapp.ValidatePublicTransparencyPublicationSource(tenant, in, s); err != nil {
		return experimentalapp.PublicTransparencyPublicationSource{}, fromExperimentalCommandError(err)
	}
	return s, ctx.Err()
}
