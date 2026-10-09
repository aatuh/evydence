package app

import (
	"context"

	e "github.com/aatuh/evydence/internal/experimental/app"
	d "github.com/aatuh/evydence/internal/experimental/domain"
)

// These test-backend reads project one current owned source chain. Historical
// diagnostics, log keys/names and Merkle leaf/signature arrays are not selected.
func (r memoryFutureExtensionsRepository) ReadPublicTransparencyTenant(ctx context.Context, tenant string) error {
	return memoryIdentityRepository(r).membershipRead(ctx, tenant, func(*MemoryUnitOfWorkSnapshot) error { return nil })
}
func memoryPublicTransparencyPublication(state *MemoryUnitOfWorkSnapshot, tenant, log, checkpoint string) (e.PublicTransparencyPublicationSource, error) {
	l, ok := state.PublicTransparencyLogs[log]
	if !ok || l.ID != log || l.TenantID != tenant {
		return e.PublicTransparencyPublicationSource{}, ErrNotFound
	}
	cp, ok := state.TransparencyCheckpoints[checkpoint]
	if !ok || cp.ID != checkpoint || cp.TenantID != tenant {
		return e.PublicTransparencyPublicationSource{}, ErrNotFound
	}
	b, ok := state.MerkleBatches[cp.BatchID]
	if !ok || b.ID != cp.BatchID || b.TenantID != tenant {
		return e.PublicTransparencyPublicationSource{}, ErrNotFound
	}
	s := e.PublicTransparencyPublicationSource{TenantID: tenant, LogID: l.ID, CheckpointID: cp.ID, BatchID: b.ID, RootHash: b.RootHash}
	if err := e.ValidatePublicTransparencyPublicationSource(tenant, e.PublicTransparencyPublicationInput{LogID: log, CheckpointID: checkpoint}, s); err != nil {
		return e.PublicTransparencyPublicationSource{}, fromExperimentalCommandError(err)
	}
	return s, nil
}
func (r memoryFutureExtensionsRepository) ReadPublicTransparencyPublication(ctx context.Context, tenant, log, checkpoint string) (e.PublicTransparencyPublicationSource, error) {
	if !memoryMembershipQueryText(log, e.MaxPublicTransparencyIDBytes) || !memoryMembershipQueryText(checkpoint, e.MaxPublicTransparencyIDBytes) {
		return e.PublicTransparencyPublicationSource{}, ErrValidation
	}
	var out e.PublicTransparencyPublicationSource
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		var err error
		out, err = memoryPublicTransparencyPublication(state, tenant, log, checkpoint)
		return err
	})
	if err != nil {
		return e.PublicTransparencyPublicationSource{}, err
	}
	return out, nil
}

func memoryPublicTransparencyVerification(state *MemoryUnitOfWorkSnapshot, tenant, id string) (d.PublicTransparencyLogEntry, error) {
	v, ok := state.PublicTransparencyEntries[id]
	if !ok || v.ID != id || v.TenantID != tenant {
		return d.PublicTransparencyLogEntry{}, ErrNotFound
	}
	for _, key := range []string{v.LogID, v.CheckpointID, v.MerkleBatchID, v.ExternalID} {
		if !memoryMembershipQueryText(key, e.MaxPublicTransparencyIDBytes) {
			return d.PublicTransparencyLogEntry{}, ErrValidation
		}
	}
	l, ok := state.PublicTransparencyLogs[v.LogID]
	if !ok || l.ID != v.LogID || l.TenantID != tenant {
		return d.PublicTransparencyLogEntry{}, ErrNotFound
	}
	cp, ok := state.TransparencyCheckpoints[v.CheckpointID]
	if !ok || cp.ID != v.CheckpointID || cp.TenantID != tenant || cp.BatchID != v.MerkleBatchID {
		return d.PublicTransparencyLogEntry{}, ErrNotFound
	}
	b, ok := state.MerkleBatches[v.MerkleBatchID]
	if !ok || b.ID != v.MerkleBatchID || b.TenantID != tenant {
		return d.PublicTransparencyLogEntry{}, ErrNotFound
	}
	out := d.PublicTransparencyLogEntry{ID: v.ID, TenantID: v.TenantID, LogID: v.LogID, CheckpointID: v.CheckpointID, MerkleBatchID: v.MerkleBatchID, ExternalID: v.ExternalID, EntryHash: v.EntryHash, InclusionRootHash: v.InclusionRootHash, InclusionProofHash: v.InclusionProofHash, State: v.State, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
	if v.InclusionVerifiedAt != nil {
		at := *v.InclusionVerifiedAt
		out.InclusionVerifiedAt = &at
	}
	if err := e.ValidatePublicTransparencyVerificationSource(tenant, id, out); err != nil {
		return d.PublicTransparencyLogEntry{}, fromExperimentalCommandError(err)
	}
	return out, nil
}
func (r memoryFutureExtensionsRepository) ReadPublicTransparencyVerification(ctx context.Context, tenant, id string) (d.PublicTransparencyLogEntry, error) {
	if !memoryMembershipQueryText(id, e.MaxPublicTransparencyIDBytes) {
		return d.PublicTransparencyLogEntry{}, ErrValidation
	}
	var out d.PublicTransparencyLogEntry
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		var err error
		out, err = memoryPublicTransparencyVerification(state, tenant, id)
		return err
	})
	if err != nil {
		return d.PublicTransparencyLogEntry{}, err
	}
	return out, nil
}
func (r memoryFutureExtensionsRepository) ReadPublicTransparencyFetch(ctx context.Context, tenant, id string) (e.PublicTransparencyFetchSource, error) {
	if !memoryMembershipQueryText(id, e.MaxPublicTransparencyIDBytes) {
		return e.PublicTransparencyFetchSource{}, ErrValidation
	}
	var out e.PublicTransparencyFetchSource
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		v, err := memoryPublicTransparencyVerification(state, tenant, id)
		if err != nil {
			return err
		}
		out = e.PublicTransparencyFetchSource{Entry: v, Endpoint: state.PublicTransparencyLogs[v.LogID].Endpoint}
		if err := e.ValidatePublicTransparencyFetchSource(tenant, id, out); err != nil {
			return fromExperimentalCommandError(err)
		}
		return nil
	})
	if err != nil {
		return e.PublicTransparencyFetchSource{}, err
	}
	return out, nil
}
func (r memoryFutureExtensionsRepository) InsertFocusedPublicTransparencyLog(ctx context.Context, v d.PublicTransparencyLog) error {
	expected, err := e.BuildPublicTransparencyLog(v.ID, v.TenantID, e.PublicTransparencyLogInput{Name: v.Name, Endpoint: v.Endpoint, PublicKey: v.PublicKey}, v.CreatedAt)
	if err != nil || expected != v {
		return ErrValidation
	}
	if err := r.ReadPublicTransparencyTenant(ctx, v.TenantID); err != nil {
		return err
	}
	return r.InsertPublicTransparencyLog(ctx, PublicTransparencyLogLegacyRecord(v))
}
func (r memoryFutureExtensionsRepository) InsertFocusedPublicTransparencyEntry(ctx context.Context, v d.PublicTransparencyLogEntry) error {
	src, err := r.ReadPublicTransparencyPublication(ctx, v.TenantID, v.LogID, v.CheckpointID)
	if err != nil {
		return err
	}
	expected, err := e.BuildPublicTransparencyPublication(v.ID, v.TenantID, e.PublicTransparencyPublicationInput{LogID: v.LogID, CheckpointID: v.CheckpointID, ExternalID: v.ExternalID}, src, v.CreatedAt)
	if err != nil || !e.SamePublicTransparencyAssessment(v, expected) || len(v.VerificationChecks) != 0 || len(v.VerificationLimitations) != 0 {
		return ErrValidation
	}
	return r.InsertPublicTransparencyLogEntry(ctx, PublicTransparencyPublicationLegacyRecord(v))
}
func (r memoryFutureExtensionsRepository) UpdateFocusedPublicTransparencyVerification(ctx context.Context, v, expected d.PublicTransparencyLogEntry) error {
	if err := e.ValidatePublicTransparencyVerificationSource(v.TenantID, v.ID, v); err != nil {
		return ErrValidation
	}
	if v.State == "published" || len(v.VerificationChecks) < 2 || len(v.VerificationChecks) > 3 || !memoryExperimentalLimitations(v.VerificationLimitations) {
		return ErrValidation
	}
	for _, c := range v.VerificationChecks {
		if !memoryMembershipQueryText(c.Name, 128) || !memoryMembershipText(c.Detail, 4096) || c.Result != "passed" && c.Result != "failed" {
			return ErrValidation
		}
	}
	immutable := v
	immutable.State, immutable.InclusionRootHash, immutable.InclusionProofHash, immutable.InclusionVerifiedAt = expected.State, expected.InclusionRootHash, expected.InclusionProofHash, expected.InclusionVerifiedAt
	if !e.SamePublicTransparencyAssessment(immutable, expected) {
		return ErrValidation
	}
	record := PublicTransparencyVerificationLegacyRecord(v)
	// Compare and write under the same memory transaction lock. A state string
	// alone cannot distinguish different same-terminal-state assessments.
	return memoryIdentityRepository(r).membershipRead(ctx, v.TenantID, func(state *MemoryUnitOfWorkSnapshot) error {
		current, err := memoryPublicTransparencyVerification(state, v.TenantID, v.ID)
		if err != nil {
			return err
		}
		if !e.SamePublicTransparencyAssessment(current, expected) {
			return ErrConflict
		}
		state.PublicTransparencyEntries[v.ID] = record
		return nil
	})
}

var _ e.PublicTransparencyMetadataReader = memoryFutureExtensionsRepository{}
var _ e.PublicTransparencyVerificationReader = memoryFutureExtensionsRepository{}
