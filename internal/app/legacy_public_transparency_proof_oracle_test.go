package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	e "github.com/aatuh/evydence/internal/experimental/app"
	d "github.com/aatuh/evydence/internal/experimental/domain"
)

// Historical declarations retained unchanged for package-local regressions.
// Native HTTP fixtures use transaction repositories, not these caches.
// These oracles do not establish SQL durability or external public-log trust.

func publicTransparencyProofInput(v VerifyPublicTransparencyLogEntryInput) e.PublicTransparencyProofInput {
	return e.PublicTransparencyProofInput{LeafHash: v.LeafHash, RootHash: v.RootHash, LeafIndex: v.LeafIndex, TreeSize: v.TreeSize, InclusionProof: v.InclusionProof}
}

func PublicTransparencyVerificationCoreRecord(v domain.PublicTransparencyLogEntry) d.PublicTransparencyLogEntry {
	out := d.PublicTransparencyLogEntry{ID: v.ID, TenantID: v.TenantID, LogID: v.LogID, CheckpointID: v.CheckpointID, MerkleBatchID: v.MerkleBatchID, ExternalID: v.ExternalID, EntryHash: v.EntryHash, State: v.State, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt, InclusionRootHash: v.InclusionRootHash, InclusionProofHash: v.InclusionProofHash, InclusionVerifiedAt: v.InclusionVerifiedAt, VerificationLimitations: v.VerificationLimitations}
	for _, c := range v.VerificationChecks {
		out.VerificationChecks = append(out.VerificationChecks, d.VerificationCheck{Name: c.Name, Result: c.Result, Detail: c.Detail})
	}
	return e.ClonePublicTransparencyEntry(out)
}

func (l *Ledger) AuthorizeVerifyPublicTransparencyLogEntry(ctx context.Context, a domain.Actor, id string, in VerifyPublicTransparencyLogEntryInput) error {
	if err := e.AuthorizePublicTransparencyMetadataActor(ctx, a); err != nil {
		return fromExperimentalCommandError(err)
	}
	if _, err := e.NormalizePublicTransparencyProofInput(id, publicTransparencyProofInput(in)); err != nil {
		return fromExperimentalCommandError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err := l.publicTransparencyVerificationSourceLocked(ctx, a.TenantID, strings.TrimSpace(id))
	return err
}

func (l *Ledger) publicTransparencyVerificationSourceLocked(ctx context.Context, tenant, id string) (d.PublicTransparencyLogEntry, error) {
	if err := ctx.Err(); err != nil {
		return d.PublicTransparencyLogEntry{}, err
	}
	if _, ok := l.tenants[tenant]; !ok {
		return d.PublicTransparencyLogEntry{}, ErrNotFound
	}
	v, ok := l.publicLogEntries[id]
	if !ok || v.TenantID != tenant {
		return d.PublicTransparencyLogEntry{}, ErrNotFound
	}
	log, ok := l.publicLogs[v.LogID]
	if !ok || log.TenantID != tenant {
		return d.PublicTransparencyLogEntry{}, ErrNotFound
	}
	cp, ok := l.transparency[v.CheckpointID]
	if !ok || cp.TenantID != tenant || cp.BatchID != v.MerkleBatchID {
		return d.PublicTransparencyLogEntry{}, ErrNotFound
	}
	b, ok := l.merkleBatches[v.MerkleBatchID]
	if !ok || b.TenantID != tenant {
		return d.PublicTransparencyLogEntry{}, ErrNotFound
	}
	s := PublicTransparencyVerificationCoreRecord(v)
	if err := e.ValidatePublicTransparencyVerificationSource(tenant, id, s); err != nil {
		return d.PublicTransparencyLogEntry{}, fromExperimentalCommandError(err)
	}
	return s, nil
}

func (l *Ledger) AuthorizeFetchPublicTransparencyLogEntryProof(ctx context.Context, a domain.Actor, id string) error {
	if err := e.AuthorizePublicTransparencyMetadataActor(ctx, a); err != nil {
		return fromExperimentalCommandError(err)
	}
	id, err := e.NormalizePublicTransparencyFetchID(id)
	if err != nil {
		return fromExperimentalCommandError(err)
	}
	if l.transparencyProofs == nil {
		return ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.publicTransparencyFetchSourceLocked(ctx, a.TenantID, id)
	return err
}

func (l *Ledger) publicTransparencyFetchSourceLocked(ctx context.Context, tenant, id string) (e.PublicTransparencyFetchSource, error) {
	v, err := l.publicTransparencyVerificationSourceLocked(ctx, tenant, id)
	if err != nil {
		return e.PublicTransparencyFetchSource{}, err
	}
	s := e.PublicTransparencyFetchSource{Entry: v, Endpoint: l.publicLogs[v.LogID].Endpoint}
	if err := e.ValidatePublicTransparencyFetchSource(tenant, id, s); err != nil {
		return e.PublicTransparencyFetchSource{}, fromExperimentalCommandError(err)
	}
	return s, nil
}

func (l *Ledger) FetchAndVerifyPublicTransparencyLogEntry(ctx context.Context, a domain.Actor, id string) (domain.PublicTransparencyLogEntry, error) {
	if err := l.AuthorizeFetchPublicTransparencyLogEntryProof(ctx, a, id); err != nil {
		return domain.PublicTransparencyLogEntry{}, err
	}
	id = strings.TrimSpace(id)
	l.mu.Lock()
	s, err := l.publicTransparencyFetchSourceLocked(ctx, a.TenantID, id)
	l.mu.Unlock()
	if err != nil {
		return domain.PublicTransparencyLogEntry{}, err
	}
	fetchCtx, cancel := context.WithTimeout(ctx, e.PublicTransparencyFetchTimeout)
	defer cancel()
	result, err := l.transparencyProofs.FetchTransparencyProof(fetchCtx, TransparencyProofRequest{TenantID: a.TenantID, LogID: s.Entry.LogID, EntryID: id, Endpoint: strings.TrimSpace(s.Endpoint), ExternalID: s.Entry.ExternalID, EntryHash: s.Entry.EntryHash})
	if ctx.Err() != nil {
		return domain.PublicTransparencyLogEntry{}, ctx.Err()
	}
	if err != nil || fetchCtx.Err() != nil {
		return domain.PublicTransparencyLogEntry{}, ErrVerificationFailed
	}
	in, err := e.NormalizePublicTransparencyFetchedProof(s, e.PublicTransparencyFetchedProof{ExternalID: result.ExternalID, Proof: e.PublicTransparencyProofInput{LeafHash: result.LeafHash, RootHash: result.RootHash, LeafIndex: result.LeafIndex, TreeSize: result.TreeSize, InclusionProof: result.InclusionProof}})
	if err != nil {
		return domain.PublicTransparencyLogEntry{}, ErrVerificationFailed
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	current, err := l.publicTransparencyFetchSourceLocked(ctx, a.TenantID, id)
	if err != nil {
		return domain.PublicTransparencyLogEntry{}, err
	}
	if !e.SamePublicTransparencyFetchSource(s, current) {
		return domain.PublicTransparencyLogEntry{}, ErrConflict
	}
	return l.verifyPublicTransparencyEntryLocked(ctx, a, VerifyPublicTransparencyLogEntryInput{LeafHash: in.LeafHash, RootHash: in.RootHash, LeafIndex: in.LeafIndex, TreeSize: in.TreeSize, InclusionProof: in.InclusionProof, Source: "fetched"}, current.Entry)
}
