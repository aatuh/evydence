package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	e "github.com/aatuh/evydence/internal/experimental/app"
	d "github.com/aatuh/evydence/internal/experimental/domain"
)

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
func PublicTransparencyVerificationLegacyRecord(v d.PublicTransparencyLogEntry) domain.PublicTransparencyLogEntry {
	v = e.ClonePublicTransparencyEntry(v)
	out := PublicTransparencyPublicationLegacyRecord(v)
	out.InclusionRootHash, out.InclusionProofHash, out.InclusionVerifiedAt = v.InclusionRootHash, v.InclusionProofHash, v.InclusionVerifiedAt
	out.VerificationLimitations = v.VerificationLimitations
	for _, c := range v.VerificationChecks {
		out.VerificationChecks = append(out.VerificationChecks, domain.VerifyCheck{Name: c.Name, Result: c.Result, Detail: c.Detail})
	}
	return out
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
