package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	e "github.com/aatuh/evydence/internal/experimental/app"
)

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
