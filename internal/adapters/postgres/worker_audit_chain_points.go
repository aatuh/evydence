package postgres

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/domain"
)

// loadAuditChainTailForTenant supplies the predecessor for a proposed worker
// entry. The write transaction independently checks committed sequence and
// predecessor continuity before rebasing pending entries.
func loadAuditChainTailForTenant(ctx context.Context, tx pgx.Tx, tenantID string) ([]domain.AuditChainEntry, error) {
	var id string
	err := tx.QueryRow(ctx, `SELECT id FROM audit_chain_entries WHERE tenant_id = $1 ORDER BY sequence DESC LIMIT 1`, tenantID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find tenant audit tail: %w", err)
	}
	entry, err := loadParserReplayAuditEntry(ctx, tx, tenantID, id)
	if err != nil {
		return nil, err
	}
	return []domain.AuditChainEntry{entry}, nil
}

// loadVEXAcceptedAuditPoints adds only the acceptance fact required by a
// strict decision job, without materializing unrelated audit history.
func loadVEXAcceptedAuditPoints(ctx context.Context, tx pgx.Tx, tenantID, documentID, actorType, actorID, payloadHash string) ([]domain.AuditChainEntry, error) {
	entries, err := loadAuditChainTailForTenant(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	if actorType == "" || actorID == "" || payloadHash == "" {
		return entries, nil
	}
	var acceptedID string
	err = tx.QueryRow(ctx, `
		SELECT id FROM audit_chain_entries
		WHERE tenant_id = $1 AND entry_type = 'vex.accepted'
		  AND subject_type = 'vex_document' AND subject_id = $2
		  AND actor_type = $3 AND actor_id = $4 AND payload_hash = $5
		ORDER BY sequence DESC LIMIT 1`, tenantID, documentID, actorType, actorID, payloadHash).Scan(&acceptedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return entries, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find VEX acceptance audit entry: %w", err)
	}
	if len(entries) != 0 && entries[0].ID == acceptedID {
		return entries, nil
	}
	accepted, err := loadParserReplayAuditEntry(ctx, tx, tenantID, acceptedID)
	if err != nil {
		return nil, err
	}
	entries = append(entries, accepted)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Sequence < entries[j].Sequence })
	return entries, nil
}
