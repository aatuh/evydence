package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

// LoadParserReplayState reads only the requested source evidence and its
// tenant's audit history for an explicit operator replay. The durable apply
// transaction still validates the current source and any existing marker.
func (s *Store) LoadParserReplayState(ctx context.Context, tenantID, evidenceID, parserVersion string) (app.PersistedState, bool, error) {
	if s == nil || s.pool == nil || ctx == nil || tenantID == "" || evidenceID == "" || parserVersion == "" ||
		strings.TrimSpace(tenantID) != tenantID || strings.TrimSpace(evidenceID) != evidenceID || strings.TrimSpace(parserVersion) != parserVersion {
		return app.PersistedState{}, false, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return app.PersistedState{}, false, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return app.PersistedState{}, false, fmt.Errorf("begin parser replay source snapshot: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanupCtx)
	}()
	source, err := loadParserReplayEvidence(ctx, tx, tenantID, evidenceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.PersistedState{}, true, nil
	}
	if err != nil {
		return app.PersistedState{}, false, err
	}
	if _, _, _, err := resolveEvidencePointScope(ctx, tx, source); err != nil {
		return app.PersistedState{}, false, err
	}
	evidence := map[string]domain.EvidenceItem{evidenceID: source}
	markerIDs, err := tx.Query(ctx, `
		SELECT id FROM evidence_items
		WHERE tenant_id = $1 AND type = 'parser_normalization'
		  AND metadata ->> 'replay_of' = $2
		  AND metadata -> 'parser' ->> 'version' = $3
		ORDER BY id LIMIT 2`, tenantID, evidenceID, parserVersion)
	if err != nil {
		return app.PersistedState{}, false, fmt.Errorf("list parser replay marker: %w", err)
	}
	ids := make([]string, 0, 2)
	for markerIDs.Next() {
		var id string
		if err := markerIDs.Scan(&id); err != nil {
			markerIDs.Close()
			return app.PersistedState{}, false, fmt.Errorf("scan parser replay marker ID: %w", err)
		}
		ids = append(ids, id)
	}
	err = markerIDs.Err()
	markerIDs.Close()
	if err != nil {
		return app.PersistedState{}, false, fmt.Errorf("iterate parser replay marker IDs: %w", err)
	}
	if len(ids) > 1 {
		return app.PersistedState{}, false, app.ErrConflict
	}
	if len(ids) == 1 {
		marker, err := loadParserReplayEvidence(ctx, tx, tenantID, ids[0])
		if err != nil {
			return app.PersistedState{}, false, err
		}
		evidence[marker.ID] = marker
	}
	chain, err := loadAuditChainEntriesForTenant(ctx, tx, tenantID)
	if err != nil {
		return app.PersistedState{}, false, err
	}
	return app.PersistedState{
		Evidence: evidence,
		Chain:    map[string][]domain.AuditChainEntry{tenantID: chain},
	}, true, nil
}
