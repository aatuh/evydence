package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

var _ evidencequery.EvidencePointReader = (*Store)(nil)

// GetEvidencePoint reads one tenant-owned evidence row and validates all
// populated parent coordinates in a stable PostgreSQL snapshot. Worker-owned
// evidence still requires the compatibility projection's provenance checks.
func (s *Store) GetEvidencePoint(ctx context.Context, tenantID, id string) (evidencequery.EvidencePoint, error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" {
		return evidencequery.EvidencePoint{}, app.ErrValidation
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return evidencequery.EvidencePoint{}, evidencequery.ErrNotFound
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return evidencequery.EvidencePoint{}, fmt.Errorf("begin evidence point snapshot: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanupCtx)
	}()
	return loadEvidencePointInTx(ctx, tx, tenantID, id)
}

func loadEvidencePointInTx(ctx context.Context, tx pgx.Tx, tenantID, id string) (evidencequery.EvidencePoint, error) {
	item, err := loadParserReplayEvidence(ctx, tx, tenantID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return evidencequery.EvidencePoint{}, evidencequery.ErrNotFound
	}
	if err != nil {
		return evidencequery.EvidencePoint{}, err
	}
	if evidencedomain.RequiresWorkerProjection(item.Type) {
		return evidencequery.EvidencePoint{}, evidencequery.ErrRequiresProjection
	}
	productID, projectID, releaseID, err := resolveEvidencePointScope(ctx, tx, item)
	if err != nil {
		return evidencequery.EvidencePoint{}, err
	}
	return evidencequery.EvidencePoint{
		Item: domain.EvidenceToContextModel(item), ProductID: productID,
		ProjectID: projectID, ReleaseID: releaseID,
	}, nil
}

func resolveEvidencePointScope(ctx context.Context, tx pgx.Tx, item domain.EvidenceItem) (string, string, string, error) {
	return repositories.ResolveEvidenceScope(ctx, tx, item)
}
