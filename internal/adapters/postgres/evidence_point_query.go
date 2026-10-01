package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

var _ evidencequery.EvidencePointReader = (*Store)(nil)

// GetEvidencePoint reads one tenant-owned evidence row and validates all
// populated parent coordinates and selected worker provenance in a stable
// PostgreSQL snapshot. The guard runs before metadata/provenance is selected.
func (s *Store) GetEvidencePoint(ctx context.Context, tenantID, id string, guard evidencequery.EvidenceReadGuard) (evidencequery.EvidencePoint, error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" || guard == nil {
		return evidencequery.EvidencePoint{}, app.ErrValidation
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return evidencequery.EvidencePoint{}, evidencequery.ErrNotFound
	}
	if len(id) > 1024 || !utf8.ValidString(id) || strings.ContainsRune(id, 0) {
		return evidencequery.EvidencePoint{}, evidencequery.ErrValidation
	}
	// FOR SHARE holds selected provenance stable; rollback guarantees this
	// logically read-only snapshot never commits effects.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return evidencequery.EvidencePoint{}, fmt.Errorf("begin evidence point snapshot: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanupCtx)
	}()
	return loadEvidencePointInTx(ctx, tx, tenantID, id, guard)
}

func loadEvidencePointInTx(ctx context.Context, tx pgx.Tx, tenantID, id string, guard evidencequery.EvidenceReadGuard) (evidencequery.EvidencePoint, error) {
	refs, err := repositories.ReadEvidenceBundleCoordinates(ctx, tx, tenantID, id, false)
	if err != nil {
		return evidencequery.EvidencePoint{}, mapEvidenceProjectionReadError(err)
	}
	refs, err = repositories.ResolveEvidenceBundleCoordinates(ctx, tx, tenantID, refs)
	if err != nil {
		return evidencequery.EvidencePoint{}, mapEvidenceProjectionReadError(err)
	}
	if err := guard(refs); err != nil {
		return evidencequery.EvidencePoint{}, err
	}
	item, err := repositories.ReadEvidenceWithWorkerProvenance(ctx, tx, tenantID, id)
	if err != nil {
		return evidencequery.EvidencePoint{}, mapEvidenceProjectionReadError(err)
	}
	return evidencequery.EvidencePoint{
		Item: item, ProductID: refs.ProductID,
		ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID,
		WorkerProjectionValidated: evidencedomain.RequiresWorkerProjection(item.Type),
	}, nil
}

func mapEvidenceProjectionReadError(err error) error {
	switch {
	case errors.Is(err, app.ErrNotFound):
		return evidencequery.ErrNotFound
	case errors.Is(err, app.ErrConflict):
		return evidencequery.ErrConflict
	case errors.Is(err, app.ErrValidation):
		return evidencequery.ErrValidation
	}
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) && (pgError.Code == "40001" || pgError.Code == "40P01") {
		return evidencequery.ErrConflict
	}
	return err
}

func resolveEvidencePointScope(ctx context.Context, tx pgx.Tx, item domain.EvidenceItem) (string, string, string, error) {
	return repositories.ResolveEvidenceScope(ctx, tx, item)
}
