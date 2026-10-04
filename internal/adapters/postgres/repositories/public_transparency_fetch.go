package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	e "github.com/aatuh/evydence/internal/experimental/app"
)

func (r futureExtensions) ReadPublicTransparencyFetch(ctx context.Context, tenant, id string) (e.PublicTransparencyFetchSource, error) {
	v, err := r.ReadPublicTransparencyVerification(ctx, tenant, id)
	if err != nil {
		return e.PublicTransparencyFetchSource{}, err
	}
	s := e.PublicTransparencyFetchSource{Entry: v}
	// The entry/root-chain reader already share-locked this owned log. Read only
	// bounded endpoint text, never name/public-key metadata or Merkle leaves.
	err = r.tx.QueryRow(ctx, `SELECT CASE WHEN octet_length(endpoint)<=4096 THEN endpoint ELSE '' END FROM public_transparency_logs WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, v.LogID).Scan(&s.Endpoint)
	if errors.Is(err, pgx.ErrNoRows) {
		return e.PublicTransparencyFetchSource{}, app.ErrNotFound
	}
	if err != nil {
		return e.PublicTransparencyFetchSource{}, fmt.Errorf("read public transparency fetch endpoint: %w", err)
	}
	return s, nil
}
