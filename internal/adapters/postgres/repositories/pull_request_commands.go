package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
)

// SourceRepositoryProvider is used only after ownership authorization when a
// request needs the stored provider default. No other repository text is read.
func (r source) SourceRepositoryProvider(ctx context.Context, tenant, id string) (string, error) {
	var provider string
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(provider,65537),octet_length(provider)>65536 FROM source_repositories WHERE tenant_id=$1 AND id=$2 FOR KEY SHARE`, tenant, id).Scan(&provider, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", app.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("read source provider: %w", err)
	}
	if large {
		return "", app.ErrConflict
	}
	return provider, nil
}
