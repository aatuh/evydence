package repositories

import (
	"context"
	"fmt"

	"github.com/aatuh/evydence/internal/app"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
)

var _ experimentalapp.SaaSProfileTenantReader = futureExtensions{}

func (r futureExtensions) ReadSaaSProfileTenants(ctx context.Context, tenant, admin string) (experimentalapp.SaaSProfileTenants, error) {
	// Primary-key membership bounds this projection to two IDs. Key-share locks
	// prevent deletion but remain compatible with another tenant's writer fence,
	// including simultaneous opposite-direction admin references.
	rows, err := r.tx.Query(ctx, `SELECT id FROM tenants WHERE id=ANY($1::text[]) ORDER BY id FOR KEY SHARE`, []string{tenant, admin})
	if err != nil {
		return experimentalapp.SaaSProfileTenants{}, fmt.Errorf("read SaaS profile tenant keys: %w", err)
	}
	defer rows.Close()
	var out experimentalapp.SaaSProfileTenants
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return experimentalapp.SaaSProfileTenants{}, err
		}
		if id == tenant {
			out.TenantID = id
		}
		if id == admin {
			out.AdminTenantID = id
		}
	}
	if err := rows.Err(); err != nil {
		return experimentalapp.SaaSProfileTenants{}, err
	}
	if out.TenantID != tenant || out.AdminTenantID != admin {
		return experimentalapp.SaaSProfileTenants{}, app.ErrNotFound
	}
	return out, nil
}
func (r futureExtensions) InsertFocusedSaaSProfile(ctx context.Context, v experimentaldomain.SaaSEditionProfile) error {
	if _, err := r.ReadSaaSProfileTenants(ctx, v.TenantID, v.AdminTenantID); err != nil {
		return err
	}
	return r.InsertSaaSEditionProfile(ctx, app.SaaSProfileLegacyRecord(v))
}
