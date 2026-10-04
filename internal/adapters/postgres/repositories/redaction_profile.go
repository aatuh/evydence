package repositories

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func (r packages) InsertFocusedRedactionProfile(ctx context.Context, v packagedomain.RedactionProfile) error {
	if ctx == nil {
		return packageapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := packageapp.ValidateRedactionProfileRecord(v); err != nil {
		return err
	}
	// Reuse the existing selected-tenant insert, not a state reload or a
	// snapshot adapter. The focused boundary rejects forged records first.
	return mapPackageDraftRepositoryError(r.InsertRedactionProfile(ctx, domain.RedactionProfile{ID: v.ID, TenantID: v.TenantID, Name: v.Name, Description: v.Description, AllowedTypes: append([]string(nil), v.AllowedTypes...), ExcludedFields: append([]string(nil), v.ExcludedFields...), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}))
}
