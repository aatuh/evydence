package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// The typed fixture adapter enforces the same canonical policy contract as
// native insertion. Existing immutable insertion detaches both policy slices;
// memory transactions do not establish PostgreSQL tenant-fence guarantees.
func (r memoryPackageRepository) InsertFocusedRedactionProfile(ctx context.Context, v packagedomain.RedactionProfile) error {
	if err := packageapp.ValidateRedactionProfileRecord(v); err != nil {
		return ErrValidation
	}
	return r.InsertRedactionProfile(ctx, domain.RedactionProfile(v))
}
