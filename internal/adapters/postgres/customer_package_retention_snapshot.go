package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	packageapp "github.com/aatuh/evydence/internal/package/app"
	"github.com/aatuh/evydence/internal/platform/jsonbounds"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

// Private component of the complete customer snapshot. Preserve tenant-wide
// observation metadata, but validate the caller's selected roots first. No
// provider request, verification receipt, audit entry or mutation lock occurs.
func readCustomerPackageRetentionTx(ctx context.Context, tx pgx.Tx, tenant, product, release string, now time.Time, budget *customerSnapshotBudget) ([]map[string]any, error) {
	if err := validateCustomerSnapshotRead(ctx, tx, tenant, product, release, budget); err != nil {
		return nil, err
	}
	now = now.UTC()
	if now.IsZero() || now.Year() < 1 || now.Year() > 9999 {
		return nil, packageapp.ErrValidation
	}
	if err := requireCustomerSnapshotScope(ctx, tx, tenant, product, release); err != nil {
		return nil, err
	}
	policies, used, err := readPublicRetentionPoliciesTx(ctx, tx, tenant, packageapp.MaxBundleSnapshotRows, budget.remainingBytes)
	if err != nil {
		return nil, err
	}
	proofs := verificationapp.ObjectLockProofs(policies, now)
	body, err := json.Marshal(proofs)
	if err != nil || len(body) > budget.remainingBytes || jsonbounds.Validate(body, jsonbounds.Limits{MaxDepth: 32, MaxObjectKeys: 4096, MaxArrayItems: packageapp.MaxSecurityReviewEvidenceIDs, MaxStringBytes: packageapp.MaxCustomerPackageManifestBytes}) != nil {
		return nil, packageapp.ErrConflict
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Charge both selected metadata and any growth from canonical proof text,
	// expiry checks and limitations, atomically after this component succeeds.
	budget.remainingBytes -= max(used, len(body))
	return proofs, nil
}
