package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	packageapp "github.com/aatuh/evydence/internal/package/app"
	"github.com/aatuh/evydence/internal/platform/jsonbounds"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

type customerPackageSnapshotBeginner interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

// CustomerPackageCreationSnapshotReader exposes only the selected public
// package view. Cryptographic dependencies are supplied by the composition
// root; this adapter has no Ledger, memory-mode fallback or mutation ports.
type CustomerPackageCreationSnapshotReader struct {
	beginner customerPackageSnapshotBeginner
	hasher   verificationapp.CanonicalHasher
	verifier verificationapp.PayloadSignatureVerifier
}

var _ packageapp.CustomerPackageSnapshotReader = (*CustomerPackageCreationSnapshotReader)(nil)

func NewCustomerPackageCreationSnapshotReader(store *Store, hasher verificationapp.CanonicalHasher, verifier verificationapp.PayloadSignatureVerifier) (*CustomerPackageCreationSnapshotReader, error) {
	if store == nil || store.pool == nil || hasher == nil || verifier == nil {
		return nil, packageapp.ErrValidation
	}
	return &CustomerPackageCreationSnapshotReader{beginner: store.pool, hasher: hasher, verifier: verifier}, nil
}

// The application authorizes the actor before this coordinate-only read. All
// roots and the selected tenant-owned profile are revalidated in this same
// committed read-only view. Nothing is published unless the view commits.
func (r *CustomerPackageCreationSnapshotReader) ReadCustomerPackageCreationSnapshot(ctx context.Context, tenant, product, release, profile string, generatedAt time.Time) (packageapp.CustomerPackageCreationSnapshot, error) {
	var empty packageapp.CustomerPackageCreationSnapshot
	generatedAt = generatedAt.UTC()
	if r == nil || r.beginner == nil || r.hasher == nil || r.verifier == nil || ctx == nil ||
		!customerSnapshotID(tenant, false) || !customerSnapshotID(product, false) || !customerSnapshotID(release, true) || !customerSnapshotID(profile, false) ||
		generatedAt.IsZero() || generatedAt.Year() < 1 || generatedAt.Year() > 9999 {
		return empty, packageapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	tx, err := r.beginner.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return empty, fmt.Errorf("begin customer-package snapshot: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanupCtx)
	}()
	view, err := readCustomerPackageCreationSnapshotTx(ctx, tx, tenant, product, release, profile, generatedAt, r.hasher, r.verifier)
	if err != nil {
		return empty, err
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := tx.Commit(ctx); err != nil {
		return empty, fmt.Errorf("commit customer-package snapshot: %w", err)
	}
	return view, nil
}

func readCustomerPackageCreationSnapshotTx(ctx context.Context, tx pgx.Tx, tenant, product, release, profileID string, now time.Time, hasher verificationapp.CanonicalHasher, verifier verificationapp.PayloadSignatureVerifier) (packageapp.CustomerPackageCreationSnapshot, error) {
	var empty packageapp.CustomerPackageCreationSnapshot
	budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	profile, err := readCustomerPackageProfileTx(ctx, tx, tenant, product, release, profileID, budget)
	if err != nil {
		return empty, err
	}
	catalog, err := readCustomerPackageCatalogTx(ctx, tx, tenant, product, release, budget)
	if err != nil {
		return empty, err
	}
	evidence, err := readCustomerPackageEvidenceTx(ctx, tx, tenant, product, release, budget)
	if err != nil {
		return empty, err
	}
	governance, err := readCustomerPackageGovernanceTx(ctx, tx, tenant, product, release, profile, now, budget)
	if err != nil {
		return empty, err
	}
	provenance, err := readCustomerPackageProvenanceTx(ctx, tx, tenant, product, release, profile, budget)
	if err != nil {
		return empty, err
	}
	readiness, err := readCustomerPackageReadinessTx(ctx, tx, tenant, product, release, now, budget)
	if err != nil {
		return empty, err
	}
	verification, err := readCustomerPackageVerificationMetadataTx(ctx, tx, tenant, product, release, budget)
	if err != nil {
		return empty, err
	}
	audit, err := readCustomerPackageAuditTx(ctx, tx, tenant, product, release, now, budget, hasher, verifier)
	if err != nil {
		return empty, err
	}
	retention, err := readCustomerPackageRetentionTx(ctx, tx, tenant, product, release, now, budget)
	if err != nil {
		return empty, err
	}
	verification["audit_chain"] = audit
	snapshot := packageapp.PackageSnapshot{
		SnapshotVersion: packageapp.CustomerPackageSnapshotVersion, TenantID: tenant, ProductID: product, ReleaseID: release,
		Tenant: catalog.Tenant, Organization: catalog.Organization, Product: catalog.Product, Release: catalog.Release,
		Evidence: catalog.Evidence, Artifacts: catalog.Artifacts, ReadinessChecks: readiness, VerificationMaterial: verification,
		SBOMs: evidence.SBOMs, VulnerabilityScans: evidence.Scans, VEXDocuments: evidence.VEX, APIContracts: evidence.Contracts,
		Decisions: governance.Decisions, Approvals: governance.Approvals, Exceptions: governance.Exceptions,
		Waivers: governance.Waivers, AnswerLibrary: governance.AnswerLibrary, ObjectLockProofs: retention, Provenance: provenance,
	}
	// Phase budgets bound selected metadata before transfer. Independently
	// bound the complete representation, including container names, static
	// limitations and canonical renderer growth, before publishing any view.
	body, err := json.Marshal(snapshot)
	if err != nil || len(body) > packageapp.MaxCustomerPackageManifestBytes ||
		jsonbounds.Validate(body, jsonbounds.Limits{MaxDepth: 32, MaxObjectKeys: 4096, MaxArrayItems: packageapp.MaxSecurityReviewEvidenceIDs, MaxStringBytes: packageapp.MaxCustomerPackageManifestBytes}) != nil {
		return empty, packageapp.ErrConflict
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return packageapp.CustomerPackageCreationSnapshot{Profile: profile, Snapshot: snapshot}, nil
}
