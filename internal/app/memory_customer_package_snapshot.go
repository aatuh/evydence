package app

import (
	"context"
	"encoding/json"
	"time"

	packageapp "github.com/aatuh/evydence/internal/package/app"
)

var _ packageapp.CustomerPackageSnapshotReader = memoryPackageRepository{}

// All components and the historical policy use one locked typed transaction
// view. This is the explicit nondurable fixture backend, not a native runtime
// fallback; it cannot prove SQL repeatable-read, transfer budgets or durability.
func (r memoryPackageRepository) ReadCustomerPackageCreationSnapshot(ctx context.Context, tenant, product, release, profileID string, at time.Time) (packageapp.CustomerPackageCreationSnapshot, error) {
	var out packageapp.CustomerPackageCreationSnapshot
	at = at.UTC()
	if ctx == nil || r.uow == nil || !memoryCustomerSnapshotID(profileID, false) || at.IsZero() || at.Year() < 1 || at.Year() > 9999 {
		return out, ErrValidation
	}
	err := r.uow.mutate(ctx, func(s *MemoryUnitOfWorkSnapshot) error {
		budget := &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
		if err := validateMemoryCustomerSnapshotRead(ctx, s, tenant, product, release, budget); err != nil {
			return err
		}
		profile, err := readMemoryCustomerRedactionProfile(s, tenant, profileID)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(profile)
		if err != nil {
			return ErrConflict
		}
		if err := budget.chargeJSON(raw); err != nil {
			return err
		}
		catalog, err := readMemoryCustomerPackageCatalog(ctx, s, tenant, product, release, budget)
		if err != nil {
			return err
		}
		evidence, err := readMemoryCustomerPackageEvidence(ctx, s, tenant, product, release, budget)
		if err != nil {
			return err
		}
		governance, err := readMemoryCustomerPackageGovernance(ctx, s, tenant, product, release, profile, at, budget)
		if err != nil {
			return err
		}
		provenance, err := readMemoryCustomerPackageProvenance(ctx, s, tenant, product, release, profile, budget)
		if err != nil {
			return err
		}
		readiness, err := readMemoryCustomerPackageReadiness(ctx, s, tenant, product, release, at, budget)
		if err != nil {
			return err
		}
		verification, err := readMemoryCustomerPackageVerification(ctx, s, tenant, product, release, budget)
		if err != nil {
			return err
		}
		audit, err := readMemoryCustomerPackageAudit(ctx, s, tenant, product, release, at, budget, memoryCustomerAuditHasher{}, memoryCustomerPayloadVerifier{})
		if err != nil {
			return err
		}
		retention, err := readMemoryCustomerPackageRetention(ctx, s, tenant, product, release, at, budget)
		if err != nil {
			return err
		}
		verification["audit_chain"] = audit
		snapshot := packageapp.PackageSnapshot{SnapshotVersion: packageapp.CustomerPackageSnapshotVersion, TenantID: tenant, ProductID: product, ReleaseID: release, Tenant: catalog.Tenant, Organization: catalog.Organization, Product: catalog.Product, Release: catalog.Release, Evidence: catalog.Evidence, Artifacts: catalog.Artifacts, ReadinessChecks: readiness, VerificationMaterial: verification, SBOMs: evidence.SBOMs, VulnerabilityScans: evidence.Scans, VEXDocuments: evidence.VEX, APIContracts: evidence.Contracts, Decisions: governance.Decisions, Approvals: governance.Approvals, Exceptions: governance.Exceptions, Waivers: governance.Waivers, AnswerLibrary: governance.AnswerLibrary, ObjectLockProofs: retention, Provenance: provenance}
		raw, err = json.Marshal(snapshot)
		if err != nil {
			return ErrConflict
		}
		final := memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
		if err := final.chargeJSON(raw); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		out = packageapp.CustomerPackageCreationSnapshot{Profile: profile, Snapshot: snapshot}
		return nil
	})
	if err != nil {
		return packageapp.CustomerPackageCreationSnapshot{}, err
	}
	return out, nil
}
