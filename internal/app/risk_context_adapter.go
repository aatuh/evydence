package app

import (
	"errors"
	"strings"

	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func buildRiskReadinessSnapshotLocked(ledger *Ledger, tenantID, releaseID string) (riskapp.ReadinessSnapshot, error) {
	releaseID = strings.TrimSpace(releaseID)
	release, ok := ledger.releases[releaseID]
	if !ok || release.TenantID != tenantID {
		return riskapp.ReadinessSnapshot{}, riskapp.ErrNotFound
	}
	snapshot := riskapp.ReadinessSnapshot{
		SnapshotVersion: riskapp.ReadinessSnapshotVersion, TenantID: tenantID, ProductID: release.ProductID, ReleaseID: release.ID,
	}
	for _, item := range ledger.evidence {
		if item.TenantID != tenantID || item.ReleaseID != releaseID {
			continue
		}
		switch item.Type {
		case "sbom":
			snapshot.HasSBOM = true
		case "vulnerability_scan":
			snapshot.HasVulnerabilityScan = true
		}
		for _, reference := range item.SubjectRefs {
			if reference.Type == "artifact" && reference.ID != "" {
				snapshot.HasArtifact = true
				snapshot.HasArtifactDigest = true
			}
		}
	}
	for _, bundle := range ledger.bundles {
		if bundle.TenantID == tenantID && bundle.ReleaseID == releaseID && len(bundle.SignatureRefs) > 0 && ledger.verifySignatureLocked(tenantID, bundle.SignatureRefs, []byte(bundle.ManifestHash)) {
			snapshot.HasVerifiedSignedBundle = true
			break
		}
	}
	releaseDigests := ledger.releaseArtifactDigestsLocked(tenantID, releaseID)
	for _, build := range ledger.buildRuns {
		if build.TenantID != tenantID || build.ReleaseID != releaseID || build.Status != buildStatusPassed {
			continue
		}
		for _, output := range build.Outputs {
			if _, ok := releaseDigests[output.Digest]; ok {
				snapshot.HasPassedBuild = true
				break
			}
		}
		if snapshot.HasPassedBuild {
			break
		}
	}
	for _, attestation := range ledger.attestations {
		if attestation.TenantID != tenantID || !ledger.hasPassedDSSEAttestationReceiptLocked(tenantID, attestation.ID) {
			continue
		}
		build, ok := ledger.buildRuns[attestation.BuildID]
		if !ok || build.TenantID != tenantID || build.ReleaseID != releaseID {
			continue
		}
		for _, digest := range attestation.SubjectDigests {
			if _, ok := releaseDigests[digest]; ok {
				snapshot.HasVerifiedBuildAttestation = true
				break
			}
		}
		if snapshot.HasVerifiedBuildAttestation {
			break
		}
	}
	snapshot.UnhandledCritical = len(ledger.unhandledCriticalFindingsLocked(tenantID, releaseID)) > 0
	snapshot.UnhandledHigh = len(ledger.unhandledFindingsBySeverityLocked(tenantID, releaseID, "high")) > 0
	for _, decision := range ledger.decisions {
		if decision.TenantID != tenantID || decision.ReleaseID != releaseID || decision.SupersededBy != "" {
			continue
		}
		if decision.CustomerVisible && strings.TrimSpace(decision.ImpactStatement) == "" {
			snapshot.MissingCustomerStatementIDs = append(snapshot.MissingCustomerStatementIDs, decision.ID)
		}
		if decision.Status == decisionStatusNotAffected && strings.TrimSpace(decision.Justification) == "" {
			snapshot.MissingNotAffectedReasonIDs = append(snapshot.MissingNotAffectedReasonIDs, decision.ID)
		}
	}
	for _, exception := range ledger.exceptions {
		if exception.TenantID != tenantID || exception.ReleaseID != releaseID {
			continue
		}
		if strings.TrimSpace(exception.Owner) == "" || strings.TrimSpace(exception.Reason) == "" || exception.ExpiresAt.IsZero() || (exception.Approved && (strings.TrimSpace(exception.ApprovedBy) == "" || exception.ApprovedAt == nil)) {
			snapshot.IncompleteExceptionIDs = append(snapshot.IncompleteExceptionIDs, exception.ID)
		}
	}
	now := ledger.now().UTC()
	for _, customerPackage := range ledger.customerPackages {
		if customerPackage.TenantID != tenantID || customerPackage.ReleaseID != releaseID {
			continue
		}
		snapshot.PackageCount++
		profile, ok := ledger.redactions[customerPackage.RedactionProfileID]
		if !ok || profile.TenantID != tenantID || len(profile.AllowedTypes) == 0 || !redactionProfileExcludesPackageSensitiveFields(profile) || !customerPackage.ExpiresAt.After(now) {
			snapshot.InvalidPackageOrProfileIDs = append(snapshot.InvalidPackageOrProfileIDs, customerPackage.ID)
		}
	}
	return snapshot, nil
}

func toRiskContextError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrValidation):
		return riskapp.ErrValidation
	case errors.Is(err, ErrForbidden):
		return riskapp.ErrForbidden
	case errors.Is(err, ErrNotFound):
		return riskapp.ErrNotFound
	case errors.Is(err, ErrConflict):
		return riskapp.ErrConflict
	default:
		return err
	}
}

func fromRiskContextError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, riskapp.ErrValidation):
		return ErrValidation
	case errors.Is(err, riskapp.ErrForbidden):
		return ErrForbidden
	case errors.Is(err, riskapp.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, riskapp.ErrConflict):
		return ErrConflict
	default:
		return err
	}
}
