package httpapi

import (
	"github.com/aatuh/evydence/internal/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func evidenceBundleForImport(value domain.EvidenceBundle) packagedomain.EvidenceBundle {
	return packagedomain.EvidenceBundle{ID: value.ID, TenantID: value.TenantID, ReleaseID: value.ReleaseID, EvidenceIDs: value.EvidenceIDs, Manifest: value.Manifest, ManifestHash: value.ManifestHash, SignatureRefs: value.SignatureRefs, VerificationText: value.VerificationText, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt}
}

func evidenceBundleFromCommands(value packagedomain.EvidenceBundle) domain.EvidenceBundle {
	return domain.EvidenceBundle{ID: value.ID, TenantID: value.TenantID, ReleaseID: value.ReleaseID, EvidenceIDs: value.EvidenceIDs, Manifest: value.Manifest, ManifestHash: value.ManifestHash, SignatureRefs: value.SignatureRefs, VerificationText: value.VerificationText, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt}
}
func evidenceBundleImportFromCommands(record packagedomain.EvidenceBundleImport) domain.EvidenceBundleImport {
	return domain.EvidenceBundleImport{ID: record.ID, TenantID: record.TenantID, BundleHash: record.BundleHash, Result: record.Result, ImportedCount: record.ImportedCount, SchemaVersion: record.SchemaVersion, CreatedAt: record.CreatedAt}
}
