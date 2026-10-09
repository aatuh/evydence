package domain

import (
	"errors"
	"reflect"
)

// CanonicalEvidenceFields excludes signature/audit references and, for v2,
// mutable relationship projections. Creation-time origin remains SubjectRefs.
// The wire encoder belongs to the versioned canonicalization adapter.
func CanonicalEvidenceFields(item EvidenceItem) EvidenceItem {
	item.CanonicalHash, item.ChainEntryID = "", ""
	item.SignatureRefs = nil
	if item.Canonicalization == EvidenceCanonicalizationProfileVersion {
		item.ProductID, item.ProjectID, item.ReleaseID, item.BuildID, item.DeploymentID = "", "", "", "", ""
		item.RelatedEvidenceRefs = nil
		item.Supersedes, item.SupersededBy = "", ""
	}
	return item
}

type CanonicalEvidenceOrigin struct {
	TenantID, EvidenceID, SchemaVersion                    string
	ProductID, ProjectID, ReleaseID, BuildID, DeploymentID string
	RelatedEvidenceRefs                                    []EvidenceRef
	Supersedes, SupersededBy                               string
}

// EvidenceWithCanonicalOrigin reconstructs legacy creation-time relationships
// only from tenant/evidence-matching v2 relationship lifecycle events. Ordinary
// lifecycle details and foreign events are not authoritative hash inputs.
func EvidenceWithCanonicalOrigin(item EvidenceItem, origins []CanonicalEvidenceOrigin) (EvidenceItem, error) {
	if item.Canonicalization != LegacyEvidenceCanonicalizationProfileVersion {
		return item, nil
	}
	var recorded *CanonicalEvidenceOrigin
	for _, origin := range origins {
		if origin.TenantID != item.TenantID || origin.EvidenceID != item.ID || origin.SchemaVersion != EvidenceRelationshipLifecycleSchemaVersion {
			continue
		}
		if recorded != nil && !reflect.DeepEqual(*recorded, origin) {
			return EvidenceItem{}, errors.New("conflicting legacy evidence canonical origins")
		}
		recorded = &origin
	}
	if recorded != nil {
		item.ProductID, item.ProjectID, item.ReleaseID, item.BuildID, item.DeploymentID = recorded.ProductID, recorded.ProjectID, recorded.ReleaseID, recorded.BuildID, recorded.DeploymentID
		item.RelatedEvidenceRefs = append([]EvidenceRef(nil), recorded.RelatedEvidenceRefs...)
		item.Supersedes, item.SupersededBy = recorded.Supersedes, recorded.SupersededBy
	}
	return item, nil
}
