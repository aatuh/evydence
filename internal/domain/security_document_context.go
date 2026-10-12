package domain

import evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"

func SecurityScanFromContext(v evidencedomain.SecurityScan) SecurityScan {
	var summary map[string]int
	if v.Summary != nil {
		summary = make(map[string]int, len(v.Summary))
		for key, n := range v.Summary {
			summary[key] = n
		}
	}
	return SecurityScan{ID: v.ID, TenantID: v.TenantID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, ArtifactID: v.ArtifactID, Category: v.Category, Format: v.Format, Scanner: v.Scanner, TargetRef: v.TargetRef, EvidenceID: v.EvidenceID, PayloadRef: v.PayloadRef, PayloadHash: v.PayloadHash, FindingCount: v.FindingCount, Summary: summary, Redacted: v.Redacted, Quarantined: v.Quarantined, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
func ManualSecurityDocumentFromContext(v evidencedomain.ManualSecurityDocument) ManualSecurityDocument {
	return ManualSecurityDocument{ID: v.ID, TenantID: v.TenantID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, DocumentType: v.DocumentType, Title: v.Title, Sensitivity: v.Sensitivity, EvidenceID: v.EvidenceID, PayloadRef: v.PayloadRef, PayloadHash: v.PayloadHash, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
