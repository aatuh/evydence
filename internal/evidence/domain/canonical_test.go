package domain

import "testing"

func TestCanonicalEvidenceFieldsPreserveImmutableOriginAndClearOnlyProjections(t *testing.T) {
	item := EvidenceItem{ID: "evidence", TenantID: "tenant", Canonicalization: EvidenceCanonicalizationProfileVersion, CanonicalHash: "hash", ChainEntryID: "chain", SignatureRefs: []string{"sig"}, ProductID: "product", ProjectID: "project", ReleaseID: "release", BuildID: "build", DeploymentID: "deployment", RelatedEvidenceRefs: []EvidenceRef{{ID: "related"}}, Supersedes: "prior", SupersededBy: "next", SubjectRefs: []SubjectRef{{Type: "release", ID: "origin"}}, Title: "immutable"}
	fields := CanonicalEvidenceFields(item)
	if fields.CanonicalHash != "" || fields.ChainEntryID != "" || len(fields.SignatureRefs) != 0 || fields.ProductID != "" || fields.ProjectID != "" || fields.ReleaseID != "" || fields.BuildID != "" || fields.DeploymentID != "" || len(fields.RelatedEvidenceRefs) != 0 || fields.Supersedes != "" || fields.SupersededBy != "" || fields.SubjectRefs[0].ID != "origin" || fields.Title != "immutable" {
		t.Fatal("canonical field contract changed", fields)
	}
	item.Canonicalization = LegacyEvidenceCanonicalizationProfileVersion
	if fields := CanonicalEvidenceFields(item); fields.ReleaseID != "release" || fields.Supersedes != "prior" || len(fields.RelatedEvidenceRefs) != 1 {
		t.Fatal("legacy fields cleared")
	}
}
func TestCanonicalEvidenceOriginIgnoresForeignAndOldSchemaAndRejectsConflicts(t *testing.T) {
	item := EvidenceItem{ID: "evidence", TenantID: "tenant", Canonicalization: LegacyEvidenceCanonicalizationProfileVersion, ReleaseID: "current"}
	event := CanonicalEvidenceOrigin{TenantID: "tenant", EvidenceID: "evidence", SchemaVersion: EvidenceRelationshipLifecycleSchemaVersion, ReleaseID: "origin"}
	for _, foreign := range []CanonicalEvidenceOrigin{{TenantID: "foreign", EvidenceID: "evidence", SchemaVersion: event.SchemaVersion, ReleaseID: "origin"}, {TenantID: "tenant", EvidenceID: "other", SchemaVersion: event.SchemaVersion, ReleaseID: "origin"}, {TenantID: "tenant", EvidenceID: "evidence", SchemaVersion: EvidenceLifecycleSchemaVersion, ReleaseID: "origin"}} {
		got, err := EvidenceWithCanonicalOrigin(item, []CanonicalEvidenceOrigin{foreign})
		if err != nil || got.ReleaseID != "current" {
			t.Fatal("untrusted origin applied", err)
		}
	}
	got, err := EvidenceWithCanonicalOrigin(item, []CanonicalEvidenceOrigin{event, event})
	if err != nil || got.ReleaseID != "origin" {
		t.Fatal("origin lost", err)
	}
	other := event
	other.ReleaseID = "different"
	if _, err := EvidenceWithCanonicalOrigin(item, []CanonicalEvidenceOrigin{event, other}); err == nil {
		t.Fatal("conflicting origin accepted")
	}
}
