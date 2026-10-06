package app

import (
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

func TestLocalCandidateCreationGuardChecksCurrentReferencesWithoutSnapshotWrites(t *testing.T) {
	l := newLegacyLedgerFixture(Config{Now: fixedNow, APIKeyPepper: "test-pepper"})
	_, _, _, a := bootstrapEnterpriseTestTenant(t, l)
	p, err := l.CreateProduct(t.Context(), a, "Parent", "parent")
	if err != nil {
		t.Fatal(err)
	}
	r, err := l.CreateRelease(t.Context(), a, p.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	in := releaseapp.CreateReleaseCandidateInput{ReleaseID: r.ID, Name: "Snapshot", BuildIDs: []string{"build", "build"}, ArtifactIDs: []string{"artifact"}, SBOMIDs: []string{"sbom"}, ScanIDs: []string{"scan"}, VEXIDs: []string{"vex"}, ContractIDs: []string{"contract"}, BundleIDs: []string{"bundle"}}
	l.buildRuns["build"] = domain.BuildRun{ID: "build", TenantID: a.TenantID, ReleaseID: r.ID}
	l.artifacts["artifact"] = domain.Artifact{ID: "artifact", TenantID: a.TenantID}
	l.sboms["sbom"] = domain.SBOM{ID: "sbom", TenantID: a.TenantID, ReleaseID: r.ID}
	l.scans["scan"] = domain.VulnerabilityScan{ID: "scan", TenantID: a.TenantID, ReleaseID: r.ID}
	l.vexDocuments["vex"] = domain.VEXDocument{ID: "vex", TenantID: a.TenantID, ReleaseID: r.ID}
	l.contracts["contract"] = domain.OpenAPIContract{ID: "contract", TenantID: a.TenantID, ReleaseID: r.ID}
	l.bundles["bundle"] = domain.ReleaseBundle{ID: "bundle", TenantID: a.TenantID, ReleaseID: r.ID}
	audits := len(l.chain[a.TenantID])
	l.now = func() time.Time { panic("local candidate guard used clock") }
	if err := l.AuthorizeCandidateCreation(t.Context(), a, in); err != nil {
		t.Fatal(err)
	}
	human := domain.Actor{TenantID: a.TenantID, UserID: "human", Scopes: []string{ScopeReleaseWrite}}
	if err := l.AuthorizeCandidateCreation(t.Context(), human, in); !errors.Is(err, ErrForbidden) {
		t.Fatal("removed grant retained candidate replay", err)
	}
	for _, field := range []string{"build", "artifact", "sbom", "scan", "vex", "contract", "bundle"} {
		bad := in
		switch field {
		case "build":
			bad.BuildIDs = []string{"missing"}
		case "artifact":
			bad.ArtifactIDs = []string{"missing"}
		case "sbom":
			bad.SBOMIDs = []string{"missing"}
		case "scan":
			bad.ScanIDs = []string{"missing"}
		case "vex":
			bad.VEXIDs = []string{"missing"}
		case "contract":
			bad.ContractIDs = []string{"missing"}
		case "bundle":
			bad.BundleIDs = []string{"missing"}
		}
		if err := l.AuthorizeCandidateCreation(t.Context(), a, bad); !errors.Is(err, ErrNotFound) {
			t.Fatal("missing reference retained replay", field, err)
		}
	}
	foreign := r
	foreign.TenantID = "other"
	l.releases[r.ID] = foreign
	if err := l.AuthorizeCandidateCreation(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign parent retained replay", err)
	}
	if len(l.candidates) != 0 || len(l.chain[a.TenantID]) != audits {
		t.Fatal("local guard wrote snapshot or audit")
	}
}
