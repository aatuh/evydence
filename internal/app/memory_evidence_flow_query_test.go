package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

func TestMemoryEvidenceFlowSnapshotCountsOwnedScalarRowsAndDetachesCounts(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	r, ok := tx.Repositories().ReleaseCatalog.(releasequery.EvidenceFlowReader)
	if !ok {
		t.Fatal("memory catalog lacks focused evidence-flow reader")
	}
	// The membership fixture also seeds packages; this count scenario owns its
	// package rows explicitly so the nine expected categories stay independent.
	tx.state.CustomerPackages = map[string]domain.CustomerSecurityPackage{}
	private := strings.Repeat("private-metadata", 5000)
	p := tx.state.Products["tenant-product"]
	p.Name = private
	tx.state.Products[p.ID] = p
	v := tx.state.Releases["tenant-release"]
	v.Version, v.State = private, "unknown"
	tx.state.Releases[v.ID] = v
	tx.state.SBOMs["sbom-a"] = domain.SBOM{ID: "sbom-a", TenantID: "tenant", ReleaseID: v.ID, ArtifactID: "art-a", Components: []domain.SBOMComponent{{Name: private}}}
	tx.state.SBOMs["sbom-d"] = domain.SBOM{ID: "sbom-d", TenantID: "tenant", ReleaseID: v.ID, ArtifactID: "art-d"}
	tx.state.VEXDocuments["vex"] = domain.VEXDocument{ID: "vex", TenantID: "tenant", ReleaseID: v.ID, ArtifactID: "art-a", Author: private}
	tx.state.VulnerabilityScans["scan"] = domain.VulnerabilityScan{ID: "scan", TenantID: "tenant", ReleaseID: v.ID, Findings: []domain.VulnerabilityFinding{{Component: private}}}
	tx.state.Decisions["decision"] = domain.VulnerabilityDecision{ID: "decision", TenantID: "tenant", ReleaseID: v.ID, InternalNotes: private}
	tx.state.Decisions["superseded"] = domain.VulnerabilityDecision{ID: "superseded", TenantID: "tenant", ReleaseID: v.ID, SupersededBy: "decision"}
	tx.state.BuildRuns["passed"] = domain.BuildRun{ID: "passed", TenantID: "tenant", ReleaseID: v.ID, Status: "passed", SourceIdentity: map[string]any{"private": private}, Outputs: []domain.BuildOutput{{ArtifactID: "art-a"}, {ArtifactID: "art-b"}, {ArtifactID: "art-b"}, {}}}
	tx.state.BuildRuns["failed"] = domain.BuildRun{ID: "failed", TenantID: "tenant", ReleaseID: v.ID, Status: "failed", Outputs: []domain.BuildOutput{{ArtifactID: "art-c"}}}
	tx.state.BuildAttestations["attestation"] = domain.BuildAttestation{ID: "attestation", TenantID: "tenant", BuildID: "passed", PayloadRef: private}
	tx.state.ReleaseBundles["bundle"] = domain.ReleaseBundle{ID: "bundle", TenantID: "tenant", ReleaseID: v.ID, Manifest: map[string]any{"private": private}}
	tx.state.EvidenceBundles["unrelated-export"] = domain.EvidenceBundle{ID: "unrelated-export", TenantID: "tenant", ReleaseID: v.ID}
	tx.state.CustomerPackages["package"] = domain.CustomerSecurityPackage{ID: "package", TenantID: "tenant", ReleaseID: v.ID, Title: private}
	for _, excluded := range []struct{ id, tenant, release string }{{"foreign", "foreign", v.ID}, {"other-release", "tenant", "foreign-release"}} {
		tx.state.SBOMs[excluded.id] = domain.SBOM{ID: excluded.id, TenantID: excluded.tenant, ReleaseID: excluded.release, ArtifactID: "private-artifact"}
		tx.state.VEXDocuments[excluded.id] = domain.VEXDocument{ID: excluded.id, TenantID: excluded.tenant, ReleaseID: excluded.release, ArtifactID: "private-artifact"}
		tx.state.VulnerabilityScans[excluded.id] = domain.VulnerabilityScan{ID: excluded.id, TenantID: excluded.tenant, ReleaseID: excluded.release}
		tx.state.Decisions[excluded.id] = domain.VulnerabilityDecision{ID: excluded.id, TenantID: excluded.tenant, ReleaseID: excluded.release}
		tx.state.BuildRuns[excluded.id] = domain.BuildRun{ID: excluded.id, TenantID: excluded.tenant, ReleaseID: excluded.release, Status: "passed", Outputs: []domain.BuildOutput{{ArtifactID: "private-artifact"}}}
		tx.state.ReleaseBundles[excluded.id] = domain.ReleaseBundle{ID: excluded.id, TenantID: excluded.tenant, ReleaseID: excluded.release}
		tx.state.CustomerPackages[excluded.id] = domain.CustomerSecurityPackage{ID: excluded.id, TenantID: excluded.tenant, ReleaseID: excluded.release}
		tx.state.BuildAttestations[excluded.id] = domain.BuildAttestation{ID: excluded.id, TenantID: "tenant", BuildID: excluded.id}
	}
	tx.state.BuildAttestations["foreign-attestation"] = domain.BuildAttestation{ID: "foreign-attestation", TenantID: "foreign", BuildID: "passed"}
	tx.state.BuildAttestations["dangling"] = domain.BuildAttestation{ID: "dangling", TenantID: "tenant", BuildID: "missing"}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	want := releasequery.EvidenceFlowSnapshot{TenantID: "tenant", ReleaseID: v.ID, ProductID: p.ID, Counts: map[string]int{"artifact_refs": 4, "passed_builds": 1, "build_attestations": 1, "sboms": 2, "vulnerability_scans": 1, "vex_documents": 1, "vulnerability_decisions": 1, "release_bundles": 1, "customer_packages": 1}}
	got, err := r.ReadEvidenceFlowSnapshot(t.Context(), "tenant", v.ID)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("flow counts differ from owned scalar SQL model", got, err)
	}
	got.Counts["artifact_refs"] = 999
	got.Counts["private"] = 1
	got, err = r.ReadEvidenceFlowSnapshot(t.Context(), "tenant", v.ID)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("caller mutation changed flow counts", got, err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("flow count reads changed any transaction state")
	}
}

func TestMemoryEvidenceFlowSnapshotRejectsForeignParentsAndInvalidContexts(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	r, ok := tx.Repositories().ReleaseCatalog.(releasequery.EvidenceFlowReader)
	if !ok {
		t.Fatal("memory catalog lacks focused evidence-flow reader")
	}
	for _, tenant := range []string{"foreign", "missing"} {
		if got, err := r.ReadEvidenceFlowSnapshot(t.Context(), tenant, "tenant-release"); !errors.Is(err, releasequery.ErrNotFound) || !reflect.DeepEqual(got, releasequery.EvidenceFlowSnapshot{}) {
			t.Fatal("foreign flow returned counts", got, err)
		}
	}
	for _, parent := range []string{"foreign-product", "missing-product"} {
		v := tx.state.Releases["tenant-release"]
		v.ProductID = parent
		tx.state.Releases[v.ID] = v
		if got, err := r.ReadEvidenceFlowSnapshot(t.Context(), "tenant", v.ID); !errors.Is(err, releasequery.ErrNotFound) || !reflect.DeepEqual(got, releasequery.EvidenceFlowSnapshot{}) {
			t.Fatal("flow accepted foreign/dangling parent", got, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var absent context.Context
	for _, check := range []struct {
		ctx             context.Context
		tenant, release string
		want            error
	}{{ctx, "tenant", "tenant-release", context.Canceled}, {absent, "tenant", "tenant-release", releasequery.ErrValidation}, {t.Context(), "tenant", "", releasequery.ErrValidation}, {t.Context(), "", "tenant-release", releasequery.ErrValidation}, {t.Context(), "tenant", " tenant-release", releasequery.ErrValidation}} {
		if got, err := r.ReadEvidenceFlowSnapshot(check.ctx, check.tenant, check.release); !errors.Is(err, check.want) || !reflect.DeepEqual(got, releasequery.EvidenceFlowSnapshot{}) {
			t.Fatal("invalid flow context/identity returned counts", got, err)
		}
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got, err := r.ReadEvidenceFlowSnapshot(t.Context(), "tenant", "tenant-release"); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(got, releasequery.EvidenceFlowSnapshot{}) {
		t.Fatal("closed flow transaction returned counts", got, err)
	}
}
