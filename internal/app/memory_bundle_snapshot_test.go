package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

type memoryBundleFixturePorts interface {
	packageapp.ReleaseBundleSnapshotReader
	packageapp.EvidenceBundleSnapshotReader
	LockReleaseBundleParent(context.Context, string, string) (string, error)
	LockEvidenceBundleTenant(context.Context, string) error
}
type memoryBundleEvidenceFixturePort interface {
	LockEvidenceBundleEvidence(context.Context, string, string) (application.ResourceReferences, error)
}

func memoryBundleSnapshotFixture(t *testing.T) (*memoryUnitOfWork, memoryBundleFixturePorts) {
	t.Helper()
	_, tx := memoryMembershipReadFixture(t)
	for _, tenant := range []string{"tenant", "foreign"} {
		r := tx.state.Releases[tenant+"-release"]
		r.Version, r.State = "1", "draft"
		tx.state.Releases[r.ID] = r
		for _, suffix := range []string{"z", "a"} {
			id := tenant + "-evidence-" + suffix
			tx.state.Evidence[id] = domain.EvidenceItem{ID: id, TenantID: tenant, ProductID: tenant + "-product", ProjectID: tenant + "-project", ReleaseID: r.ID, Title: "private-title", PayloadRef: "object://private-source", Metadata: map[string]any{"private_payload": "must-not-load"}}
		}
		tx.state.AuditEntries[tenant] = []domain.AuditChainEntry{{TenantID: tenant, Sequence: 4, EntryHash: "sha256:" + strings.Repeat("b", 64)}, {TenantID: tenant, Sequence: 2, EntryHash: "sha256:" + strings.Repeat("a", 64)}}
	}
	ports, ok := tx.Repositories().Packages.(memoryBundleFixturePorts)
	if !ok {
		t.Fatal("memory package repository lacks focused bundle snapshot/guard ports")
	}
	return tx, ports
}

func TestMemoryBundleSnapshotsSelectCurrentDetachedPublicFacts(t *testing.T) {
	tx, p := memoryBundleSnapshotFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.ReadReleaseBundleSnapshot(t.Context(), "tenant", "tenant-release", fixedNow())
	if err != nil || r.SnapshotVersion != packageapp.ReleaseBundleSnapshotVersion || r.ProductID != "tenant-product" || r.ReleaseVersion != "1" || r.ReleaseState != "draft" || r.ChainSequence != 4 || r.ChainHeadHash != before.AuditEntries["tenant"][0].EntryHash || !reflect.DeepEqual(r.EvidenceIDs, []string{"tenant-evidence-a", "tenant-evidence-z"}) {
		t.Fatal("release bundle snapshot lost current public facts", r, err)
	}
	r.EvidenceIDs[0] = "caller mutation"
	e, err := p.ReadEvidenceBundleSnapshot(t.Context(), "tenant", "tenant-release", fixedNow())
	if err != nil || e.SnapshotVersion != packageapp.EvidenceBundleSnapshotVersion || len(e.Evidence) != 2 || e.Evidence[0].ID != "tenant-evidence-a" || e.Evidence[0].Resources != (application.ResourceReferences{ProductID: "tenant-product", ProjectID: "tenant-project", ReleaseID: "tenant-release"}) || e.AuditChainHead != before.AuditEntries["tenant"][0].EntryHash {
		t.Fatal("evidence bundle snapshot lost current coordinates", e, err)
	}
	e.Evidence[0].Resources.ProductID = "caller mutation"
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("bundle snapshot modified stored state")
	}
	if _, err := p.ReadReleaseBundleSnapshot(t.Context(), "tenant", "foreign-release", fixedNow()); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign release selected", err)
	}
	if _, err := p.ReadEvidenceBundleSnapshot(t.Context(), "tenant", "foreign-release", fixedNow()); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign export selected", err)
	}
	if product, err := p.LockReleaseBundleParent(t.Context(), "tenant", "tenant-release"); err != nil || product != "tenant-product" {
		t.Fatal("release guard lost current parent", product, err)
	}
	evidence, ok := tx.Repositories().Evidence.(memoryBundleEvidenceFixturePort)
	if !ok {
		t.Fatal("memory evidence lacks focused bundle coordinate guard")
	}
	if refs, err := evidence.LockEvidenceBundleEvidence(t.Context(), "tenant", "tenant-evidence-a"); err != nil || refs.ProductID != "tenant-product" {
		t.Fatal("selected evidence guard failed", refs, err)
	}
	if refs, err := evidence.LockEvidenceBundleEvidence(t.Context(), "tenant", "foreign-evidence-a"); !errors.Is(err, ErrNotFound) || refs != (application.ResourceReferences{}) {
		t.Fatal("foreign evidence returned coordinates", refs, err)
	}
	if err := p.LockEvidenceBundleTenant(t.Context(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing target tenant accepted", err)
	}
}

func TestMemoryBundleSnapshotsRejectIncoherentOversizedAndCancelledViewsWithoutData(t *testing.T) {
	for _, mutate := range []func(*MemoryUnitOfWorkSnapshot){
		func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Products["tenant-product"]
			v.ID = "wrong-identity"
			s.Products["tenant-product"] = v
		},
		func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Releases["tenant-release"]
			v.Version = strings.Repeat("x", 4097)
			s.Releases[v.ID] = v
		},
		func(s *MemoryUnitOfWorkSnapshot) {
			for i := 0; i < packageapp.MaxBundleSnapshotRows; i++ {
				id := fmt.Sprintf("evidence-%04d", i)
				s.Evidence[id] = domain.EvidenceItem{ID: id, TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release"}
			}
		},
		func(s *MemoryUnitOfWorkSnapshot) { s.AuditEntries["tenant"][0].EntryHash = strings.Repeat("x", 1025) },
	} {
		tx, p := memoryBundleSnapshotFixture(t)
		mutate(&tx.state)
		if v, err := p.ReadReleaseBundleSnapshot(t.Context(), "tenant", "tenant-release", fixedNow()); err == nil || !reflect.DeepEqual(v, packageapp.ReleaseBundleSnapshot{}) {
			t.Fatal("invalid release snapshot returned data", err)
		}
	}
	tx, p := memoryBundleSnapshotFixture(t)
	v := tx.state.Evidence["tenant-evidence-a"]
	v.ProjectID = "foreign-project"
	tx.state.Evidence[v.ID] = v
	if value, err := p.ReadEvidenceBundleSnapshot(t.Context(), "tenant", "tenant-release", fixedNow()); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(value, packageapp.EvidenceBundleSnapshot{}) {
		t.Fatal("incoherent evidence parent exported", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := p.ReadReleaseBundleSnapshot(ctx, "tenant", "tenant-release", fixedNow()); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, packageapp.ReleaseBundleSnapshot{}) {
		t.Fatal("cancelled bundle snapshot returned data", err)
	}
	if v, err := p.ReadEvidenceBundleSnapshot(t.Context(), "tenant", "", time.Time{}); !errors.Is(err, ErrValidation) || !reflect.DeepEqual(v, packageapp.EvidenceBundleSnapshot{}) {
		t.Fatal("zero observation time accepted", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if v, err := p.ReadReleaseBundleSnapshot(t.Context(), "tenant", "tenant-release", fixedNow()); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, packageapp.ReleaseBundleSnapshot{}) {
		t.Fatal("closed bundle snapshot returned data", err)
	}
}

func TestMemoryBundleSnapshotsSharePublicRetentionBudgetAndNeverExposeLocations(t *testing.T) {
	tx, p := memoryBundleSnapshotFixture(t)
	retention := memoryCustomerRetentionFixture(t)
	tx.state.ObjectRetentionPolicies = retention.state.ObjectRetentionPolicies
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	release, err := p.ReadReleaseBundleSnapshot(t.Context(), "tenant", "tenant-release", fixedNow())
	if err != nil || len(release.ObjectLockProofs) != 3 || release.ObjectLockProofs[1]["status"] == "verified" || release.ObjectLockProofs[2]["status"] != "verified" {
		t.Fatal("public retention expiry/status changed", err)
	}
	all, err := p.ReadEvidenceBundleSnapshot(t.Context(), "tenant", "", fixedNow())
	if err != nil || len(all.Evidence) != 2 || all.ProductID != "" || len(all.ObjectLockProofs) != 3 {
		t.Fatal("tenant-wide export snapshot lost public facts", err)
	}
	raw, err := json.Marshal([]any{release, all})
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"private-title", "private-source", "private_payload", "private-prefix-marker", "private-key-marker", "private-bucket-marker", "foreign-policy"} {
		if strings.Contains(string(raw), marker) {
			t.Fatal("bundle snapshot exposed private or foreign source field", marker)
		}
	}
	release.ObjectLockProofs[0]["name"] = "caller mutation"
	all.ObjectLockProofs[0]["verification_checks"].([]map[string]any)[0]["detail"] = "caller mutation"
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("returned bundle proofs alias stored observations")
	}
	for i := 0; i < packageapp.MaxBundleSnapshotRows-2; i++ {
		id := fmt.Sprintf("bounded-evidence-%04d", i)
		tx.state.Evidence[id] = domain.EvidenceItem{ID: id, TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release"}
	}
	if v, err := p.ReadReleaseBundleSnapshot(t.Context(), "tenant", "tenant-release", fixedNow()); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, packageapp.ReleaseBundleSnapshot{}) {
		t.Fatal("combined evidence/proof overflow was truncated or returned", err)
	}
	if v, err := p.ReadEvidenceBundleSnapshot(t.Context(), "tenant", "", fixedNow()); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, packageapp.EvidenceBundleSnapshot{}) {
		t.Fatal("combined export/proof overflow returned data", err)
	}
}
