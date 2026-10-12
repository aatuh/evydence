package app

import (
	"errors"
	"testing"
)

func TestGraphSnapshotRejectsMismatchedProductAndRelease(t *testing.T) {
	l := newLegacyLedgerFixture(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	a, release, _ := setupReleaseRiskFixture(t, l)
	product, err := l.CreateProduct(t.Context(), a, "Other", "other")
	if err != nil {
		t.Fatal(err)
	}
	beforeGraphs, beforeAudit := len(l.graphSnapshots), len(l.chain[a.TenantID])
	v, err := l.CreateGraphSnapshot(t.Context(), a, CreateGraphSnapshotInput{ProductID: product.ID, ReleaseID: release.ID})
	if !errors.Is(err, ErrNotFound) || v.ID != "" {
		t.Fatal("mismatched pair published a false has_release edge", v, err)
	}
	if len(l.graphSnapshots) != beforeGraphs || len(l.chain[a.TenantID]) != beforeAudit {
		t.Fatal("invalid graph published effects")
	}
}

func TestGraphSnapshotResponseCannotMutateStoredAdjacency(t *testing.T) {
	l := newLegacyLedgerFixture(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	a, release, _ := setupReleaseRiskFixture(t, l)
	v, err := l.CreateGraphSnapshot(t.Context(), a, CreateGraphSnapshotInput{ProductID: release.ProductID, ReleaseID: release.ID})
	if err != nil {
		t.Fatal(err)
	}
	v.Nodes[0].Label = "changed"
	v.Edges[0].From = "changed"
	v.Limitations[0] = "changed"
	saved := l.graphSnapshots[v.ID]
	if saved.Nodes[0].Label == "changed" || saved.Edges[0].From == "changed" || saved.Limitations[0] == "changed" {
		t.Fatal("graph caller mutated immutable stored adjacency")
	}
}
