package app

import (
	"context"
	"errors"
	"testing"
)

func TestCollectorReleaseHealthAndImportBundleCollector(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, _, artifact := setupReleaseRiskFixture(t, ledger)
	collector, _, _, err := ledger.CreateCollector(ctx, actor, CreateCollectorInput{
		Name:    "offline-import",
		Type:    collectorTypeImportBundle,
		Version: "0.1.0",
		Scopes:  []string{ScopeBundleWrite, ScopeEvidenceWrite},
	})
	if err != nil {
		t.Fatalf("collector: %v", err)
	}
	sig, err := ledger.CreateArtifactSignature(ctx, actor, CreateArtifactSignatureInput{ArtifactID: artifact.ID, Algorithm: "cosign", Signature: "sig"})
	if err != nil {
		t.Fatalf("signature: %v", err)
	}
	release, err := ledger.RecordCollectorRelease(ctx, actor, RecordCollectorReleaseInput{
		CollectorID:    collector.ID,
		Version:        "0.1.0",
		ArtifactDigest: artifact.Digest,
		SignatureID:    sig.ID,
		Pinned:         true,
	})
	if err != nil {
		t.Fatalf("collector release: %v", err)
	}
	if !release.Pinned || release.HealthStatus != "needs_evidence" {
		t.Fatalf("collector release = %#v", release)
	}
	report, err := ledger.CollectorHealthReport(ctx, actor, collector.ID)
	if err != nil {
		t.Fatalf("health report: %v", err)
	}
	if report.PinnedReleaseID != release.ID || report.SupplyChainStatus != "needs_evidence" {
		t.Fatalf("health report = %#v", report)
	}
	_, _, otherSecret, err := ledger.BootstrapTenant(ctx, "Other", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap other: %v", err)
	}
	other, err := ledger.Authenticate(ctx, otherSecret)
	if err != nil {
		t.Fatalf("auth other: %v", err)
	}
	if _, err := ledger.CollectorHealthReport(ctx, other, collector.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant health err=%v, want not found", err)
	}
}
