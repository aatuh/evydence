package app

import (
	"context"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func TestEvidenceCanonicalProfileKeepsImmutableOriginBoundWhileRelationshipsEvolve(t *testing.T) {
	item := domain.EvidenceItem{
		ID: "ev_profile", TenantID: "ten_profile", ProductID: "prod_origin", ReleaseID: "rel_origin",
		Type: "build", Title: "Build evidence", SourceSystem: "api", PayloadHash: sampleDigest("payload"),
		Canonicalization: evidencedomain.EvidenceCanonicalizationProfileVersion,
		SubjectRefs:      []domain.SubjectRef{{Type: "product", ID: "prod_origin"}, {Type: "release", ID: "rel_origin"}},
		CreatedAt:        fixedNow(), ObservedAt: fixedNow(),
	}
	originalHash, err := canonicalHash(item)
	if err != nil {
		t.Fatalf("canonicalHash original: %v", err)
	}
	linked := item
	linked.ProductID = "prod_projection"
	linked.ReleaseID = "rel_projection"
	linked.RelatedEvidenceRefs = []domain.EvidenceRef{{Type: "release", ID: "rel_projection", Relationship: "linked_to"}}
	linked.SupersededBy = "ev_replacement"
	linkedHash, err := canonicalHash(linked)
	if err != nil {
		t.Fatalf("canonicalHash linked: %v", err)
	}
	if linkedHash != originalHash {
		t.Fatalf("relationship projection changed immutable canonical hash: original=%q linked=%q", originalHash, linkedHash)
	}

	tampered := linked
	tampered.SubjectRefs = []domain.SubjectRef{{Type: "product", ID: "prod_tampered"}}
	tamperedHash, err := canonicalHash(tampered)
	if err != nil {
		t.Fatalf("canonicalHash tampered: %v", err)
	}
	if tamperedHash == originalHash {
		t.Fatal("immutable origin subject references were not hash-bound")
	}
}

func TestReleaseArtifactDigestsIgnoreUnboundSubjectDigestAssertions(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	tenantID, releaseID := "ten_1", "rel_1"
	registered := domain.Artifact{ID: "art_1", TenantID: tenantID, Digest: sampleDigest("build")}
	forged := sampleDigest("x")
	ledger.artifacts[registered.ID] = registered
	ledger.evidence["ev_1"] = domain.EvidenceItem{
		ID: "ev_1", TenantID: tenantID, ReleaseID: releaseID,
		SubjectRefs: []domain.SubjectRef{
			{Type: "artifact", Digest: forged},
			{Type: "artifact", ID: registered.ID, Digest: forged},
			{Type: "Artifact", ID: "opaque", Digest: forged},
		},
	}

	digests := ledger.releaseArtifactDigestsLocked(tenantID, releaseID)
	if _, ok := digests[registered.Digest]; !ok {
		t.Fatalf("registered artifact digest missing: %#v", digests)
	}
	if _, ok := digests[forged]; ok {
		t.Fatalf("unbound subject digest was trusted: %#v", digests)
	}
}

func TestCreateLinkSupersedeEvidencePreservesCanonicalVerification(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	product, err := ledger.CreateProduct(ctx, actor, "Product", "product")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	original, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{Type: "build", Title: "Original", PayloadHash: sampleDigest("original")})
	if err != nil {
		t.Fatalf("create original evidence: %v", err)
	}
	replacement, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ProductID: product.ID, Type: "build", Title: "Replacement", PayloadHash: sampleDigest("replacement")})
	if err != nil {
		t.Fatalf("create replacement evidence: %v", err)
	}
	if original.Canonicalization != evidencedomain.EvidenceCanonicalizationProfileVersion || replacement.Canonicalization != evidencedomain.EvidenceCanonicalizationProfileVersion {
		t.Fatalf("canonicalization profiles: original=%q replacement=%q", original.Canonicalization, replacement.Canonicalization)
	}

	linked, err := ledger.LinkEvidence(ctx, actor, original.ID, "release", release.ID)
	if err != nil {
		t.Fatalf("link evidence: %v", err)
	}
	if linked.CanonicalHash != original.CanonicalHash {
		t.Fatalf("link rewrote canonical history: before=%q after=%q", original.CanonicalHash, linked.CanonicalHash)
	}
	assertEvidenceCanonicalVerificationPassed(t, ledger, actor, original.ID)

	superseded, err := ledger.SupersedeEvidence(ctx, actor, original.ID, replacement.ID, "corrected build evidence")
	if err != nil {
		t.Fatalf("supersede evidence: %v", err)
	}
	if superseded.CanonicalHash != original.CanonicalHash {
		t.Fatalf("supersession rewrote canonical history: before=%q after=%q", original.CanonicalHash, superseded.CanonicalHash)
	}
	assertEvidenceCanonicalVerificationPassed(t, ledger, actor, original.ID)
	assertEvidenceCanonicalVerificationPassed(t, ledger, actor, replacement.ID)

	events, err := ledger.ListEvidenceLifecycleEvents(ctx, actor, original.ID)
	if err != nil {
		t.Fatalf("list lifecycle events: %v", err)
	}
	var supersessionRecorded bool
	for _, event := range events {
		if event.Reason == "corrected build evidence" && event.ReplacementID == replacement.ID && event.Details["operation"] == "supersede" {
			supersessionRecorded = true
		}
	}
	if len(events) != 2 || !supersessionRecorded {
		t.Fatalf("append-only relationship history = %#v", events)
	}
}

func TestLegacyEvidenceLinkAndSupersessionRemainVerifiable(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	product, err := ledger.CreateProduct(ctx, actor, "Legacy product", "legacy-product")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	original, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{Type: "build", Title: "Legacy original", PayloadHash: sampleDigest("legacy-original")})
	if err != nil {
		t.Fatalf("create original: %v", err)
	}
	replacement, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{Type: "build", Title: "Legacy replacement", PayloadHash: sampleDigest("legacy-replacement")})
	if err != nil {
		t.Fatalf("create replacement: %v", err)
	}
	for _, id := range []string{original.ID, replacement.ID} {
		legacy := ledger.evidence[id]
		legacy.Canonicalization = evidencedomain.LegacyEvidenceCanonicalizationProfileVersion
		legacy.CanonicalHash, err = canonicalHash(legacy)
		if err != nil {
			t.Fatalf("legacy canonical hash: %v", err)
		}
		ledger.evidence[id] = legacy
	}
	original = ledger.evidence[original.ID]
	replacement = ledger.evidence[replacement.ID]
	ledger.lifecycle["elc_historical_spoof"] = domain.EvidenceLifecycleEvent{
		ID: "elc_historical_spoof", TenantID: actor.TenantID, EvidenceID: original.ID,
		Action: "amendment", Reason: "historical caller detail",
		Details: map[string]any{evidencedomain.LegacyCanonicalOriginDetailKey: map[string]any{"release_id": "rel_spoof"}},
		ActorID: actor.KeyID, SchemaVersion: evidencedomain.EvidenceLifecycleSchemaVersion, CreatedAt: fixedNow(),
	}

	linked, err := ledger.LinkEvidence(ctx, actor, original.ID, "release", release.ID)
	if err != nil {
		t.Fatalf("link legacy evidence: %v", err)
	}
	if linked.CanonicalHash != original.CanonicalHash {
		t.Fatalf("legacy link rewrote canonical hash: before=%q after=%q", original.CanonicalHash, linked.CanonicalHash)
	}
	assertEvidenceCanonicalVerificationPassed(t, ledger, actor, original.ID)

	if _, err := ledger.SupersedeEvidence(ctx, actor, original.ID, replacement.ID, "legacy correction"); err != nil {
		t.Fatalf("supersede legacy evidence: %v", err)
	}
	assertEvidenceCanonicalVerificationPassed(t, ledger, actor, original.ID)
	assertEvidenceCanonicalVerificationPassed(t, ledger, actor, replacement.ID)
}

func assertEvidenceCanonicalVerificationPassed(t *testing.T, ledger *Ledger, actor domain.Actor, evidenceID string) {
	t.Helper()
	result, err := ledger.VerifySubject(context.Background(), actor, "evidence_item", evidenceID)
	if err != nil {
		t.Fatalf("VerifySubject(%q): %v", evidenceID, err)
	}
	if result.Result != "passed" {
		t.Fatalf("VerifySubject(%q) result = %q, checks=%#v", evidenceID, result.Result, result.Checks)
	}
}
