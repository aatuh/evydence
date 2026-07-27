package app

import (
	"context"
	"errors"
	"testing"
)

func TestReleaseTransitionsRequireCurrentRevision(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Revisioned product", "revisioned-product")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	if release.Revision != 1 {
		t.Fatalf("created release revision=%d, want 1", release.Revision)
	}
	if _, err := ledger.FreezeRelease(ctx, actor, release.ID, 0); !errors.Is(err, ErrValidation) {
		t.Fatalf("freeze without revision err=%v, want validation", err)
	}
	frozen, err := ledger.FreezeRelease(ctx, actor, release.ID, release.Revision)
	if err != nil || frozen.Revision != 2 || frozen.State != "frozen" {
		t.Fatalf("freeze result=%#v err=%v", frozen, err)
	}
	if _, err := ledger.ApproveRelease(ctx, actor, frozen.ID, 1); !CurrentVersionConflict(err) {
		t.Fatalf("stale approve err=%v, want version conflict", err)
	} else if current, ok := CurrentRevision(err); !ok || current != frozen.Revision {
		t.Fatalf("stale approve current revision=%d ok=%t, want %d", current, ok, frozen.Revision)
	}
	approved, err := ledger.ApproveRelease(ctx, actor, frozen.ID, frozen.Revision)
	if err != nil || approved.Revision != 3 || approved.State != "approved" {
		t.Fatalf("approve result=%#v err=%v", approved, err)
	}
}

func TestReleaseCandidateTransitionRequiresCurrentRevision(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Candidate product", "candidate-product")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	candidate, err := ledger.CreateReleaseCandidate(ctx, actor, CreateReleaseCandidateInput{ReleaseID: release.ID, Name: "candidate"})
	if err != nil {
		t.Fatalf("create candidate: %v", err)
	}
	if candidate.Revision != 1 {
		t.Fatalf("created candidate revision=%d, want 1", candidate.Revision)
	}
	promoted, err := ledger.UpdateReleaseCandidateState(ctx, actor, candidate.ID, candidatePromoted, "accepted", candidate.Revision)
	if err != nil || promoted.Revision != 2 || promoted.State != candidatePromoted {
		t.Fatalf("promote result=%#v err=%v", promoted, err)
	}
	if _, err := ledger.UpdateReleaseCandidateState(ctx, actor, candidate.ID, candidateRejected, "late", candidate.Revision); !CurrentVersionConflict(err) {
		t.Fatalf("stale candidate transition err=%v, want version conflict", err)
	} else if current, ok := CurrentRevision(err); !ok || current != promoted.Revision {
		t.Fatalf("stale candidate current revision=%d ok=%t, want %d", current, ok, promoted.Revision)
	}
}
