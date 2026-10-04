package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestLocalSubjectVerificationReplayUsesCurrentScopeWithoutInspection(t *testing.T) {
	l := NewLedger(Config{})
	a, release, _ := setupReleaseRiskFixture(t, l)
	l.projects["project"] = domain.Project{ID: "project", TenantID: a.TenantID, ProductID: release.ProductID}
	l.buildRuns["build"] = domain.BuildRun{ID: "build", TenantID: a.TenantID, ProjectID: "project", ReleaseID: release.ID}
	l.evidence["evidence"] = domain.EvidenceItem{ID: "evidence", TenantID: a.TenantID, ProductID: release.ProductID, ProjectID: "project", ReleaseID: release.ID, BuildID: "build"}
	l.attestations["attestation"] = domain.BuildAttestation{ID: "attestation", TenantID: a.TenantID, BuildID: "build", EvidenceID: "evidence", PayloadRef: strings.Repeat("private-", 1200000)}
	l.bundles["bundle"] = domain.ReleaseBundle{ID: "bundle", TenantID: a.TenantID, ReleaseID: release.ID}
	l.merkleBatches["batch"] = domain.MerkleBatch{ID: "batch", TenantID: a.TenantID}
	l.backupManifests["backup"] = domain.BackupManifest{ID: "backup", TenantID: a.TenantID}
	l.artifacts["artifact"] = domain.Artifact{ID: "artifact", TenantID: a.TenantID}
	l.artifactSigs["signature"] = domain.ArtifactSignature{ID: "signature", TenantID: a.TenantID, ArtifactID: "artifact"}
	before := len(l.chain[a.TenantID])
	l.verificationCommands = nil
	l.now = func() time.Time { panic("guard used clock/inspector") }
	guard, ok := any(l).(interface {
		AuthorizeSubjectVerification(context.Context, domain.Actor, string, string) error
	})
	if !ok {
		t.Fatal("missing local generic current-ownership guard")
	}
	for _, tc := range []struct {
		kind, id string
		scoped   bool
	}{
		{"audit_chain", "", false}, {"evidence_item", "evidence", true}, {"release_bundle", "bundle", true}, {"build_attestation", "attestation", true}, {"artifact_signature", "signature", false}, {"merkle_batch", "batch", false}, {"audit_chain_checkpoint", "batch", false}, {"audit_chain_release_manifest", "bundle", false}, {"backup_manifest", "backup", false},
	} {
		human := domain.Actor{TenantID: a.TenantID, UserID: "user", Scopes: []string{ScopeVerifyRead}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: a.TenantID, Scopes: []string{ScopeVerifyRead}}}}
		if err := guard.AuthorizeSubjectVerification(t.Context(), human, tc.kind, tc.id); err != nil {
			t.Fatal(tc, err)
		}
		human.ResourceGrants[0].ResourceType, human.ResourceGrants[0].ResourceID = "release", release.ID
		err := guard.AuthorizeSubjectVerification(t.Context(), human, tc.kind, tc.id)
		if tc.scoped && err != nil || !tc.scoped && !errors.Is(err, ErrForbidden) {
			t.Fatal("wrong scoped replay policy", tc, err)
		}
		human.ResourceGrants = nil
		if err := guard.AuthorizeSubjectVerification(t.Context(), human, tc.kind, tc.id); !errors.Is(err, ErrForbidden) {
			t.Fatal(tc, err)
		}
		if tc.kind != "audit_chain" {
			if err := guard.AuthorizeSubjectVerification(t.Context(), a, tc.kind, "missing"); !errors.Is(err, ErrNotFound) {
				t.Fatal(tc, err)
			}
		}
	}
	product := l.products[release.ProductID]
	foreign := product
	foreign.TenantID = "other"
	l.products[release.ProductID] = foreign
	for _, tc := range []struct{ kind, id string }{{"evidence_item", "evidence"}, {"release_bundle", "bundle"}, {"audit_chain_release_manifest", "bundle"}} {
		if err := guard.AuthorizeSubjectVerification(t.Context(), a, tc.kind, tc.id); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign current product accepted", tc, err)
		}
	}
	l.products[release.ProductID] = product
	if len(l.verifications) != 0 || len(l.chain[a.TenantID]) != before {
		t.Fatal("guard wrote verification or audit")
	}
}
