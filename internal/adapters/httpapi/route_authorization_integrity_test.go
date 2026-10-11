package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func newNativeIntegrityAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	f := newNativeReportAuthorizationFixture(t)
	var err error
	f.batch, err = createMerkleBatchFixture(t.Context(), f.ledger, f.owner.actor, f.owner.release.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	// The HTTP backup commitment port is explicitly synthetic; native policy,
	// locked audit verification and manifest/receipt/audit writes still execute.
	// This is not PostgreSQL backup-state or recovery evidence.
	backup, err := (verificationCommandFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: f.ledger}}).GenerateBackupManifest(t.Context(), f.owner.actor)
	if err != nil {
		t.Fatal(err)
	}
	f.backup = domain.BackupManifestFromContextModel(backup)
	f.artifact = seedArtifactNativeFixture(t, f.ledger, f.owner)
	f.signature, err = createFixtureArtifactSignature(t.Context(), f.ledger, nil, f.owner.actor, verificationapp.CreateArtifactSignatureInput{ArtifactID: f.artifact.ID, Algorithm: "recorded", Signature: "opaque-metadata"})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func newNativeRetentionAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	f := newNativeAuthorizationFixture(t)
	at := f.owner.release.CreatedAt
	key := "tenants/" + f.owner.actor.TenantID + "/raw/fixture"
	var calls int
	// This is a controlled provider observation, not a claim of enforced
	// retention on an external object store. Policy/transactions stay native.
	provider := retentionFixtureProviderFunc(func(ctx context.Context, in app.ObjectRetentionRequest) (app.ObjectRetentionResult, error) {
		calls++
		if ctx.Err() != nil || in.TenantID != f.owner.actor.TenantID || in.ObjectKey != key {
			t.Fatal("retention observation used an unauthorized scope")
		}
		return app.ObjectRetentionResult{Provider: "s3", Bucket: "fixture", ObjectKey: key, Mode: "governance", RetentionDays: 30, Enforced: true, ObservedAt: at, Checks: []domain.VerifyCheck{{Name: "fixture_observation", Result: "passed"}}, Limitations: []string{"Controlled fixture observation, not real storage-provider proof"}}, nil
	})
	commands := retentionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: f.ledger}, clock: application.ClockFunc(func() time.Time { return at }), verifier: provider}
	p, err := commands.CreateObjectRetentionPolicy(t.Context(), f.owner.actor, verificationapp.CreateObjectRetentionPolicyInput{Name: "Lock", Mode: "governance", RetentionDays: 30, ObjectKey: key})
	if err != nil {
		t.Fatal(err)
	}
	f.retention = domain.ObjectRetentionPolicyFromContextModel(p)
	f.server.retentionCommands = commands
	f.externalCalls = func() int { return calls }
	return f
}

func newNativeDSSEAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	seed := newDSSENativeFixture(t, true)
	foreign := seedOperationsFixtureScope(t, seed.ledger, "Foreign")
	snapshot, err := seed.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	owner := operationsFixtureScope{actor: seed.owner.actor, product: seed.owner.product, release: snapshot.Releases[seed.build.ReleaseID], evidence: seed.owner.original}
	f := nativeAuthorizationFixtureFromScopes(t, seed.ledger, seed.base, owner, foreign)
	f.build, f.attestation = seed.build, seed.attestation
	f.server.bindDSSEVerificationFixtureResources(seed.objects)
	return f
}

func addNativeIntegrityAuthorizationCases(cases map[string]func(*testing.T)) {
	for _, tc := range []struct{ operation, path string }{
		{"createMerkleBatch", "/v1/merkle-batches"}, {"generateBackupManifest", "/v1/backup-manifests"},
	} {
		cases[tc.operation] = nativeWriteAuthorizationCase(tc.operation, func(nativeAuthorizationFixture) (string, []byte) { return tc.path, []byte(`{}`) }, 201)
	}
	cases["createTransparencyCheckpoint"] = nativeWriteAuthorizationFixtureCase("createTransparencyCheckpoint", newNativeIntegrityAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
		return "/v1/transparency-checkpoints", []byte(fmt.Sprintf(`{"batch_id":%q,"provider":"internal","external_id":"recorded-assertion"}`, f.batch.ID))
	}, 201, 404)
	cases["createObjectRetentionPolicy"] = nativeWriteAuthorizationCase("createObjectRetentionPolicy", func(nativeAuthorizationFixture) (string, []byte) {
		return "/v1/object-retention-policies", []byte(`{"name":"Lock","mode":"governance","retention_days":30}`)
	}, 201)
	cases["verifyObjectRetentionPolicy"] = nativeMutationAuthorizationFixtureCase("verifyObjectRetentionPolicy", newNativeRetentionAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
		return "/v1/object-retention-policies/" + f.retention.ID + "/verify", []byte(`{}`)
	}, nativeMutationExpectation{status: 200, foreignStatus: 404, auditDelta: 1, externalCalls: 1})
	for _, tc := range []struct {
		operation string
		foreign   int
		path      func(nativeAuthorizationFixture) string
	}{
		{"verifyAuditChain", 0, func(nativeAuthorizationFixture) string { return "/v1/audit-chain/verify" }},
		{"verifyBackupManifest", 404, func(f nativeAuthorizationFixture) string { return "/v1/backup-manifests/" + f.backup.ID + "/verify" }},
		{"verifyMerkleBatch", 404, func(f nativeAuthorizationFixture) string { return "/v1/merkle-batches/" + f.batch.ID + "/verify" }},
		{"verifyReleaseBundle", 404, func(f nativeAuthorizationFixture) string {
			return "/v1/release-bundles/" + f.report.bundle.ID + "/verify"
		}},
	} {
		cases[tc.operation] = nativeMutationAuthorizationFixtureCase(tc.operation, newNativeIntegrityAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) { return tc.path(f), nil }, nativeMutationExpectation{status: 200, foreignStatus: tc.foreign, auditDelta: 1, method: http.MethodGet, result: "passed"})
	}
	cases["verifyBuildAttestationSignature"] = nativeMutationAuthorizationFixtureCase("verifyBuildAttestationSignature", newNativeDSSEAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
		return "/v1/build-attestations/" + f.attestation.ID + "/verify-signature", []byte(`{}`)
	}, nativeMutationExpectation{status: 200, foreignStatus: 404, auditDelta: 1, result: "passed"})
	cases["verify"] = func(t *testing.T) {
		for _, tc := range []struct {
			kind string
			id   func(nativeAuthorizationFixture) string
			dsse bool
		}{
			{"evidence_item", func(f nativeAuthorizationFixture) string { return f.owner.evidence.ID }, false},
			{"build_attestation", func(f nativeAuthorizationFixture) string { return f.attestation.ID }, true},
			{"audit_chain", func(nativeAuthorizationFixture) string { return "" }, false},
			{"release_bundle", func(f nativeAuthorizationFixture) string { return f.report.bundle.ID }, false},
			{"artifact_signature", func(f nativeAuthorizationFixture) string { return f.signature.ID }, false},
			{"merkle_batch", func(f nativeAuthorizationFixture) string { return f.batch.ID }, false},
			{"audit_chain_checkpoint", func(f nativeAuthorizationFixture) string { return f.batch.ID }, false},
			{"audit_chain_release_manifest", func(f nativeAuthorizationFixture) string { return f.report.bundle.ID }, false},
			{"backup_manifest", func(f nativeAuthorizationFixture) string { return f.backup.ID }, false},
		} {
			t.Run(tc.kind, func(t *testing.T) {
				fixture := newNativeIntegrityAuthorizationFixture
				if tc.dsse {
					fixture = newNativeDSSEAuthorizationFixture
				}
				foreign := 404
				if tc.kind == "audit_chain" {
					foreign = 0
				}
				result := "passed"
				if tc.kind == "artifact_signature" {
					result = "limited"
				} // metadata is not cryptographic verification
				run := nativeMutationAuthorizationFixtureCase("verify", fixture, func(f nativeAuthorizationFixture) (string, []byte) {
					return "/v1/verify", []byte(fmt.Sprintf(`{"subject_type":%q,"subject_id":%q}`, tc.kind, tc.id(f)))
				}, nativeMutationExpectation{status: 200, foreignStatus: foreign, auditDelta: 1, result: result})
				run(t)
			})
		}
	}
}
