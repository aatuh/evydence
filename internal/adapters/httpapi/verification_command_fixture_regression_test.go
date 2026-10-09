package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type failingVerificationCommandFixture struct {
	verificationCommandFixture
	changedID string
	isolated  bool
}

func (f *failingVerificationCommandFixture) failAfterWrite(ctx context.Context, id string, err error) error {
	if err != nil {
		return err
	}
	f.changedID, f.isolated = id, f.commandLedger(ctx) != f.ledger
	return errors.New("private verification fixture failure")
}

func (f *failingVerificationCommandFixture) VerifySubject(ctx context.Context, actor domain.Actor, kind, id string) (verificationdomain.VerificationResult, error) {
	value, err := f.verificationCommandFixture.VerifySubject(ctx, actor, kind, id)
	return value, f.failAfterWrite(ctx, value.ID, err)
}

func (f *failingVerificationCommandFixture) GenerateBackupManifest(ctx context.Context, actor domain.Actor) (verificationdomain.BackupManifest, error) {
	value, err := f.verificationCommandFixture.GenerateBackupManifest(ctx, actor)
	return value, f.failAfterWrite(ctx, value.ID, err)
}

func (f *failingVerificationCommandFixture) CreateMerkleBatch(ctx context.Context, actor domain.Actor, input verificationapp.CreateMerkleBatchInput) (verificationdomain.MerkleBatch, error) {
	value, err := f.verificationCommandFixture.CreateMerkleBatch(ctx, actor, input)
	return value, f.failAfterWrite(ctx, value.ID, err)
}

func (f *failingVerificationCommandFixture) CreateTransparencyCheckpoint(ctx context.Context, actor domain.Actor, input verificationapp.CreateTransparencyCheckpointInput) (verificationdomain.TransparencyCheckpoint, error) {
	value, err := f.verificationCommandFixture.CreateTransparencyCheckpoint(ctx, actor, input)
	return value, f.failAfterWrite(ctx, value.ID, err)
}

func (f *failingVerificationCommandFixture) CreateObjectRetentionPolicy(ctx context.Context, actor domain.Actor, input verificationapp.CreateObjectRetentionPolicyInput) (verificationdomain.ObjectRetentionPolicy, error) {
	value, err := f.verificationCommandFixture.CreateObjectRetentionPolicy(ctx, actor, input)
	return value, f.failAfterWrite(ctx, value.ID, err)
}

func (f *failingVerificationCommandFixture) VerifyObjectRetentionPolicy(ctx context.Context, actor domain.Actor, id string) (verificationdomain.ObjectRetentionPolicy, error) {
	value, err := f.verificationCommandFixture.VerifyObjectRetentionPolicy(ctx, actor, id)
	return value, f.failAfterWrite(ctx, value.ID, err)
}

func TestVerificationCommandFixturesRollBackAllEffectsAfterWriteFailure(t *testing.T) {
	for _, action := range []string{"subject", "backup", "merkle", "checkpoint", "retention-create", "retention-verify"} {
		t.Run(action, func(t *testing.T) {
			factory := app.NewMemoryUnitOfWorkFactory()
			ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory})
			scope := seedEvidenceFixtureScope(t, ledger, "Fixture")
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			server.authn = &configuredAuthenticator{actor: scope.actor}
			commands := &failingVerificationCommandFixture{verificationCommandFixture: verificationCommandFixture{catalogFixtureCommands{ledger: ledger}}}
			server.subjectVerification, server.backupGenerationCommands, server.merkleCreationCommands = commands, commands, commands
			server.transparencyCheckpointCommands, server.retentionCommands = commands, commands
			path, body := "/v1/verify", `{"subject_type":"audit_chain"}`
			switch action {
			case "backup":
				path, body = "/v1/backup-manifests", `{}`
			case "merkle":
				path, body = "/v1/merkle-batches", `{}`
			case "checkpoint":
				batch, err := ledger.CreateMerkleBatch(t.Context(), scope.actor, app.CreateMerkleBatchInput{})
				if err != nil {
					t.Fatal(err)
				}
				path, body = "/v1/transparency-checkpoints", fmt.Sprintf(`{"batch_id":%q,"provider":"operator","external_id":"assertion"}`, batch.ID)
			case "retention-create":
				path, body = "/v1/object-retention-policies", `{"name":"Lock","mode":"governance","retention_days":30}`
			case "retention-verify":
				policy, err := ledger.CreateObjectRetentionPolicy(t.Context(), scope.actor, app.CreateObjectRetentionPolicyInput{Name: "Lock", Mode: "governance", RetentionDays: 30})
				if err != nil {
					t.Fatal(err)
				}
				path, body = "/v1/object-retention-policies/"+policy.ID+"/verify", `{}`
			}
			keysBefore, err := listFixtureSigningKeys(t.Context(), ledger, scope.actor)
			if err != nil {
				t.Fatal(err)
			}
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, server, scope.secret, path, "fixture-verification-failure", []byte(body), 500)
			if commands.changedID == "" || !commands.isolated || strings.Contains(out, `"data"`) || strings.Contains(out, "private verification") || strings.Contains(out, `"signature_refs"`) {
				t.Fatal("failed verification command bypassed isolation or leaked partial effects")
			}
			if action != "retention-verify" && strings.Contains(out, commands.changedID) {
				t.Fatal("failed command disclosed a newly allocated receipt ID")
			}
			after, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if len(after.Idempotency) != 1 {
				t.Fatal("failed command lost its failed replay record")
			}
			for _, record := range after.Idempotency {
				if record.State != app.IdempotencyFailed || record.Response != nil || record.Status != 0 {
					t.Fatal("failed command stored a partial replay response")
				}
			}
			after.Idempotency = before.Idempotency
			if !reflect.DeepEqual(before, after) {
				t.Fatal("failed command committed key, signature, metadata, receipt, audit or job effects")
			}
			keysAfter, err := listFixtureSigningKeys(t.Context(), ledger, scope.actor)
			if err != nil || !reflect.DeepEqual(keysBefore, keysAfter) {
				t.Fatal("failed command changed cached signing-key lifecycle", err)
			}
		})
	}
}

func TestVerificationCommandFixtureGuardsPreserveAuthorityAndReadOnlyState(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory})
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	foreign := seedEvidenceFixtureScope(t, ledger, "Foreign")
	commands := verificationCommandFixture{catalogFixtureCommands{ledger: ledger}}
	checks := []struct {
		name, scope string
		run         func(context.Context, domain.Actor) error
	}{
		{"backup", "admin", commands.AuthorizeBackupGeneration},
		{"merkle", "keys:admin", commands.AuthorizeMerkleCreation},
		{"checkpoint", "keys:admin", func(ctx context.Context, actor domain.Actor) error {
			return commands.AuthorizeTransparencyCheckpoint(ctx, actor, "batch")
		}},
		{"retention-create", "admin", func(ctx context.Context, actor domain.Actor) error {
			return commands.AuthorizeCreateObjectRetentionPolicy(ctx, actor, verificationapp.CreateObjectRetentionPolicyInput{})
		}},
		{"retention-verify", "verify:read", func(ctx context.Context, actor domain.Actor) error {
			return commands.AuthorizeVerifyObjectRetentionPolicy(ctx, actor, "policy")
		}},
		{"cosign", "verify:read", func(ctx context.Context, actor domain.Actor) error {
			return commands.AuthorizeCosignVerification(ctx, actor, verificationapp.VerifyCosignInput{})
		}},
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(t.Context(), owner.actor); err != nil {
				t.Fatal("guard rejected current issued authority", err)
			}
			denied := owner.actor
			denied.Scopes = []string{"evidence:read"}
			if err := tc.run(t.Context(), denied); !errors.Is(err, application.ErrForbidden) {
				t.Fatal("guard skipped required authority", err)
			}
			human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"*"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"*"}}}}
			if err := tc.run(t.Context(), human); !errors.Is(err, application.ErrForbidden) {
				t.Fatal("product grant became tenant-wide authority", err)
			}
			human.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: owner.actor.TenantID, Scopes: []string{tc.scope}}}
			if err := tc.run(t.Context(), human); err != nil {
				t.Fatal("guard rejected current tenant grant", err)
			}
			human.ResourceGrants = nil
			if err := tc.run(t.Context(), human); !errors.Is(err, application.ErrForbidden) {
				t.Fatal("removed grant retained authority", err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if err := tc.run(ctx, owner.actor); !errors.Is(err, context.Canceled) {
				t.Fatal("guard ignored cancellation", err)
			}
		})
	}
	if err := commands.AuthorizeSubjectVerification(t.Context(), owner.actor, "evidence_item", owner.original.ID); err != nil {
		t.Fatal("subject guard rejected owned evidence", err)
	}
	if err := commands.AuthorizeSubjectVerification(t.Context(), foreign.actor, "evidence_item", owner.original.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("subject guard accepted foreign evidence", err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("verification replay guards changed repository state", err)
	}
}

func TestVerificationFixtureMappersPreserveAllReceiptFieldsWithoutAliasing(t *testing.T) {
	now := time.Date(2026, 10, 7, 14, 0, 0, 0, time.UTC)
	value := domain.CosignVerification{ID: "receipt", TenantID: "tenant", ArtifactID: "artifact", ContainerImageID: "image", ArtifactSignatureID: "signature", SubjectDigest: "digest", RekorUUID: "uuid", RekorLogIndex: "7", CertificateIdentity: "identity", CertificateIssuer: "issuer", VerifierLibraryVersion: "library", TrustRootVersion: "root", VerificationMode: "offline", Result: "failed", Checks: []domain.VerifyCheck{{Name: "proof", Result: "failed", Detail: "mismatch"}}, Profile: domain.VerificationProfile{ID: "profile", Version: "1", RequiredChecks: []string{"proof"}, TrustMaterial: []string{"root"}, IdentityPolicy: "policy", TransparencyProof: "embedded", PayloadScope: "scope", PayloadDigest: "digest", Limitations: []string{"profile-limit"}}, Limitations: []string{"receipt-limit"}, SchemaVersion: "cosign.v1", CreatedAt: now}
	model, err := fixtureCosignVerification(value, app.ErrVerificationFailed)
	if !errors.Is(err, app.ErrVerificationFailed) || !reflect.DeepEqual(domain.CosignVerificationFromContextModel(model), value) {
		t.Fatal("fixture mapper lost failed receipt or public assurance metadata", err)
	}
	model.Checks[0].Detail, model.Profile.RequiredChecks[0], model.Profile.TrustMaterial[0], model.Profile.Limitations[0], model.Limitations[0] = "changed", "changed", "changed", "changed", "changed"
	if value.Checks[0].Detail != "mismatch" || value.Profile.RequiredChecks[0] != "proof" || value.Profile.TrustMaterial[0] != "root" || value.Profile.Limitations[0] != "profile-limit" || value.Limitations[0] != "receipt-limit" {
		t.Fatal("fixture mapper shared mutable receipt data")
	}
	if result, err := fixtureCosignVerification(value, app.ErrForbidden); !errors.Is(err, app.ErrForbidden) || result.ID != "" {
		t.Fatal("denied inspection produced a public receipt", err)
	}
	backup := domain.BackupManifest{ID: "backup", TenantID: "tenant", StateHash: "hash", ResourceCounts: map[string]int{"evidence": 2}, ConsistencyChecks: []domain.VerifyCheck{{Name: "chain", Result: "passed", Detail: "intact"}}, Limitations: []string{"not restore proof"}, SchemaVersion: "backup-manifest.v1.0.0", CreatedAt: now}
	manifest := fixtureBackupManifest(backup)
	if !reflect.DeepEqual(domain.BackupManifestFromContextModel(manifest), backup) {
		t.Fatal("fixture mapper changed backup hash, profile version or metadata")
	}
	manifest.ResourceCounts["evidence"], manifest.ConsistencyChecks[0].Detail, manifest.Limitations[0] = 99, "changed", "changed"
	if backup.ResourceCounts["evidence"] != 2 || backup.ConsistencyChecks[0].Detail != "intact" || backup.Limitations[0] != "not restore proof" {
		t.Fatal("fixture mapper shared mutable backup data")
	}
}

func TestRetiredVerificationAPIDescriptionsRequirePostgreSQL(t *testing.T) {
	server, _ := testServer(t)
	raw, err := server.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths      map[string]map[string]struct{ Description string }
		Components struct {
			Schemas map[string]struct{ Description string }
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	descriptions := map[string]string{}
	for _, path := range []string{"/v1/verify", "/v1/backup-manifests", "/v1/artifact-signatures/{id}/verify-cosign", "/v1/build-attestations/{id}/verify-signature"} {
		descriptions[path] = doc.Paths[path]["post"].Description
	}
	for _, name := range []string{"CreateMerkleBatchRequest", "CreateTransparencyCheckpointRequest", "CreateObjectRetentionPolicyRequest"} {
		descriptions[name] = doc.Components.Schemas[name].Description
	}
	for name, description := range descriptions {
		if !strings.Contains(description, "requires PostgreSQL") || strings.Contains(strings.ToLower(description), "local memory") {
			t.Fatal("verification contract promises a retired runtime", name)
		}
	}
}
