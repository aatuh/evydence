package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
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

func TestBackupGenerationFixtureUsesNativeTenantManifestNotLegacySnapshot(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture-pepper", UnitOfWork: factory})
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	foreign := seedEvidenceFixtureScope(t, ledger, "Foreign")
	cold := newLegacyLedgerFixture(repositoryFixtureConfig{UnitOfWork: factory, Now: func() time.Time { panic("backup consulted aggregate clock") }})
	commands := verificationCommandFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: cold}}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := commands.GenerateBackupManifest(t.Context(), owner.actor)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != verificationdomain.BackupManifestTenantSchemaVersion || manifest.TenantID != owner.actor.TenantID || len(manifest.ResourceCounts) != 8 || !strings.HasPrefix(manifest.StateHash, "sha256:") {
		t.Fatal("HTTP fixture still generated a historical aggregate snapshot manifest")
	}
	if len(manifest.ConsistencyChecks) == 0 || len(manifest.Limitations) == 0 {
		t.Fatal("native manifest lost audit checks or backup limitations")
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{owner.secret, foreign.secret, foreign.actor.TenantID} {
		if strings.Contains(string(raw), private) {
			t.Fatal("public manifest disclosed credentials or foreign tenant data")
		}
	}
	expected, err := application.NormalizedJSONHash("HTTP backup commitment port test double; not a state snapshot")
	if err != nil || manifest.StateHash != expected || manifest.ResourceCounts["audit_chain_entries"] != len(before.AuditEntries[owner.actor.TenantID]) {
		t.Fatal("native core did not preserve the explicit synthetic commitment and current audit coordinate", err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(after.BackupManifests[manifest.ID], domain.BackupManifestFromContextModel(manifest)) {
		t.Fatal("native manifest was not stored intact", err)
	}
	entries := after.AuditEntries[owner.actor.TenantID]
	if len(entries) != len(before.AuditEntries[owner.actor.TenantID])+1 {
		t.Fatal("native generation did not append exactly one audit entry")
	}
	event := entries[len(entries)-1]
	if event.EntryType != "backup_manifest.generated" || event.SubjectType != "backup_manifest" || event.SubjectID != manifest.ID || event.PayloadHash != manifest.StateHash || !app.VerifyAuditChainEntryHash(event) {
		t.Fatal("backup audit binding or canonical hash changed")
	}
	manifest.ResourceCounts["evidence"], manifest.ConsistencyChecks[0].Detail, manifest.Limitations[0] = 99, "caller mutation", "caller mutation"
	unchanged, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(after, unchanged) {
		t.Fatal("returned manifest aliases stored rows", err)
	}
	delete(after.BackupManifests, manifest.ID)
	after.AuditEntries[owner.actor.TenantID] = before.AuditEntries[owner.actor.TenantID]
	if !reflect.DeepEqual(before, after) {
		t.Fatal("native generation changed unrelated rows or foreign tenant state")
	}
}

func TestBackupGenerationFixtureGuardAndReplayAvoidCommitmentReads(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture-pepper", UnitOfWork: factory})
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	reads := 0
	commands := verificationCommandFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, backupCommitment: func(ctx context.Context, tenant string, reader verificationapp.AuditChainVerificationReader) (verificationapp.BackupStateCommitment, error) {
		reads++
		return scriptedHTTPBackupCommitment(ctx, tenant, reader)
	}}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := commands.AuthorizeBackupGeneration(t.Context(), owner.actor); err != nil || reads != 0 {
		t.Fatal("backup guard generated a commitment", err)
	}
	guarded, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, guarded) {
		t.Fatal("backup guard changed current rows", err)
	}
	auth := &configuredAuthenticator{actor: owner.actor}
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	server.backupGenerationCommands = commands
	one := postRaw(t, server, owner.secret, "/v1/backup-manifests", "native-fixture", []byte(`{}`), 201)
	assertTrustHTTPReplay(t, one, postRaw(t, server, owner.secret, "/v1/backup-manifests", "native-fixture", []byte(`{}`), 201))
	if reads != 1 {
		t.Fatal("completed replay regenerated its commitment", reads)
	}
	after, err := factory.Snapshot()
	if err != nil || len(after.BackupManifests) != len(before.BackupManifests)+1 || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+1 {
		t.Fatal("generation or replay duplicated manifest/audit effects", err)
	}
	auth.actor.Scopes = []string{"evidence:read"}
	postRaw(t, server, owner.secret, "/v1/backup-manifests", "native-fixture", []byte(`{}`), 403)
	if reads != 1 {
		t.Fatal("revoked admin authority reached commitment reader")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := commands.AuthorizeBackupGeneration(ctx, owner.actor); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled guard succeeded", err)
	}
	missing := owner.actor
	missing.TenantID = "missing-tenant"
	if err := commands.AuthorizeBackupGeneration(t.Context(), missing); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("guard trusted cached/missing tenant ownership", err)
	}
	unchanged, err := factory.Snapshot()
	if err != nil || reads != 1 || !reflect.DeepEqual(after, unchanged) {
		t.Fatal("denied/missing/cancelled guard changed repository state", err)
	}
}

func TestBackupGenerationFixtureRejectsInvalidCommitmentAndCommitFailureWithoutEffects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*verificationapp.BackupStateCommitment)
		want   error
	}{
		{"foreign", func(c *verificationapp.BackupStateCommitment) { c.TenantID = "foreign" }, app.ErrNotFound},
		{"legacy-profile", func(c *verificationapp.BackupStateCommitment) {
			c.Profile = verificationapp.BackupStateCommitmentProfileV1
		}, app.ErrConflict},
		{"bad-digest", func(c *verificationapp.BackupStateCommitment) { c.StateHash = "sha256:invalid" }, app.ErrConflict},
		{"audit-mismatch", func(c *verificationapp.BackupStateCommitment) { c.ResourceCounts["audit_chain_entries"]-- }, app.ErrConflict},
		{"row-limit", func(c *verificationapp.BackupStateCommitment) {
			c.RowsRead = verificationapp.MaxBackupStateCommitmentRows + 1
		}, app.ErrConflict},
		{"commit-failure", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := app.NewMemoryUnitOfWorkFactory()
			factory := &operatorQueryFailureFactory{base: base}
			ledger := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture-pepper", UnitOfWork: factory})
			owner := seedEvidenceFixtureScope(t, ledger, "Owner")
			reads := 0
			commands := verificationCommandFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, backupCommitment: func(ctx context.Context, tenant string, reader verificationapp.AuditChainVerificationReader) (verificationapp.BackupStateCommitment, error) {
				reads++
				c, err := scriptedHTTPBackupCommitment(ctx, tenant, reader)
				if err == nil && tc.change != nil {
					tc.change(&c)
				}
				return c, err
			}}
			factory.fail = tc.name == "commit-failure"
			before, err := base.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			value, err := commands.GenerateBackupManifest(t.Context(), owner.actor)
			if err == nil || tc.want != nil && !errors.Is(err, tc.want) || reads != 1 || !reflect.DeepEqual(value, verificationdomain.BackupManifest{}) {
				t.Fatal("invalid/failed generation exposed a manifest", err)
			}
			after, err := base.Snapshot()
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("invalid commitment or final commit failure published partial effects", err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if value, err := commands.GenerateBackupManifest(ctx, owner.actor); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(value, verificationdomain.BackupManifest{}) || reads != 1 {
				t.Fatal("cancelled generation consulted commitment or returned data", err)
			}
		})
	}
}

func TestHTTPBackupFixtureDoesNotCallAggregateGenerator(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "verification_command_fixture_ports_test.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "GenerateBackupManifest" {
			return true
		}
		if _, aggregate := selector.X.(*ast.CallExpr); aggregate {
			t.Error("HTTP backup fixture still calls the aggregate generator")
		}
		return true
	})
}
