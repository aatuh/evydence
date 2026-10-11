package postgres

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestPostgresBackupGenerationFixtureUsesOwnTypedPolicy(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	identity := postgresIdentitySetup(factory, "fixture")
	_, _, secret, err := identity.BootstrapTenant(t.Context(), "Owner", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := identity.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	actor.Scopes = []string{"admin"}
	uow, err := factory.BeginUnitOfWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = uow.Rollback(t.Context()) }()
	guard, ok := uow.Repositories().Identity.(postgresBundleFence)
	if !ok {
		t.Fatal("fixture lacks tenant fence")
	}
	tx := postgresBackupGenerationTransaction{guard: guard}
	for _, tc := range []struct {
		name    string
		request application.AuthorizationRequest
		allowed bool
	}{
		{"backup action", application.AuthorizationRequest{Action: authz.ActionBackupGenerate, TenantWide: true}, true},
		{"retention action with same admin capability", application.AuthorizationRequest{Action: authz.ActionRetentionPoliciesManage, TenantWide: true}, false},
		{"legacy admin scope without action", application.AuthorizationRequest{Scope: "admin", TenantWide: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tx.Authorize(t.Context(), actor, tc.request)
			if tc.allowed && err != nil || !tc.allowed && !errors.Is(err, application.ErrForbidden) {
				t.Fatal("fixture accepted an unrelated or untyped backup policy", err)
			}
		})
	}
}

func TestPostgresBackupGenerationFixtureRejectsIncompleteMemoryCommitmentWithoutEffects(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	identity := postgresIdentitySetup(factory, "fixture-pepper")
	_, _, secret, err := identity.BootstrapTenant(t.Context(), "Owner", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := identity.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	commands, err := newBackupGenerationFixture(factory)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := generateBackupManifestFixture(t.Context(), factory, actor); !errors.Is(err, verificationapp.ErrValidation) || !reflect.DeepEqual(v, domain.BackupManifest{}) {
		t.Fatal("incomplete memory backend produced a v2 commitment or partial result", err)
	}
	if err := commands.AuthorizeBackupGeneration(t.Context(), actor); !errors.Is(err, verificationapp.ErrValidation) {
		t.Fatal("missing complete commitment capability was silently accepted", err)
	}
	denied := actor
	denied.Scopes = []string{"verify:read"}
	if v, err := generateBackupManifestFixture(t.Context(), factory, denied); !errors.Is(err, verificationapp.ErrForbidden) || !reflect.DeepEqual(v, domain.BackupManifest{}) {
		t.Fatal("non-admin fixture returned a manifest", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := generateBackupManifestFixture(ctx, factory, actor); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, domain.BackupManifest{}) {
		t.Fatal("cancelled fixture produced metadata", err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("incomplete/denied/cancelled backup fixture wrote state", err)
	}
}

func TestPostgresRecoveryFixturesDoNotGenerateBackupsThroughLedger(t *testing.T) {
	for _, path := range []string{"paired_backup_restore_test.go", "store_test.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
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
			if receiver, ok := selector.X.(*ast.Ident); ok && receiver.Name == "ledger" {
				t.Errorf("%s still uses the aggregate backup generator", path)
			}
			return true
		})
	}
}
