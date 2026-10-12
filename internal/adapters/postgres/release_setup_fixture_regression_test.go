package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

func TestPostgresReleaseSetupFixtureSelectsTypedAuthorizationDelegate(t *testing.T) {
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
	f := postgresReleaseSetup(factory)
	actor.Scopes = []string{releaseapp.ScopeEvidenceWrite}
	for _, tc := range []struct {
		name    string
		request application.AuthorizationRequest
		allowed bool
	}{
		{"artifact action", application.AuthorizationRequest{Action: authz.ActionArtifactsWrite, ScopeOnly: true}, true},
		{"catalog action with unrelated capability", application.AuthorizationRequest{Action: authz.ActionProductsCreate, ScopeOnly: true}, false},
		{"legacy scope without action", application.AuthorizationRequest{Scope: releaseapp.ScopeEvidenceWrite, ScopeOnly: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := f.Authorize(t.Context(), actor, tc.request)
			if tc.allowed && err != nil || !tc.allowed && !errors.Is(err, application.ErrForbidden) {
				t.Fatal("fixture selected the wrong typed delegate", err)
			}
		})
	}
}

// This proves the outer fixture's transaction composition with the real memory
// test backend, not PostgreSQL locks, durability or backup/restore behavior.
func TestPostgresReleaseSetupFixtureUsesCurrentRowsAndCallerReplayTransaction(t *testing.T) {
	base := app.NewMemoryUnitOfWorkFactory()
	executor := app.IdempotencyUnitOfWork{Transactions: base}
	identity := postgresIdentitySetup(base, "fixture")
	_, _, secret, err := identity.BootstrapTenant(t.Context(), "Owner", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := identity.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	f := postgresReleaseSetup(base)
	product, err := f.CreateProduct(t.Context(), actor, "Original", "original")
	if err != nil || product.ID == "" {
		t.Fatal("cold product setup failed", err)
	}
	release, err := f.CreateRelease(t.Context(), actor, product.ID, "1")
	if err != nil || release.ProductID != product.ID || release.State != "draft" || release.Revision != 1 {
		t.Fatal("release setup used stale catalog parents", err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	artifact, err := f.RegisterArtifact(t.Context(), actor, "Original", "application/octet-stream", digest, 9007199254740993)
	if err != nil || artifact.Size != 9007199254740993 {
		t.Fatal("artifact setup lost exact integer size", err)
	}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := f.RegisterArtifact(t.Context(), actor, "Replacement", "changed", digest, 1)
	if err != nil || !reflect.DeepEqual(duplicate, artifact) {
		t.Fatal("artifact setup changed immutable natural-key identity", err)
	}
	denied := actor
	denied.KeyID, denied.UserID = "", "human"
	denied.ResourceGrants = nil
	if v, err := f.RegisterArtifact(t.Context(), denied, "Denied", "changed", digest, 1); !errors.Is(err, application.ErrForbidden) || v != (domain.Artifact{}) {
		t.Fatal("denied duplicate exposed private metadata or returned the wrong error", err)
	}
	reused, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, reused) {
		t.Fatal("duplicate or denied setup wrote effects", err)
	}
	want := errors.New("fixture outer transaction rollback")
	_, _, err = executor.WithBody(t.Context(), actor, "POST", "/v1/products", "fixture-rollback", []byte(`{"name":"Pending","slug":"pending"}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		commands := postgresReleaseSetup(base)
		pending, err := commands.CreateProduct(ctx, actor, "Pending", "pending")
		if err != nil {
			return 0, nil, err
		}
		if _, err := commands.CreateRelease(ctx, actor, pending.ID, "1"); err != nil {
			return 0, nil, err
		}
		return 500, nil, want
	})
	if !errors.Is(err, want) {
		t.Fatal("fixture failed to join caller's active transaction", err)
	}
	after, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Idempotency) != len(before.Idempotency)+1 {
		t.Fatal("failed caller replay state was not recorded")
	}
	for _, record := range after.Idempotency {
		if record.State != "failed" {
			t.Fatal("failed compound transaction retained successful replay state")
		}
	}
	// Failed replay status is intentional; all catalog/audit effects must roll back.
	after.Idempotency = before.Idempotency
	if !reflect.DeepEqual(before, after) {
		t.Fatal("nested setup escaped the caller's transaction rollback")
	}
}

func TestPostgresNativeReplayFixtureCommitsCurrentRowsAndDiscardsFinalCommitFailure(t *testing.T) {
	base := app.NewMemoryUnitOfWorkFactory()
	factory := &identityFixtureCommitFailureFactory{UnitOfWorkFactory: base}
	identity := postgresIdentitySetup(factory, "fixture-pepper")
	_, _, secret, err := identity.BootstrapTenant(t.Context(), "Owner", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := identity.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	_, _, foreignSecret, err := identity.BootstrapTenant(t.Context(), "Foreign", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := identity.Authenticate(t.Context(), foreignSecret)
	if err != nil {
		t.Fatal(err)
	}
	setup := postgresReleaseSetup(factory)
	executor := app.IdempotencyUnitOfWork{Transactions: factory}
	runs := 0
	run := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		runs++
		product, err := setup.CreateProduct(ctx, actor, "Native replay", "native-replay")
		if err != nil {
			return 0, nil, err
		}
		if _, err := setup.CreateRelease(ctx, actor, product.ID, "1"); err != nil {
			return 0, nil, err
		}
		return 201, product, nil
	}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	commits := factory.commits
	status, first, err := executor.WithBody(t.Context(), actor, "POST", "/v1/products", "native-compound", []byte(`{"name":"Native replay"}`), run)
	if err != nil || status != 201 || runs != 1 || factory.commits != commits+1 {
		t.Fatal("compound native setup did not join one caller transaction", err)
	}
	productID := postgresIdempotencyResponseID(t, first)
	after, err := base.Snapshot()
	if err != nil || len(after.Products) != len(before.Products)+1 || len(after.Releases) != len(before.Releases)+1 || len(after.AuditEntries[actor.TenantID]) != len(before.AuditEntries[actor.TenantID])+2 || len(after.Idempotency) != len(before.Idempotency)+1 {
		t.Fatal("compound native setup did not atomically commit product/release/audit/replay rows", err)
	}
	status, replay, err := executor.WithBody(t.Context(), actor, "POST", "/v1/products", "native-compound", []byte(`{"name":"Native replay"}`), run)
	if err != nil || status != 201 || runs != 1 || postgresIdempotencyResponseID(t, replay) != productID {
		t.Fatal("matching native delivery did not replay the original result", err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	replayJSON, err := json.Marshal(replay)
	if err != nil {
		t.Fatal(err)
	}
	var left, right any
	leftDecoder, rightDecoder := json.NewDecoder(strings.NewReader(string(firstJSON))), json.NewDecoder(strings.NewReader(string(replayJSON)))
	leftDecoder.UseNumber()
	rightDecoder.UseNumber()
	if leftDecoder.Decode(&left) != nil || rightDecoder.Decode(&right) != nil || !reflect.DeepEqual(left, right) {
		t.Fatal("native replay changed a stored response field")
	}
	if value, err := setup.CreateRelease(t.Context(), foreign, productID, "foreign"); !errors.Is(err, releaseapp.ErrNotFound) || value != (domain.Release{}) {
		t.Fatal("native release setup exposed another tenant's product", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if status, response, err := executor.WithBody(ctx, actor, "POST", "/v1/products", "cancelled", []byte(`{}`), run); !errors.Is(err, context.Canceled) || status != 0 || response != nil || runs != 1 {
		t.Fatal("cancelled native replay invoked business work or returned data", err)
	}
	unchanged, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, unchanged) {
		t.Fatal("replay/foreign/cancelled setup changed current rows", err)
	}
	factory.fail = true
	commits = factory.commits
	status, response, err := executor.WithBody(t.Context(), actor, "POST", "/v1/products", "commit-failure", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		product, err := setup.CreateProduct(ctx, actor, "Pending", "pending")
		if err != nil {
			return 0, nil, err
		}
		if _, err := setup.CreateRelease(ctx, actor, product.ID, "1"); err != nil {
			return 0, nil, err
		}
		return 201, product, nil
	})
	if err == nil || status != 0 || response != nil || factory.commits != commits+1 {
		t.Fatal("final native commit failure returned a partial response or was not reached", err)
	}
	unchanged, err = base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, unchanged) {
		t.Fatal("failed final commit published product, release, audit or replay effects", err)
	}
}
