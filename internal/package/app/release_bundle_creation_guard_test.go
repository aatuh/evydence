package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
)

type bundleGuardUnusedReader struct{ ReleaseBundleSnapshotReader }
type bundleGuardUnusedSigner struct{ PackageSigner }
type bundleGuardUnusedHasher struct{ ManifestHasher }
type bundleGuardTestTransactions struct {
	state *packageTestState
	locks int
	err   error
}
type bundleGuardTestTx struct {
	serviceReleaseBundleTransaction
	owner *bundleGuardTestTransactions
}

func (x bundleGuardTestTx) LockReleaseBundleCreationScope(_ context.Context, tenant, id string) (string, error) {
	x.owner.locks++
	if tenant != "ten_1" || id != "rel_1" {
		return "", ErrNotFound
	}
	return "prod_1", x.owner.err
}
func (x *bundleGuardTestTransactions) ExecuteReleaseBundle(ctx context.Context, fn func(context.Context, ReleaseBundleTransaction) error) error {
	return x.state.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		return fn(ctx, bundleGuardTestTx{serviceReleaseBundleTransaction{tx.Packages(), tx.Signatures(), tx.Authorization(), tx.Audit(), tx.Outbox()}, x})
	})
}
func TestReleaseBundleCreationGuardIsReadOnlyAndNormalizesBeforeStorage(t *testing.T) {
	state := newPackageTestState()
	local := newPackageTestService(t, state)
	tx := &bundleGuardTestTransactions{state: state}
	c, err := NewReleaseBundleCommands(ReleaseBundleCommandConfig{Reader: bundleGuardUnusedReader{}, Signer: bundleGuardUnusedSigner{}, Hasher: bundleGuardUnusedHasher{}, Transactions: tx, Authorizer: local.authorizer, Clock: application.ClockFunc(func() time.Time { t.Fatal("guard consulted clock"); return time.Time{} }), IDs: application.IDGeneratorFunc(func(string) string { t.Fatal("guard allocated ID"); return "" })})
	if err != nil {
		t.Fatal(err)
	}
	state.authorize = func(r application.AuthorizationRequest) error {
		if r.Scope != "bundle:write" || r.TenantWide || !r.ScopeOnly && r.Resources != (application.ResourceReferences{ProductID: "prod_1", ReleaseID: "rel_1"}) {
			t.Fatal("unexpected bundle scope", r)
		}
		return nil
	}
	if err := c.AuthorizeReleaseBundleCreation(t.Context(), packageTestActor(), " rel_1 "); err != nil || tx.locks != 1 || len(state.audit)+len(state.outbox)+len(state.releaseBundles)+len(state.signatures) != 0 {
		t.Fatal("guard effects", err)
	}
	for _, bad := range []string{"", " ", "bad\x00", string([]byte{255}), strings.Repeat(" ", 1024) + "rel_1"} {
		before := tx.locks
		if err := c.AuthorizeReleaseBundleCreation(t.Context(), packageTestActor(), bad); !errors.Is(err, ErrValidation) || tx.locks != before {
			t.Fatal("malformed release reached storage", err)
		}
	}
	for _, badTenant := range []string{" ten_1 ", "bad\x00", strings.Repeat("t", 1025)} {
		a := packageTestActor()
		a.TenantID = badTenant
		before := tx.locks
		if err := c.AuthorizeReleaseBundleCreation(t.Context(), a, "rel_1"); !errors.Is(err, ErrValidation) || tx.locks != before {
			t.Fatal("invalid tenant coordinate reached bundle storage", err)
		}
	}
	tx.err = ErrNotFound
	if err := c.AuthorizeReleaseBundleCreation(t.Context(), packageTestActor(), "rel_1"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	tx.err = nil
	state.authorize = func(application.AuthorizationRequest) error { return application.ErrForbidden }
	before := tx.locks
	if err := c.AuthorizeReleaseBundleCreation(t.Context(), packageTestActor(), "rel_1"); !errors.Is(err, application.ErrForbidden) || tx.locks != before {
		t.Fatal("denied scope reached storage", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := c.AuthorizeReleaseBundleCreation(ctx, packageTestActor(), "rel_1"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
