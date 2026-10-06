package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type exportGuardFixture struct {
	ExportTransaction
	locks  []string
	denied bool
}

func (f *exportGuardFixture) ExecuteEvidenceBundleExport(ctx context.Context, fn func(context.Context, ExportTransaction) error) error {
	return fn(ctx, f)
}
func (f *exportGuardFixture) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	if r.Scope != "bundle:read" || f.denied && !r.ScopeOnly {
		return application.ErrForbidden
	}
	return nil
}
func (f *exportGuardFixture) LockEvidenceBundleTenant(context.Context, string) error {
	f.locks = append(f.locks, "tenant")
	return nil
}
func (f *exportGuardFixture) LockEvidenceBundleRelease(context.Context, string, string) (string, error) {
	f.locks = append(f.locks, "release")
	return "product", nil
}
func (f *exportGuardFixture) LockEvidenceBundleEvidence(_ context.Context, _ string, id string) (application.ResourceReferences, error) {
	f.locks = append(f.locks, id)
	if id == "missing" {
		return application.ResourceReferences{}, ErrNotFound
	}
	return application.ResourceReferences{ProductID: "product", ReleaseID: "release"}, nil
}

type exportGuardUnusedReader struct{ EvidenceBundleSnapshotReader }
type exportGuardUnusedSigner struct{ PackageSigner }

func TestEvidenceBundleGuardUsesOnlyBoundedCurrentScopeCoordinates(t *testing.T) {
	f := &exportGuardFixture{}
	s, err := NewExportCommands(ExportCommandConfig{Reader: exportGuardUnusedReader{}, Signer: exportGuardUnusedSigner{}, Transactions: f, Authorizer: f, Hasher: importGuardUnusedHasher{}, Clock: application.ClockFunc(func() time.Time { panic("guard allocated time") }), IDs: application.IDGeneratorFunc(func(string) string { panic("guard allocated ID") })})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AuthorizeEvidenceBundleExport(t.Context(), packageTestActor(), " release ", []string{" b ", "a", "a"}); err != nil || !reflect.DeepEqual(f.locks, []string{"tenant", "release", "a", "b"}) {
		t.Fatal("guard used snapshot/signing/hash or lost normalized locks", err, f.locks)
	}
	f.locks = nil
	if err := s.AuthorizeEvidenceBundleExport(t.Context(), packageTestActor(), "", nil); err != nil || !reflect.DeepEqual(f.locks, []string{"tenant"}) {
		t.Fatal("automatic guard selected evidence", err, f.locks)
	}
	f.denied = true
	if err := s.AuthorizeEvidenceBundleReplay(t.Context(), packageTestActor(), "", []string{"historical"}); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("historical selection bypassed current grants", err)
	}
	f.denied = false
	if err := s.AuthorizeEvidenceBundleReplay(t.Context(), packageTestActor(), "", []string{"missing"}); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing historical selection replayed", err)
	}
	for _, ids := range [][]string{{""}, {"id\x00"}, {strings.Repeat(" ", 1024) + "x"}, make([]string, MaxBundleSnapshotRows+1)} {
		if err := s.AuthorizeEvidenceBundleExport(t.Context(), packageTestActor(), "", ids); !errors.Is(err, ErrValidation) {
			t.Fatal("raw input normalized past its budget", err)
		}
	}
	large := make([]string, 1500)
	for n := range large {
		large[n] = fmt.Sprintf("id_%d", n)
	}
	if err := s.AuthorizeEvidenceBundleReplay(t.Context(), packageTestActor(), "", large); err != nil {
		t.Fatal("server-selected replay was limited by HTTP request array budget", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.AuthorizeEvidenceBundleReplay(ctx, packageTestActor(), "", []string{"historical"}); !errors.Is(err, context.Canceled) {
		t.Fatal("guard ignored cancellation", err)
	}
}
