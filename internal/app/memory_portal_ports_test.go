package app

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

type memoryPortalPorts interface {
	packageapp.PortalAccessWriteReader
	packageapp.PortalAccessLookup
	packagequery.PortalAccessReader
	ReadPortalAccessForToken(context.Context, string, string) (packagedomain.CustomerPortalAccess, error)
	InsertFocusedPortalAccess(context.Context, packagedomain.CustomerPortalAccess) error
	RevokeFocusedPortalAccess(context.Context, string, string, time.Time) error
	UpdateFocusedPortalTokenAccess(context.Context, packagedomain.CustomerPortalAccess, packagedomain.CustomerPortalAccess) error
}

func memoryPortalReadFixture(t *testing.T) (*memoryUnitOfWork, memoryPortalPorts) {
	t.Helper()
	_, tx := memoryMembershipReadFixture(t)
	for _, tenant := range []string{"tenant", "foreign"} {
		at := fixedNow()
		v := domain.CustomerPortalAccess{ID: tenant + "-access", TenantID: tenant, PackageID: tenant + "-package", CustomerName: "Customer", ReviewerName: "Reviewer", ReviewerEmail: "reviewer@example.test", RequireNDA: true, Watermark: "Review copy", Prefix: "evycp_abcdef", Hash: strings.Repeat("a", 64), ExpiresAt: at.Add(time.Hour), CreatedAt: at, SchemaVersion: packagedomain.CustomerPortalAccessVersion}
		tx.state.CustomerPortalAccess[v.ID] = v
	}
	r, ok := tx.Repositories().Identity.(memoryPortalPorts)
	if !ok {
		t.Fatal("memory identity lacks focused portal ports")
	}
	return tx, r
}

func TestMemoryPortalPortsKeepOwnedDetachedPublicAndCredentialReads(t *testing.T) {
	tx, r := memoryPortalReadFixture(t)
	// Ambiguous global prefixes must not choose an arbitrary tenant credential.
	if _, err := r.LookupPortalAccess(t.Context(), "evycp_abcdef"); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("ambiguous prefix selected a tenant", err)
	}
	foreign := tx.state.CustomerPortalAccess["foreign-access"]
	foreign.Prefix = "evycp_foreig"
	foreign.Hash = strings.Repeat("x", 9437184) // Unrelated data is not a bound on this read.
	tx.state.CustomerPortalAccess[foreign.ID] = foreign
	at := fixedNow()
	owned := tx.state.CustomerPortalAccess["tenant-access"]
	owned.NDAAcceptedAt, owned.RevokedAt, owned.LastAccessedAt, owned.LastFailedAt = &at, &at, &at, &at
	owned.NDAAcceptedBy = "Reviewer"
	owned.AccessCount, owned.FailedAccessCount = 2, 1
	tx.state.CustomerPortalAccess[owned.ID] = owned
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := r.ReadPortalPackageScope(t.Context(), "tenant", "tenant-package")
	if err != nil || scope.TenantID != "tenant" || scope.PackageID != "tenant-package" || scope.Resources.ProductID != "tenant-product" || scope.Resources.ReleaseID != "tenant-release" || scope.Resources.CustomerPackageID != "tenant-package" {
		t.Fatal("portal scope lost current parents", scope, err)
	}
	candidate, err := r.LookupPortalAccess(t.Context(), owned.Prefix)
	if err != nil || candidate != (packageapp.PortalAccessCandidate{TenantID: "tenant", AccessID: owned.ID}) {
		t.Fatal("bounded prefix coordinates changed", candidate, err)
	}
	public, err := r.ReadPortalAccessForRevocation(t.Context(), "tenant", owned.ID)
	want := owned
	want.Hash = ""
	if err != nil || !reflect.DeepEqual(domain.CustomerPortalAccess(public), want) {
		t.Fatal("public portal reader lost metadata or exposed hash", err)
	}
	credential, err := r.ReadPortalAccessForToken(t.Context(), "tenant", owned.ID)
	if err != nil || !reflect.DeepEqual(domain.CustomerPortalAccess(credential), owned) {
		t.Fatal("credential reader lost exact owned record", err)
	}
	*public.NDAAcceptedAt = at.Add(time.Hour)
	*public.RevokedAt = at.Add(time.Hour)
	*credential.LastAccessedAt = at.Add(time.Hour)
	*credential.LastFailedAt = at.Add(time.Hour)
	for _, read := range []func(context.Context, string, string) (packagedomain.CustomerPortalAccess, error){r.ReadPortalAccessForRevocation, r.ReadPortalAccessForToken} {
		if _, err := read(t.Context(), "tenant", foreign.ID); !errors.Is(err, ErrNotFound) {
			t.Fatal("portal reader crossed tenant", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := read(ctx, "tenant", owned.ID); !errors.Is(err, context.Canceled) {
			t.Fatal("portal read ignored cancellation", err)
		}
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("portal reads share timestamps or mutate repository state")
	}
	owned.Hash = strings.Repeat("x", 65)
	tx.state.CustomerPortalAccess[owned.ID] = owned
	if _, err := r.ReadPortalAccessForRevocation(t.Context(), "tenant", owned.ID); err != nil {
		t.Fatal("administrative metadata depended on token hash", err)
	}
	if _, err := r.ReadPortalAccessForToken(t.Context(), "tenant", owned.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("oversized selected credential was retained", err)
	}
	owned.CustomerName = strings.Repeat("x", 641)
	tx.state.CustomerPortalAccess[owned.ID] = owned
	if _, err := r.ReadPortalAccessForRevocation(t.Context(), "tenant", owned.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("oversized selected metadata was retained", err)
	}
	if _, err := r.ReadPortalPackageScope(t.Context(), "tenant", "foreign-package"); !errors.Is(err, ErrNotFound) {
		t.Fatal("portal scope crossed tenant", err)
	}
	release := tx.state.Releases["tenant-release"]
	release.ProductID = "foreign-product"
	tx.state.Releases[release.ID] = release
	if _, err := r.ReadPortalPackageScope(t.Context(), "tenant", "tenant-package"); !errors.Is(err, ErrNotFound) {
		t.Fatal("portal scope trusted inconsistent parents", err)
	}
}

func TestMemoryPortalPortsPreserveMonotonicLifecycleAndRollback(t *testing.T) {
	tx, r := memoryPortalReadFixture(t)
	v := packagedomain.CustomerPortalAccess(tx.state.CustomerPortalAccess["tenant-access"])
	v.ID = "created"
	if err := r.InsertFocusedPortalAccess(t.Context(), v); err != nil {
		t.Fatal("valid owned portal credential was not inserted", err)
	}
	if err := r.InsertFocusedPortalAccess(t.Context(), v); !errors.Is(err, ErrConflict) {
		t.Fatal("duplicate portal credential was not rejected", err)
	}
	updated := packageapp.ClonePortalAccess(v)
	now := fixedNow().Add(time.Minute)
	updated.AccessCount, updated.NDAAcceptedAt, updated.LastAccessedAt, updated.NDAAcceptedBy = 1, &now, &now, "Reviewer"
	if err := r.UpdateFocusedPortalTokenAccess(t.Context(), v, updated); err != nil || !reflect.DeepEqual(tx.state.CustomerPortalAccess[v.ID], domain.CustomerPortalAccess(updated)) {
		t.Fatal("NDA/access lifecycle update changed", err)
	}
	if err := r.UpdateFocusedPortalTokenAccess(t.Context(), v, updated); !errors.Is(err, ErrConflict) {
		t.Fatal("stale lifecycle update overwrote current state", err)
	}
	bad := packageapp.ClonePortalAccess(updated)
	bad.CustomerName = "Changed recipient"
	bad.AccessCount++
	if err := r.UpdateFocusedPortalTokenAccess(t.Context(), updated, bad); !errors.Is(err, packageapp.ErrValidation) {
		t.Fatal("lifecycle update changed immutable recipient", err)
	}
	if err := r.RevokeFocusedPortalAccess(t.Context(), "foreign", v.ID, now); !errors.Is(err, ErrNotFound) {
		t.Fatal("revocation crossed tenant", err)
	}
	if err := r.RevokeFocusedPortalAccess(t.Context(), "tenant", v.ID, now); err != nil || tx.state.CustomerPortalAccess[v.ID].RevokedAt == nil {
		t.Fatal("owned revocation did not update lifecycle", err)
	}
	if err := r.RevokeFocusedPortalAccess(t.Context(), "tenant", v.ID, now); !errors.Is(err, ErrConflict) {
		t.Fatal("repeated repository revocation did not conflict", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadPortalAccessForToken(t.Context(), "tenant", v.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("closed portal transaction remained readable", err)
	}
}

func TestMemoryPortalPagesFilterCurrentParentsAndNeverExposeHashes(t *testing.T) {
	tx, r := memoryPortalReadFixture(t)
	for i := 0; i < 3; i++ {
		v := tx.state.CustomerPortalAccess["tenant-access"]
		v.ID = "access-" + strconv.Itoa(i)
		tx.state.CustomerPortalAccess[v.ID] = v
	}
	request := packagequery.PortalAccessPageRequest{TenantID: "tenant", AllowedProductIDs: []string{"tenant-product"}, Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}}
	seen := map[string]bool{}
	for {
		page, err := r.PagePortalAccess(t.Context(), request)
		if err != nil || len(page.Items) != 1 || page.Items[0].Access.Hash != "" || page.Items[0].Access.TenantID != "tenant" || seen[page.Items[0].Access.ID] {
			t.Fatal("portal page leaked, repeated or dropped owned data", err)
		}
		seen[page.Items[0].Access.ID] = true
		if page.Next == nil {
			break
		}
		request.After = page.Next
	}
	if len(seen) != 4 {
		t.Fatal("portal pages truncated owned records", len(seen))
	}
	request.After, request.PackageID = nil, "foreign-package"
	if _, err := r.PagePortalAccess(t.Context(), request); !errors.Is(err, packagequery.ErrPortalAccessNotFound) {
		t.Fatal("foreign package filter revealed access", err)
	}
	request.PackageID, request.AllowedProductIDs = "tenant-package", []string{"foreign-product"}
	if _, err := r.PagePortalAccess(t.Context(), request); !errors.Is(err, ErrForbidden) {
		t.Fatal("foreign grant authorized selected package", err)
	}
}
