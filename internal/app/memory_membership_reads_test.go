package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func memoryMembershipReadFixture(t *testing.T) (*MemoryUnitOfWorkFactory, *memoryUnitOfWork) {
	t.Helper()
	factory := NewMemoryUnitOfWorkFactory()
	unit, err := factory.BeginUnitOfWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	tx := unit.(*memoryUnitOfWork)
	for _, tenant := range []string{"tenant", "foreign"} {
		tx.state.Tenants[tenant] = domain.Tenant{ID: tenant, Name: tenant, CreatedAt: fixedNow()}
		tx.state.Organizations[tenant+"-org"] = domain.Organization{ID: tenant + "-org", TenantID: tenant, Slug: "Example"}
		at := fixedNow()
		tx.state.Users[tenant+"-user"] = domain.HumanUser{ID: tenant + "-user", TenantID: tenant, OrganizationID: tenant + "-org", Email: "private@example.test", DisplayName: "Private", Status: "deactivated", CreatedAt: at, DeactivatedAt: &at, SchemaVersion: domain.HumanUserSchemaVersion}
		tx.state.APIKeys[tenant+"-key"] = domain.APIKey{ID: tenant + "-key", TenantID: tenant, Hash: "private-credential-hash"}
		tx.state.Collectors[tenant+"-collector"] = domain.Collector{ID: tenant + "-collector", TenantID: tenant, APIKeyID: tenant + "-key"}
		tx.state.Products[tenant+"-product"] = domain.Product{ID: tenant + "-product", TenantID: tenant}
		tx.state.Projects[tenant+"-project"] = domain.Project{ID: tenant + "-project", TenantID: tenant, ProductID: tenant + "-product"}
		tx.state.Releases[tenant+"-release"] = domain.Release{ID: tenant + "-release", TenantID: tenant, ProductID: tenant + "-product"}
		tx.state.CustomerPackages[tenant+"-package"] = domain.CustomerSecurityPackage{ID: tenant + "-package", TenantID: tenant, ProductID: tenant + "-product", ReleaseID: tenant + "-release"}
		tx.state.EvidenceBundles[tenant+"-bundle"] = domain.EvidenceBundle{ID: tenant + "-bundle", TenantID: tenant, ReleaseID: tenant + "-release"}
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	unit, err = factory.BeginUnitOfWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	tx = unit.(*memoryUnitOfWork)
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	return factory, tx
}

func TestMemoryMembershipReadersPreserveOwnedDetachedPublicRecords(t *testing.T) {
	factory, tx := memoryMembershipReadFixture(t)
	reader, ok := tx.Repositories().Identity.(identityapp.MembershipWriteReader)
	if !ok {
		t.Fatal("memory identity lacks focused membership reads")
	}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	foreignOrg := tx.state.Organizations["foreign-org"]
	foreignOrg.Slug = "foreign-only"
	tx.state.Organizations[foreignOrg.ID] = foreignOrg
	foreignUser := tx.state.Users["foreign-user"]
	foreignUser.Email = "foreign-only@example.test"
	tx.state.Users[foreignUser.ID] = foreignUser
	// The foreign-only identity must not conflict with this tenant's creates.
	if found, err := reader.OrganizationSlugExists(t.Context(), "tenant", foreignOrg.Slug); err != nil || found {
		t.Fatal("organization identity existence crossed tenant boundary", found, err)
	}
	if found, err := reader.UserEmailExists(t.Context(), "tenant", foreignUser.Email); err != nil || found {
		t.Fatal("user identity existence crossed tenant boundary", found, err)
	}
	// Restore before taking the full read-purity comparison.
	tx.state.Organizations[foreignOrg.ID] = before.Organizations[foreignOrg.ID]
	tx.state.Users[foreignUser.ID] = before.Users[foreignUser.ID]
	if err := reader.LockMembershipWrites(t.Context(), "tenant"); err != nil {
		t.Fatal(err)
	}
	org, err := reader.ReadMembershipOrganization(t.Context(), "tenant", "tenant-org")
	if err != nil || org != (identityapp.MembershipOrganization{ID: "tenant-org", TenantID: "tenant"}) {
		t.Fatal("organization ownership projection changed", org, err)
	}
	user, err := reader.ReadMembershipUser(t.Context(), "tenant", "tenant-user")
	if err != nil || !reflect.DeepEqual(user, identitydomain.HumanUser(tx.state.Users["tenant-user"])) {
		t.Fatal("public user lifecycle fields changed", user, err)
	}
	*user.DeactivatedAt = user.DeactivatedAt.AddDate(1, 0, 0)
	for _, query := range []struct {
		kind, value string
		want        bool
	}{{"slug", "Example", true}, {"slug", "example", false}, {"email", "private@example.test", true}, {"email", "missing@example.test", false}} {
		var got bool
		if query.kind == "slug" {
			got, err = reader.OrganizationSlugExists(t.Context(), "tenant", query.value)
		} else {
			got, err = reader.UserEmailExists(t.Context(), "tenant", query.value)
		}
		if err != nil || got != query.want {
			t.Fatal("tenant identity existence changed", query.kind, query.value, got, err)
		}
	}
	for _, id := range []string{"missing", "foreign-user"} {
		if _, err := reader.ReadMembershipUser(t.Context(), "tenant", id); !errors.Is(err, ErrNotFound) {
			t.Fatal("membership reader accepted foreign/missing user", id, err)
		}
	}
	if _, err := reader.ReadMembershipOrganization(t.Context(), "tenant", "foreign-org"); !errors.Is(err, ErrNotFound) {
		t.Fatal("membership reader accepted foreign organization", err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("membership reads or returned pointer mutation changed transaction state")
	}
	persisted, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, persisted) {
		t.Fatal("membership reads changed authoritative storage", err)
	}
	bad := tx.state.Users["tenant-user"]
	bad.DisplayName = strings.Repeat("x", 65537)
	tx.state.Users[bad.ID] = bad
	if _, err := reader.ReadMembershipUser(t.Context(), "tenant", bad.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("membership reader truncated or accepted oversized historical user", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reader.ReadMembershipUser(ctx, "tenant", "tenant-user"); !errors.Is(err, context.Canceled) {
		t.Fatal("membership read ignored cancellation", err)
	}
	if _, err := reader.ReadMembershipOrganization(t.Context(), " tenant", "tenant-org"); !errors.Is(err, ErrValidation) {
		t.Fatal("membership read accepted noncanonical tenant", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := reader.LockMembershipWrites(t.Context(), "tenant"); !errors.Is(err, ErrConflict) {
		t.Fatal("membership reader retained a closed transaction", err)
	}
}

func TestMemoryRoleTargetsVerifyCurrentParentOwnershipWithoutPrivateMetadata(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	reader, ok := tx.Repositories().Identity.(identityapp.RoleBindingWriteReader)
	if !ok {
		t.Fatal("memory identity lacks focused role-target reads")
	}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.LockRoleBindingWrites(t.Context(), "tenant"); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"user", "collector"} {
		if err := reader.ValidateSubject(t.Context(), "tenant", kind, "tenant-"+kind); err != nil {
			t.Fatal(kind, err)
		}
		if err := reader.ValidateSubject(t.Context(), "tenant", kind, "foreign-"+kind); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign subject accepted", kind, err)
		}
	}
	for kind, suffix := range map[string]string{"product": "product", "project": "project", "release": "release", "customer_security_package": "package", "evidence_bundle": "bundle"} {
		if err := reader.ValidateResource(t.Context(), "tenant", kind, "tenant-"+suffix); err != nil {
			t.Fatal(kind, err)
		}
		if err := reader.ValidateResource(t.Context(), "tenant", kind, "foreign-"+suffix); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign target accepted", kind, err)
		}
	}
	for _, kind := range []string{"", "tenant"} {
		if err := reader.ValidateResource(t.Context(), "tenant", kind, ""); err != nil {
			t.Fatal("tenant-wide compatibility lost", kind, err)
		}
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("role reads mutated state")
	}
	user := tx.state.Users["tenant-user"]
	user.DisplayName = strings.Repeat("private", 10000)
	tx.state.Users[user.ID] = user
	if err := reader.ValidateSubject(t.Context(), "tenant", "user", user.ID); err != nil {
		t.Fatal("role guard read irrelevant user text", err)
	}
	user.OrganizationID = "foreign-org"
	tx.state.Users[user.ID] = user
	if err := reader.ValidateSubject(t.Context(), "tenant", "user", user.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign user parent accepted", err)
	}
	collector := tx.state.Collectors["tenant-collector"]
	collector.APIKeyID = "foreign-key"
	tx.state.Collectors[collector.ID] = collector
	if err := reader.ValidateSubject(t.Context(), "tenant", "collector", collector.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign collector credential parent accepted", err)
	}
	project := tx.state.Projects["tenant-project"]
	project.ProductID = "foreign-product"
	tx.state.Projects[project.ID] = project
	if err := reader.ValidateResource(t.Context(), "tenant", "project", project.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign project parent accepted", err)
	}
	pkg := tx.state.CustomerPackages["tenant-package"]
	pkg.ReleaseID = "foreign-release"
	tx.state.CustomerPackages[pkg.ID] = pkg
	if err := reader.ValidateResource(t.Context(), "tenant", "customer_security_package", pkg.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign package parent accepted", err)
	}
	release := tx.state.Releases["tenant-release"]
	release.ProductID = "foreign-product"
	tx.state.Releases[release.ID] = release
	for _, target := range []struct{ kind, id string }{{"release", release.ID}, {"evidence_bundle", "tenant-bundle"}} {
		if err := reader.ValidateResource(t.Context(), "tenant", target.kind, target.id); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign release ancestor accepted", target.kind, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := reader.ValidateResource(ctx, "tenant", "tenant", ""); !errors.Is(err, context.Canceled) {
		t.Fatal("role read ignored cancellation", err)
	}
	if err := reader.ValidateResource(t.Context(), "tenant", "product", ""); !errors.Is(err, ErrNotFound) {
		t.Fatal("blank scoped target accepted", err)
	}
	tx.state.Releases["tenant-other-release"] = domain.Release{ID: "tenant-other-release", TenantID: "tenant", ProductID: "tenant-other-product"}
	tx.state.Products["tenant-other-product"] = domain.Product{ID: "tenant-other-product", TenantID: "tenant"}
	pkg.ReleaseID = "tenant-other-release"
	tx.state.CustomerPackages[pkg.ID] = pkg
	if err := reader.ValidateResource(t.Context(), "tenant", "customer_security_package", pkg.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("package accepted a release from another owned product", err)
	}
	pkg.ReleaseID = ""
	tx.state.CustomerPackages[pkg.ID] = pkg
	if err := reader.ValidateResource(t.Context(), "tenant", "customer_security_package", pkg.ID); err != nil {
		t.Fatal("release-less package ownership compatibility lost", err)
	}
	bundle := tx.state.EvidenceBundles["tenant-bundle"]
	bundle.ReleaseID = ""
	tx.state.EvidenceBundles[bundle.ID] = bundle
	if err := reader.ValidateResource(t.Context(), "tenant", "evidence_bundle", bundle.ID); err != nil {
		t.Fatal("release-less bundle ownership compatibility lost", err)
	}
}
