package repositories_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	postgresrepositories "github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func TestCustomerPackageLockedReadScopesAndBoundsManifest(t *testing.T) {
	ctx, pool := openRepositoryTestPool(t)
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	exec(`INSERT INTO tenants(id,name)VALUES('ten_package','Package'),('ten_foreign','Foreign')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug)VALUES('prod_package','ten_package','Package','package')`)
	exec(`INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('rel_package','ten_package','prod_package','1','draft')`)
	exec(`INSERT INTO redaction_profiles(id,tenant_id,name,allowed_types,excluded_fields,schema_version,created_at)VALUES('rp_package','ten_package','Review',ARRAY['sbom'],'{}','redaction.v1',$1)`, now)
	exec(`INSERT INTO customer_security_packages(id,tenant_id,product_id,release_id,redaction_profile_id,title,state,manifest,manifest_hash,expires_at,schema_version,created_at)VALUES('csp_package','ten_package','prod_package','rel_package','rp_package','Review','generated','{"evidence_ids":["ev_1"]}','sha256:fixture',$1,'package.v1',$2)`, now.Add(time.Hour), now)
	repository := postgresrepositories.New(tx).Packages
	for _, input := range []struct{ tenant, id string }{
		{"ten_package", "bad\x00"}, {"bad\x00", "csp_package"},
		{"ten_package", string([]byte{0xff})}, {"ten_package", strings.Repeat("x", 1025)},
		{strings.Repeat("x", 1025), "csp_package"},
	} {
		if result, err := repository.GetCustomerSecurityPackageForUpdate(ctx, input.tenant, input.id); !errors.Is(err, app.ErrValidation) || result.ID != "" {
			t.Fatal("invalid raw coordinates reached SQL", err)
		}
	}
	pkg, err := repository.GetCustomerSecurityPackageForUpdate(ctx, "ten_package", "csp_package")
	if err != nil || pkg.ID != "csp_package" || pkg.ReleaseID != "rel_package" || pkg.Manifest["evidence_ids"] == nil {
		t.Fatalf("pkg=%#v err=%v", pkg, err)
	}
	if _, err := repository.GetCustomerSecurityPackageForUpdate(ctx, "ten_foreign", "csp_package"); !errors.Is(err, app.ErrNotFound) {
		t.Fatal(err)
	}
	exec(`UPDATE customer_security_packages SET manifest='[]' WHERE id='csp_package'`)
	if _, err := repository.GetCustomerSecurityPackageForUpdate(ctx, "ten_package", "csp_package"); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("malformed manifest err=%v", err)
	}
	exec(`UPDATE customer_security_packages SET manifest=jsonb_build_object('title',$1::text) WHERE id='csp_package'`, strings.Repeat("x", packageapp.MaxCustomerPackageManifestBytes+1))
	if result, err := repository.GetCustomerSecurityPackageForUpdate(ctx, "ten_package", "csp_package"); !errors.Is(err, app.ErrConflict) || result.ID != "" {
		t.Fatalf("oversized pkg=%#v err=%v", result, err)
	}
}
