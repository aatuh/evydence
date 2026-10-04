package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// This immutable fixture stands in for the as-yet-unbound production snapshot
// reader. These tests prove the real write adapter/UOW, not HTTP migration or
// production snapshot completeness.
type customerCreationSnapshotFixture struct {
	view  packageapp.CustomerPackageCreationSnapshot
	reads int
}

func (f *customerCreationSnapshotFixture) ReadCustomerPackageCreationSnapshot(_ context.Context, tenant, product, release, profile string, _ time.Time) (packageapp.CustomerPackageCreationSnapshot, error) {
	f.reads++
	if tenant != f.view.Snapshot.TenantID || product != f.view.Snapshot.ProductID || release != f.view.Snapshot.ReleaseID || profile != f.view.Profile.ID {
		return packageapp.CustomerPackageCreationSnapshot{}, packageapp.ErrNotFound
	}
	return f.view, nil
}
func seedCustomerCreation(t *testing.T, p *pgxpool.Pool) (*customerCreationSnapshotFixture, packageapp.CreateCustomerPackageInput) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := p.Exec(t.Context(), `INSERT INTO tenants(id,name)VALUES('tenant','Tenant'),('other','Other');
INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant','Product','product'),('second-product','tenant','Second','second'),('other-product','other','Other','other');
INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('release','tenant','product','1','draft'),('second-release','tenant','second-product','1','draft'),('other-release','other','other-product','1','draft');`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(t.Context(), `INSERT INTO redaction_profiles(id,tenant_id,name,allowed_types,excluded_fields,schema_version,created_at)VALUES('profile','tenant','Customer',ARRAY['sbom'],ARRAY['internal_notes'],'redaction-profile.v1.0.0',$1),('other-profile','other',repeat('private unrelated',300000),ARRAY['sbom'],'{}','redaction-profile.v1.0.0',$1)`, now); err != nil {
		t.Fatal(err)
	}
	return &customerCreationSnapshotFixture{view: packageapp.CustomerPackageCreationSnapshot{Profile: packagedomain.RedactionProfile{ID: "profile", TenantID: "tenant", Name: "Customer", AllowedTypes: []string{"sbom"}, ExcludedFields: []string{"internal_notes"}, SchemaVersion: packagedomain.RedactionProfileSchemaVersion, CreatedAt: now}, Snapshot: packageapp.PackageSnapshot{SnapshotVersion: packageapp.CustomerPackageSnapshotVersion, TenantID: "tenant", ProductID: "product", ReleaseID: "release", Tenant: map[string]any{"id": "tenant"}, Product: map[string]any{"id": "product"}, Release: map[string]any{"id": "release"}, SBOMs: []map[string]any{{"id": "sbom", "internal_notes": "creation-secret-fixture"}}}}}, packageapp.CreateCustomerPackageInput{ProductID: "product", ReleaseID: "release", RedactionProfileID: "profile", Title: "Review", ExpiresAt: now.Add(time.Hour)}
}
func customerCreationCounts(t *testing.T, p *pgxpool.Pool) [2]int {
	t.Helper()
	var out [2]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM customer_security_packages),(SELECT count(*)FROM audit_chain_entries)`).Scan(&out[0], &out[1]); err != nil {
		t.Fatal(err)
	}
	return out
}
func customerCreationActor() identitydomain.Actor {
	return identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"package:write"}}
}

func TestPostgresCustomerCreationWriteBoundaryAndReplayGuard(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	r, in := seedCustomerCreation(t, p)
	c, err := BuildCustomerPackageCreationCommands(r, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildCustomerPackageCreationCommands(nil, store); err == nil {
		t.Fatal("nil reader accepted")
	}
	if _, err := BuildCustomerPackageCreationCommands(r, nil); err == nil {
		t.Fatal("nil transactions accepted")
	}
	v, err := c.CreateCustomerSecurityPackage(t.Context(), customerCreationActor(), in)
	if err != nil || v.ID == "" || r.reads != 1 || customerCreationCounts(t, p) != [2]int{1, 1} {
		t.Fatal("focused durable command failed", err)
	}
	var storedHash, actor, entryType string
	var manifest []byte
	if err := p.QueryRow(t.Context(), `SELECT c.manifest,c.manifest_hash,a.actor_id,a.entry_type FROM customer_security_packages c JOIN audit_chain_entries a ON a.subject_id=c.id AND a.tenant_id=c.tenant_id WHERE c.id=$1`, v.ID).Scan(&manifest, &storedHash, &actor, &entryType); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(manifest), "creation-secret-fixture") || storedHash != v.ManifestHash || actor != "key" || entryType != "customer_package.generated" {
		t.Fatal("manifest/hash/audit mismatch")
	}
	expectedHash, err := application.NormalizedJSONHash(json.RawMessage(manifest))
	if err != nil || storedHash != expectedHash {
		t.Fatal("native canonical hash differs from stored manifest", err)
	}
	expired := in
	expired.ExpiresAt = time.Now().Add(-time.Hour)
	if err := c.AuthorizeCreateCustomerSecurityPackage(t.Context(), customerCreationActor(), expired); err != nil {
		t.Fatal("expired original cannot replay", err)
	}
	if r.reads != 1 || customerCreationCounts(t, p) != [2]int{1, 1} {
		t.Fatal("replay guard generated effects")
	}
	for _, change := range []func(*packageapp.CreateCustomerPackageInput){
		func(in *packageapp.CreateCustomerPackageInput) { in.ProductID = "other-product" },
		func(in *packageapp.CreateCustomerPackageInput) { in.ReleaseID = "other-release" },
		func(in *packageapp.CreateCustomerPackageInput) { in.ReleaseID = "second-release" },
		func(in *packageapp.CreateCustomerPackageInput) { in.RedactionProfileID = "other-profile" },
		func(in *packageapp.CreateCustomerPackageInput) { in.ReleaseID = "missing" },
	} {
		wrong := in
		change(&wrong)
		if err := c.AuthorizeCreateCustomerSecurityPackage(t.Context(), customerCreationActor(), wrong); !errors.Is(err, packageapp.ErrNotFound) {
			t.Fatal("foreign scope replayed", err)
		}
	}
	human := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"package:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"package:write"}}}}
	if err := c.AuthorizeCreateCustomerSecurityPackage(t.Context(), human, in); err != nil {
		t.Fatal(err)
	}
	human.ResourceGrants = nil
	if err := c.AuthorizeCreateCustomerSecurityPackage(t.Context(), human, in); !errors.Is(err, packageapp.ErrForbidden) {
		t.Fatal("revoked grant replayed", err)
	}
}

func TestPostgresCustomerCreationFencePrecedesRootAndPolicyLocks(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	r, in := seedCustomerCreation(t, p)
	c, err := BuildCustomerPackageCreationCommands(r, store)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	leader, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = leader.Rollback(context.WithoutCancel(ctx)) }()
	if err := coordination.LockWorkerProjection(ctx, leader, "tenant"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.AuthorizeCreateCustomerSecurityPackage(ctx, customerCreationActor(), in) }()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			t.Fatal("creation guard bypassed common fence", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
			var blocked bool
			if err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()AND wait_event='advisory'AND $1=ANY(pg_blocking_pids(pid)))`, leader.Conn().PgConn().PID()).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if !blocked {
				continue
			}
			for _, sql := range []string{`SELECT id FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`, `SELECT id FROM products WHERE id='product'FOR UPDATE NOWAIT`, `SELECT id FROM releases WHERE id='release'FOR UPDATE NOWAIT`, `SELECT id FROM redaction_profiles WHERE id='profile'FOR UPDATE NOWAIT`} {
				if _, err := leader.Exec(ctx, sql); err != nil {
					t.Fatal("root or policy locked before common fence", err)
				}
			}
			if err := leader.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("guard did not resume", ctx.Err())
			}
			if r.reads != 0 || customerCreationCounts(t, p) != [2]int{} {
				t.Fatal("guard generated snapshot/write effects")
			}
			return
		}
	}
}

func TestPostgresCustomerCreationCoordinatesRejectMalformedInputsBeforeSQL(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	_, _ = seedCustomerCreation(t, p)
	for _, value := range []string{"", " ", "bad\x00", string([]byte{0xff}), strings.Repeat("x", 1025)} {
		err := app.ExecuteUnitOfWork(t.Context(), store, func(ctx context.Context, repos app.Repositories) error {
			guard, ok := repos.Packages.(customerPackageCreationRepository)
			if !ok {
				t.Fatal("guard missing")
			}
			for _, coords := range [][3]string{{value, "product", "release"}, {"tenant", value, "release"}} {
				if err := guard.LockCustomerPackageCreationScope(ctx, coords[0], coords[1], coords[2]); !errors.Is(err, app.ErrValidation) {
					t.Fatal("raw scope reached SQL", err)
				}
			}
			if _, err := guard.GetCustomerPackageRedactionProfile(ctx, "tenant", value); !errors.Is(err, app.ErrValidation) {
				t.Fatal("raw policy ID reached SQL", err)
			}
			return nil
		})
		if err != nil {
			t.Fatal("bad input aborted SQL transaction", err)
		}
	}
	// Also prove the native repository boundary without the composition mapper.
	tx, err := p.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	guard := repositories.New(tx).Packages.(customerPackageCreationRepository)
	if err := guard.LockCustomerPackageCreationScope(t.Context(), "tenant", "product", "bad\x00"); !errors.Is(err, app.ErrValidation) {
		t.Fatal(err)
	}
	if customerCreationCounts(t, p) != [2]int{} {
		t.Fatal("validation wrote effects")
	}
}

func TestPostgresCustomerCreationWriteBoundaryRollsBackFailures(t *testing.T) {
	for _, stage := range []string{"insert", "audit", "commit", "changed policy"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			r, in := seedCustomerCreation(t, p)
			c, err := BuildCustomerPackageCreationCommands(r, store)
			if err != nil {
				t.Fatal(err)
			}
			if stage == "changed policy" {
				if _, err := p.Exec(t.Context(), `UPDATE redaction_profiles SET excluded_fields=ARRAY['internal_notes','title']WHERE id='profile'`); err != nil {
					t.Fatal(err)
				}
			} else {
				table := "customer_security_packages"
				if stage == "audit" {
					table = "audit_chain_entries"
				}
				trigger := `CREATE TRIGGER reject_customer_creation BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_customer_creation()`
				if stage == "commit" {
					trigger = `CREATE CONSTRAINT TRIGGER reject_customer_creation AFTER INSERT ON customer_security_packages DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_customer_creation()`
				}
				if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_customer_creation()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private creation SQL error';END$$;`+trigger); err != nil {
					t.Fatal(err)
				}
			}
			v, err := c.CreateCustomerSecurityPackage(t.Context(), customerCreationActor(), in)
			if err == nil || v.ID != "" || customerCreationCounts(t, p) != [2]int{} {
				t.Fatal("failed creation published effects", stage, err)
			}
			if stage == "changed policy" && !errors.Is(err, packageapp.ErrConflict) || stage != "changed policy" && !strings.Contains(err.Error(), "private creation SQL error") {
				t.Fatal("failure did not reach intended boundary", stage, err)
			}
		})
	}
}

func TestPostgresCustomerCreationSelectedProfileBounds(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	r, in := seedCustomerCreation(t, p)
	c, err := BuildCustomerPackageCreationCommands(r, store)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`UPDATE redaction_profiles SET name=repeat('x',65537)WHERE id='profile'`,
		`UPDATE redaction_profiles SET name='Customer',allowed_types=array_fill('sbom'::text,ARRAY[1025])WHERE id='profile'`,
		`UPDATE redaction_profiles SET allowed_types=ARRAY[repeat('x',1025)]WHERE id='profile'`,
		`UPDATE redaction_profiles SET allowed_types=ARRAY[repeat('é',513)]WHERE id='profile'`,
		`UPDATE redaction_profiles SET allowed_types=ARRAY[NULL]::text[]WHERE id='profile'`,
	} {
		if _, err := p.Exec(t.Context(), stmt); err != nil {
			t.Fatal(err)
		}
		if err := c.AuthorizeCreateCustomerSecurityPackage(t.Context(), customerCreationActor(), in); !errors.Is(err, packageapp.ErrConflict) {
			t.Fatal("unsafe profile accepted", err)
		}
	}
	if customerCreationCounts(t, p) != [2]int{} || r.reads != 0 {
		t.Fatal("guard loaded private snapshot or generated effects")
	}
}

type customerCreationCountingFactory struct {
	app.UnitOfWorkFactory
	begins int
}

func (f *customerCreationCountingFactory) BeginUnitOfWork(ctx context.Context) (app.UnitOfWork, error) {
	f.begins++
	if f.begins > 1 {
		return nil, errors.New("unexpected nested customer unit of work")
	}
	return f.UnitOfWorkFactory.BeginUnitOfWork(ctx)
}
func TestPostgresCustomerCreationJoinsDurableUnitOfWork(t *testing.T) {
	for _, commitFails := range []bool{false, true} {
		t.Run(fmt.Sprint(commitFails), func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			r, in := seedCustomerCreation(t, p)
			factory := &customerCreationCountingFactory{UnitOfWorkFactory: store}
			c, err := BuildCustomerPackageCreationCommands(r, factory)
			if err != nil {
				t.Fatal(err)
			}
			executor, err := BuildDurableCommandExecutor(factory)
			if err != nil {
				t.Fatal(err)
			}
			if commitFails {
				if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_joined_creation()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'joined commit failure';END$$;
CREATE CONSTRAINT TRIGGER reject_joined_creation AFTER INSERT ON customer_security_packages DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_joined_creation()`); err != nil {
					t.Fatal(err)
				}
			}
			status, response, err := executor.WithBody(t.Context(), customerCreationActor(), "POST", "/v1/customer-packages", "joined", []byte(`{}`), func(ctx context.Context) error {
				return c.AuthorizeCreateCustomerSecurityPackage(ctx, customerCreationActor(), in)
			}, func(ctx context.Context) (int, any, error) {
				v, err := c.CreateCustomerSecurityPackage(ctx, customerCreationActor(), in)
				if err != nil {
					return 0, nil, err
				}
				var pending [3]int
				if err := p.QueryRow(ctx, `SELECT(SELECT count(*)FROM customer_security_packages),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records)`).Scan(&pending[0], &pending[1], &pending[2]); err != nil {
					return 0, nil, err
				}
				if pending != [3]int{} {
					t.Fatal("uncommitted effects visible outside parent transaction")
				}
				return http.StatusCreated, packageAccessToLegacy(v), nil
			})
			if factory.begins != 1 {
				t.Fatal("creation opened nested transaction", factory.begins)
			}
			var replayRecords int
			if e := p.QueryRow(t.Context(), `SELECT count(*)FROM idempotency_records`).Scan(&replayRecords); e != nil {
				t.Fatal(e)
			}
			if commitFails {
				if err == nil || !strings.Contains(err.Error(), "joined commit failure") || status != 0 || response != nil || customerCreationCounts(t, p) != [2]int{} || replayRecords != 0 {
					t.Fatal("outer commit failure exposed successful package or effects", status, err)
				}
			} else if err != nil || status != http.StatusCreated || response == nil || customerCreationCounts(t, p) != [2]int{1, 1} || replayRecords != 1 {
				t.Fatal("native creation did not join durable unit of work", status, err)
			}
		})
	}
}
