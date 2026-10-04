package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func wiringTrustRootInput() verificationapp.CreateDSSETrustRootInput {
	return verificationapp.CreateDSSETrustRootInput{Name: "Builder", KeyID: "builder-key", Algorithm: "Ed25519", PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedPredicateTypes: []string{"https://slsa.dev/provenance/v1"}, ExpectedBuilderIDs: []string{"https://ci.example.test/builder"}, RequiredClaims: []string{"external_parameters", "builder_id"}}
}

func TestPostgresTrustConfigurationGuardRequiresCurrentTenantWithoutEffects(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	if _, err := p.Exec(t.Context(), `INSERT INTO tenants(id,name)VALUES('tenant','Tenant')`); err != nil {
		t.Fatal(err)
	}
	c, err := BuildTrustConfigurationCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "missing", KeyID: "key", Scopes: []string{"keys:admin"}}
	if err := c.AuthorizeTrustConfiguration(t.Context(), a); !errors.Is(err, verificationapp.ErrNotFound) {
		t.Fatal("missing tenant authorized replay", err)
	}
	a.TenantID = "tenant"
	if err := c.AuthorizeTrustConfiguration(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM signing_providers)+(SELECT count(*)FROM dsse_trust_roots)+(SELECT count(*)FROM audit_chain_entries)+(SELECT count(*)FROM idempotency_records)`).Scan(&count); err != nil || count != 0 {
		t.Fatal("replay guard generated metadata", count, err)
	}
}

func TestPostgresTrustConfigurationFencePrecedesTenantLock(t *testing.T) {
	for _, stage := range []string{"guard", "provider", "root"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			if _, err := p.Exec(t.Context(), `INSERT INTO tenants(id,name)VALUES('tenant','Tenant')`); err != nil {
				t.Fatal(err)
			}
			c, err := BuildTrustConfigurationCommands(store)
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
			go func() {
				a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"keys:admin"}}
				var err error
				switch stage {
				case "guard":
					err = c.AuthorizeTrustConfiguration(ctx, a)
				case "provider":
					_, err = c.CreateSigningProvider(ctx, a, verificationapp.CreateSigningProviderInput{Name: "KMS", Type: "aws_kms", KeyRef: "key"})
				case "root":
					_, err = c.CreateDSSETrustRoot(ctx, a, wiringTrustRootInput())
				}
				done <- err
			}()
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case err := <-done:
					t.Fatal("trust command bypassed tenant fence", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-ticker.C:
					var blocked bool
					if err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory' AND $1=ANY(pg_blocking_pids(pid)))`, leader.Conn().PgConn().PID()).Scan(&blocked); err != nil {
						t.Fatal(err)
					}
					if !blocked {
						continue
					}
					if _, err := leader.Exec(ctx, `SELECT id FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`); err != nil {
						t.Fatal("tenant lock preceded writer fence", err)
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
						t.Fatal("trust command did not resume", ctx.Err())
					}
					var count int
					if err := p.QueryRow(ctx, `SELECT(SELECT count(*)FROM signing_providers)+(SELECT count(*)FROM dsse_trust_roots)+(SELECT count(*)FROM audit_chain_entries)`).Scan(&count); err != nil {
						t.Fatal(err)
					}
					want := 2
					if stage == "guard" {
						want = 0
					}
					if count != want {
						t.Fatal("fenced command changed wrong records", count)
					}
					return
				}
			}
		})
	}
}
func TestPostgresTrustConfigurationCommandsPersistAtomicallyAndReplay(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Tenant'),('foreign','Foreign')`)
	commands, err := BuildTrustConfigurationCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"keys:admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "foreign", Scopes: []string{"keys:admin"}}}}
	providerInput := verificationapp.CreateSigningProviderInput{Name: "KMS", Type: "aws_kms", KeyRef: "arn:aws:kms:example", Encrypted: true}
	if _, err := commands.CreateSigningProvider(ctx, actor, providerInput); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("foreign tenant grant accepted", err)
	}
	if _, err := commands.CreateDSSETrustRoot(ctx, actor, wiringTrustRootInput()); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("foreign trust grant accepted", err)
	}
	actor.ResourceGrants[0].ResourceID = "tenant"
	provider, err := commands.CreateSigningProvider(ctx, actor, providerInput)
	if err != nil || provider.TenantID != "tenant" || provider.SchemaVersion != domain.SigningProviderSchemaVersion {
		t.Fatal(provider, err)
	}
	root, err := commands.CreateDSSETrustRoot(ctx, actor, wiringTrustRootInput())
	if err != nil || root.TenantID != "tenant" || !reflect.DeepEqual(root.RequiredClaims, []string{"builder_id", "external_parameters"}) {
		t.Fatal(root, err)
	}
	var keyRef string
	var claims []byte
	if err := pool.QueryRow(ctx, `SELECT key_ref FROM signing_providers WHERE id=$1 AND tenant_id='tenant'`, provider.ID).Scan(&keyRef); err != nil || keyRef != providerInput.KeyRef {
		t.Fatal(keyRef, err)
	}
	if err := pool.QueryRow(ctx, `SELECT required_claims FROM dsse_trust_roots WHERE id=$1 AND tenant_id='tenant'`, root.ID).Scan(&claims); err != nil {
		t.Fatal(string(claims), err)
	}
	var storedClaims []string
	if err := json.Unmarshal(claims, &storedClaims); err != nil || !reflect.DeepEqual(storedClaims, root.RequiredClaims) {
		t.Fatal("stored trust policy changed", storedClaims, err)
	}
	// Reuse the same enclosing HTTP idempotency unit of work, not an
	// independent transaction that could commit without its replay record.
	actor.UserID, actor.KeyID = "", "key"
	actor.ResourceGrants = nil
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	replayRootInput := wiringTrustRootInput()
	replayRootInput.KeyID = "replay-builder-key"
	for range 2 {
		if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/signing-providers", "provider", []byte(`{"name":"Replay KMS"}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			p, err := commands.CreateSigningProvider(ctx, actor, providerInput)
			return 201, domain.SigningProviderFromContextModel(p), err
		}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/dsse-trust-roots", "root", []byte(`{"name":"Replay Builder"}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			r, err := commands.CreateDSSETrustRoot(ctx, actor, replayRootInput)
			return 201, domain.DSSETrustRootFromContextModel(r), err
		}); err != nil {
			t.Fatal(err)
		}
	}
	count := func(table string) int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count("signing_providers") != 2 || count("dsse_trust_roots") != 2 || count("audit_chain_entries") != 4 {
		t.Fatal("replay duplicated effects")
	}
	if _, err := commands.CreateDSSETrustRoot(ctx, actor, wiringTrustRootInput()); !errors.Is(err, verificationapp.ErrConflict) || count("audit_chain_entries") != 4 {
		t.Fatal("duplicate trust key changed state", err)
	}
	exec(`CREATE FUNCTION reject_trust_audit() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''forced audit failure''; END'; CREATE TRIGGER reject_trust_audit BEFORE INSERT ON audit_chain_entries FOR EACH ROW EXECUTE FUNCTION reject_trust_audit()`)
	if _, err := commands.CreateSigningProvider(ctx, actor, providerInput); err == nil {
		t.Fatal("provider audit failure hidden")
	}
	rollbackRootInput := wiringTrustRootInput()
	rollbackRootInput.KeyID = "rollback-builder-key"
	if _, err := commands.CreateDSSETrustRoot(ctx, actor, rollbackRootInput); err == nil {
		t.Fatal("trust-root audit failure hidden")
	}
	if count("signing_providers") != 2 || count("dsse_trust_roots") != 2 || count("audit_chain_entries") != 4 {
		t.Fatal("audit failure published metadata")
	}
}
