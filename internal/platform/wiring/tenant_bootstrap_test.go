package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

func TestPostgresTenantBootstrapCommitsBeforeReturningCredentials(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	commands, err := BuildTenantBootstrapCommands(store, "bootstrap-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	input := identityapp.BootstrapTenantInput{TenantName: " First Tenant ", APIKeyName: " local-admin ", Scopes: []string{"*"}}
	result, err := commands.BootstrapFirstTenant(t.Context(), input)
	if err != nil || !result.Created || result.Tenant.ID == "" || result.Tenant.Name != "First Tenant" || result.Key.TenantID != result.Tenant.ID || result.Key.Name != "local-admin" || result.Key.Hash != "" || result.Secret == "" || !reflect.DeepEqual(result.Key.Scopes, []string{"*"}) {
		t.Fatal("bootstrap did not return the committed public identity", err)
	}
	var tenantCount, keyCount, signingCount, auditCount int
	if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM tenants), (SELECT count(*) FROM api_keys), (SELECT count(*) FROM signing_keys), (SELECT count(*) FROM audit_chain_entries)`).Scan(&tenantCount, &keyCount, &signingCount, &auditCount); err != nil || [4]int{tenantCount, keyCount, signingCount, auditCount} != [4]int{1, 1, 1, 1} {
		t.Fatal("bootstrap effects were not atomic", err, tenantCount, keyCount, signingCount, auditCount)
	}
	credentials, err := buildAuthenticationCredentials("bootstrap-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	var hash, prefix, actorType, actorID, subjectID string
	if err := pool.QueryRow(t.Context(), `SELECT hash, prefix FROM api_keys WHERE id=$1 AND tenant_id=$2`, result.Key.ID, result.Tenant.ID).Scan(&hash, &prefix); err != nil || !credentials.Equal(hash, credentials.Hash(result.Secret)) || prefix != credentials.Prefix(result.Secret) {
		t.Fatal("credential does not match durable issuance", err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT actor_type, actor_id, subject_id FROM audit_chain_entries WHERE tenant_id=$1 AND entry_type='tenant.created'`, result.Tenant.ID).Scan(&actorType, &actorID, &subjectID); err != nil || actorType != "system" || actorID != "bootstrap" || subjectID != result.Tenant.ID {
		t.Fatal("bootstrap audit lost its system identity", err)
	}
	var public, provider string
	var private []byte
	if err := pool.QueryRow(t.Context(), `SELECT public_key, provider, encrypted_private_key FROM signing_keys WHERE tenant_id=$1`, result.Tenant.ID).Scan(&public, &provider, &private); err != nil || public == "" || provider != "local_ed25519" || len(private) != 64 {
		t.Fatal("legacy initial signing-key format changed", err)
	}
	clear(private)
	encoded, err := json.Marshal(result)
	if err != nil || strings.Contains(string(encoded), result.Secret) || strings.Contains(string(encoded), hash) {
		t.Fatal("bootstrap result serialization exposed credentials", err)
	}
	reader, err := BuildAuthenticator(store, store, "bootstrap-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := reader.Authenticate(t.Context(), result.Secret)
	if err != nil || actor.TenantID != result.Tenant.ID || actor.KeyID != result.Key.ID || !actor.HasScope("admin") {
		t.Fatal("fresh durable authentication rejected bootstrap key", err)
	}
	// Existing installations must not select tenant names, stored hashes, or
	// signing material, and must never reissue the secret on restart.
	if _, err := pool.Exec(t.Context(), `UPDATE tenants SET name=repeat('x',9000000)`); err != nil {
		t.Fatal(err)
	}
	if next, err := commands.BootstrapFirstTenant(t.Context(), input); err != nil || !reflect.DeepEqual(next, TenantBootstrapResult{}) {
		t.Fatal("existing installation was bootstrapped again", err)
	}
}

func TestPostgresTenantBootstrapRollsBackEveryFailure(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	commands, err := BuildTenantBootstrapCommands(store, "bootstrap-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`CREATE FUNCTION reject_bootstrap() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private-bootstrap-backend-canary'; END $$`)
	input := identityapp.BootstrapTenantInput{TenantName: "Tenant", APIKeyName: "admin"}
	for _, table := range []string{"tenants", "api_keys", "audit_chain_entries", "signing_keys"} {
		t.Run(table, func(t *testing.T) {
			exec(`CREATE TRIGGER reject_bootstrap BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_bootstrap()`)
			result, err := commands.BootstrapFirstTenant(t.Context(), input)
			if err == nil || strings.Contains(err.Error(), "private-bootstrap-backend-canary") || !reflect.DeepEqual(result, TenantBootstrapResult{}) {
				t.Fatal("failed bootstrap exposed staged identity, secret, or backend details")
			}
			var count int
			if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM tenants)+(SELECT count(*) FROM api_keys)+(SELECT count(*) FROM signing_keys)+(SELECT count(*) FROM audit_chain_entries)`).Scan(&count); err != nil || count != 0 {
				t.Fatal("partial bootstrap was committed", err, count)
			}
			exec(`DROP TRIGGER reject_bootstrap ON ` + table)
		})
	}
	exec(`CREATE CONSTRAINT TRIGGER reject_bootstrap AFTER INSERT ON signing_keys DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_bootstrap()`)
	result, err := commands.BootstrapFirstTenant(t.Context(), input)
	if err == nil || strings.Contains(err.Error(), "private-bootstrap-backend-canary") || !reflect.DeepEqual(result, TenantBootstrapResult{}) {
		t.Fatal("commit failure exposed staged bootstrap credentials")
	}
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM tenants)+(SELECT count(*) FROM api_keys)+(SELECT count(*) FROM signing_keys)+(SELECT count(*) FROM audit_chain_entries)`).Scan(&count); err != nil || count != 0 {
		t.Fatal("deferred failure committed partial state", err, count)
	}
	exec(`DROP TRIGGER reject_bootstrap ON signing_keys`)
	if result, err := commands.BootstrapFirstTenant(t.Context(), input); err != nil || !result.Created || result.Secret == "" {
		t.Fatal("rolled-back bootstrap could not be retried", err)
	}
}

func TestPostgresTenantBootstrapConcurrentStartupsCreateExactlyOneTenant(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	commands, err := BuildTenantBootstrapCommands(store, "bootstrap-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	const attempts = 8
	results := make(chan TenantBootstrapResult, attempts)
	errorsCh := make(chan error, attempts)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			result, err := commands.BootstrapFirstTenant(t.Context(), identityapp.BootstrapTenantInput{TenantName: "First", APIKeyName: "admin"})
			results <- result
			errorsCh <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	created := 0
	for result := range results {
		if result.Created {
			created++
		} else if !reflect.DeepEqual(result, TenantBootstrapResult{}) {
			t.Fatal("losing startup exposed a bootstrap result")
		}
	}
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM tenants`).Scan(&count); err != nil || created != 1 || count != 1 {
		t.Fatal("concurrent startup duplicated administrators", err, created, count)
	}
}

func TestTenantBootstrapCompositionRejectsUnsafeDependencies(t *testing.T) {
	if _, err := BuildTenantBootstrapCommands(nil, "pepper", false); err == nil {
		t.Fatal("nil transaction factory accepted")
	}
	for _, pepper := range []string{"", identityapp.LocalDevelopmentPepper} {
		if _, err := BuildTenantBootstrapCommands(app.NewMemoryUnitOfWorkFactory(), pepper, true); !errors.Is(err, identityapp.ErrValidation) {
			t.Fatal("unsafe production pepper accepted", err)
		}
	}
	commands, err := BuildTenantBootstrapCommands(app.NewMemoryUnitOfWorkFactory(), "pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := commands.BootstrapFirstTenant(t.Context(), identityapp.BootstrapTenantInput{TenantName: "Tenant", APIKeyName: "admin"}); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(result, TenantBootstrapResult{}) {
		t.Fatal("non-durable compatibility factory was used for production bootstrap", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if result, err := commands.BootstrapFirstTenant(ctx, identityapp.BootstrapTenantInput{}); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(result, TenantBootstrapResult{}) {
		t.Fatal("canceled bootstrap returned state", err)
	}
}

func TestPostgresTenantBootstrapLockProtectsEmptyInstallationAndHonorsCancellation(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	guard := repositories.New(tx).Identity.(tenantBootstrapGuard)
	if exists, err := guard.LockAndCheckTenantBootstrap(ctx); err != nil || exists {
		t.Fatal("empty installation guard failed", err)
	}
	other, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := other.Exec(ctx, `SET LOCAL lock_timeout='100ms'`); err != nil {
		t.Fatal(err)
	}
	_, err = other.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('other','Independent writer')`)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Fatal("ordinary tenant insert bypassed empty-installation fence", err)
	}
	commands, err := BuildTenantBootstrapCommands(store, "bootstrap-test-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if result, err := commands.BootstrapFirstTenant(waitCtx, identityapp.BootstrapTenantInput{TenantName: "New", APIKeyName: "admin"}); !errors.Is(err, context.DeadlineExceeded) || err.Error() != context.DeadlineExceeded.Error() || !reflect.DeepEqual(result, TenantBootstrapResult{}) {
		t.Fatal("startup lock wait did not preserve safe cancellation", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('other',repeat('x',9000000))`); err != nil {
		t.Fatal(err)
	}
	if result, err := commands.BootstrapFirstTenant(ctx, identityapp.BootstrapTenantInput{TenantName: "New", APIKeyName: "admin"}); err != nil || !reflect.DeepEqual(result, TenantBootstrapResult{}) {
		t.Fatal("concurrent independent initialization was overwritten", err)
	}
}
