package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

type providerReceiptWiringAPI struct {
	requests []app.ProviderIdentityValidationRequest
	hook     func()
}

func TestPostgresProviderReceiptPreflightTakesMutationFenceBeforeParentLocks(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, pool)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	leader, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = leader.Rollback(context.WithoutCancel(ctx)) }()
	if err := coordination.LockWorkerProjection(ctx, leader, "tenant"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := (providerReceiptReader{factory: store}).ReadOwnedSSOProvider(ctx, "tenant", "provider")
		done <- err
	}()
	// Observe actual advisory contention instead of assuming a sleep proves it.
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			t.Fatal("receipt preflight bypassed the mutation fence", err)
		case <-ctx.Done():
			t.Fatal("receipt preflight did not reach its mutation fence", ctx.Err())
		case <-ticker.C:
			var blocked bool
			if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory' AND $1=ANY(pg_blocking_pids(pid)))`, leader.Conn().PgConn().PID()).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if !blocked {
				continue
			}
			// A writer holding the fence can still lock the parent: the waiting
			// receipt has not taken that row lock in the opposite order.
			if _, err := leader.Exec(ctx, `SELECT id FROM sso_providers WHERE tenant_id='tenant' AND id='provider' FOR UPDATE NOWAIT`); err != nil {
				t.Fatal("receipt took parent lock before fence", err)
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
				t.Fatal("receipt did not resume after fence release", ctx.Err())
			}
			return
		}
	}
}

func (f *providerReceiptWiringAPI) ValidateProviderIdentity(_ context.Context, r app.ProviderIdentityValidationRequest) (app.ProviderIdentityValidationResult, error) {
	f.requests = append(f.requests, r)
	if f.hook != nil {
		f.hook()
	}
	return app.ProviderIdentityValidationResult{Checks: []domain.VerifyCheck{{Name: "live_subject", Result: "passed", Detail: "credential echo " + r.AccessToken}}, Groups: []string{"security"}, Limitations: []string{"safe receipt: " + r.AccessToken}}, nil
}
func providerReceiptHTTP(t *testing.T, store *postgres.Store, live app.ProviderIdentityValidator, key, body string, want int) string {
	t.Helper()
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store, ProviderAPI: live}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil || opts.ProviderVerificationCommands == nil {
		t.Fatal("provider receipts remain Ledger-backed", err)
	}
	noReload := newAggregateLoadCanary(t, t.Context(), store)
	s, err := newNativeHTTPFixture(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/provider-verifications", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || !noReload.Intact(t.Context()) || strings.Contains(w.Body.String(), "access-token-secret") || strings.Contains(w.Body.String(), "evysso_receipt_fixture") {
		t.Fatalf("unsafe/legacy provider receipt: status=%d want=%d canary=%t body=%s", w.Code, want, noReload.Intact(t.Context()), w.Body.String())
	}
	if want >= 400 && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatal("missing problem contract")
	}
	return w.Body.String()
}
func seedProviderReceiptHTTP(t *testing.T, pool *pgxpool.Pool) identityapp.ExchangeSSOCredentialInput {
	t.Helper()
	in := seedSSOExchangeWiring(t, pool)
	c, err := identityapp.NewHMACAuthenticationCredentials("receipt-test-pepper")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE role_bindings SET role='tenant_admin' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO sso_sessions(id,tenant_id,user_id,provider_id,prefix,hash,expires_at,schema_version,created_at)VALUES('operator-session','tenant','user','provider',$1,$2,now()+interval '1 hour','sso-session.v1',now())`, c.Prefix("evysso_receipt_fixture"), c.Hash("evysso_receipt_fixture")); err != nil {
		t.Fatal(err)
	}
	return in
}
func TestPostgresProviderReceiptHTTPRestartReplayAndAuthority(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, pool)
	if c, err := BuildProviderVerificationCommands(nil, nil); err == nil || c != nil {
		t.Fatal("missing transactions accepted")
	}
	live := &providerReceiptWiringAPI{}
	body := `{"provider_type":"oidc","provider_id":"provider","subject":"subject","access_token":"access-token-secret"}`
	first := providerReceiptHTTP(t, store, live, "receipt-key", body, 201)
	second := providerReceiptHTTP(t, store, live, "receipt-key", body, 201)
	var left, right any
	if json.Unmarshal([]byte(first), &left) != nil || json.Unmarshal([]byte(second), &right) != nil || !reflect.DeepEqual(left, right) {
		t.Fatal("restart replay differs")
	}
	if len(live.requests) != 1 || exchangeWiringCounts(t, pool) != [4]int{1, 1, 1, 1} {
		t.Fatal("receipt replay reran provider/effects", len(live.requests), exchangeWiringCounts(t, pool))
	}
	var metadata string
	if err := pool.QueryRow(t.Context(), `SELECT concat(checks::text,limitations::text,assurance_profile::text) FROM provider_verifications`).Scan(&metadata); err != nil || strings.Contains(metadata, "access-token-secret") {
		t.Fatal("credential persisted", err)
	}
	var replay string
	if err := pool.QueryRow(t.Context(), `SELECT response::text FROM idempotency_records`).Scan(&replay); err != nil || strings.Contains(replay, "access-token-secret") {
		t.Fatal("credential replay persisted", err)
	}
	providerReceiptHTTP(t, store, live, "receipt-key", strings.Replace(body, `"subject":"subject"`, `"subject":"different"`, 1), 409)
	if _, err := pool.Exec(t.Context(), `UPDATE role_bindings SET resource_type='release',resource_id='missing-release' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	providerReceiptHTTP(t, store, live, "receipt-key", body, 403)
	if len(live.requests) != 1 {
		t.Fatal("replay bypassed current authority")
	}
}
func TestPostgresProviderReceiptLocalMetadataAndHTTPFailureContract(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	in := seedProviderReceiptHTTP(t, pool)
	metadata := `{"provider_type":"oidc","provider_id":"provider","subject":"subject"}`
	providerReceiptHTTP(t, store, nil, "metadata", metadata, 201)
	local := `{"provider_type":"oidc","provider_id":"provider","subject":"subject","id_token":"` + in.IDToken + `"}`
	providerReceiptHTTP(t, store, nil, "local", local, 201)
	if exchangeWiringCounts(t, pool) != [4]int{2, 1, 2, 2} {
		t.Fatal("metadata/local receipt effects differ", exchangeWiringCounts(t, pool))
	}
	// A direct receipt command commits a failed assessment. The HTTP create
	// contract instead rolls it back with its outer transaction and stores a
	// safe failed idempotency marker, as before this runtime migration.
	providerReceiptHTTP(t, store, nil, "failed", strings.Replace(local, in.IDToken, "bad-token", 1), 422)
	providerReceiptHTTP(t, store, nil, "failed", strings.Replace(local, in.IDToken, "bad-token", 1), 409)
	if exchangeWiringCounts(t, pool) != [4]int{2, 1, 2, 3} {
		t.Fatal("failed HTTP assessment partially committed", exchangeWiringCounts(t, pool))
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO sso_providers(id,tenant_id,name,type,issuer,client_id,status,schema_version,created_at)VALUES('foreign','other',repeat('x',9437184),'oidc','https://foreign.example.test','client','active','sso-provider.v1',now())`); err != nil {
		t.Fatal(err)
	}
	providerReceiptHTTP(t, store, nil, "foreign", strings.Replace(metadata, "provider\"", "foreign\"", 1), 404)
}

func TestPostgresProviderReceiptDirectFailurePersistsOnlyAssessment(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, pool)
	commands, err := BuildProviderVerificationCommands(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := commands.VerifyProviderIdentity(t.Context(), domain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"identity:admin"}}, identityapp.VerifyProviderIdentityInput{ProviderType: "oidc", ProviderID: "provider", Subject: "subject", IDToken: "invalid-credential-canary"})
	if !errors.Is(err, identityapp.ErrVerificationFailed) || v.ID == "" || v.Profile.ID == "" || exchangeWiringCounts(t, pool) != [4]int{1, 1, 1, 0} {
		t.Fatal("direct failed assessment was not committed safely", v, err, exchangeWiringCounts(t, pool))
	}
	var metadata string
	if err := pool.QueryRow(t.Context(), `SELECT concat(checks::text,limitations::text,assurance_profile::text) FROM provider_verifications WHERE id=$1`, v.ID).Scan(&metadata); err != nil || strings.Contains(metadata, "invalid-credential-canary") {
		t.Fatal("direct failure persisted credentials", err)
	}
}
func TestPostgresProviderReceiptRejectsOversizedRowsAndRollsBack(t *testing.T) {
	for _, phase := range []string{"provider", "link", "insert", "audit", "commit"} {
		t.Run(phase, func(t *testing.T) {
			store, pool := openHTMLReportWiringStore(t)
			seedProviderReceiptHTTP(t, pool)
			query := map[string]string{
				"provider": `UPDATE sso_providers SET name=repeat('x',9437184) WHERE id='provider'`,
				"link":     `UPDATE user_identity_links SET email=repeat('x',9437184) WHERE id='link'`,
				"insert":   `CREATE FUNCTION fail_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private receipt write'; END $$;CREATE TRIGGER fail_receipt BEFORE INSERT ON provider_verifications FOR EACH ROW EXECUTE FUNCTION fail_receipt()`,
				"audit":    `CREATE FUNCTION fail_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private receipt audit'; END $$;CREATE TRIGGER fail_receipt BEFORE INSERT ON audit_chain_entries FOR EACH ROW EXECUTE FUNCTION fail_receipt()`,
				"commit":   `CREATE FUNCTION fail_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private receipt commit'; END $$;CREATE CONSTRAINT TRIGGER fail_receipt AFTER INSERT ON provider_verifications DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_receipt()`,
			}[phase]
			if _, err := pool.Exec(t.Context(), query); err != nil {
				t.Fatal(err)
			}
			want := 500
			if phase == "provider" || phase == "link" {
				want = 409
			}
			body := providerReceiptHTTP(t, store, nil, "fault", `{"provider_type":"oidc","provider_id":"provider","subject":"subject"}`, want)
			if strings.Contains(body, "private receipt") {
				t.Fatal("database details escaped")
			}
			counts := exchangeWiringCounts(t, pool)
			if counts[0] != 0 || counts[1] != 1 || counts[2] != 0 {
				t.Fatal("partial receipt committed", counts)
			}
		})
	}
}
func TestPostgresProviderReceiptRevalidatesProviderAndLinkBeforeDirectCommit(t *testing.T) {
	for _, phase := range []string{"provider", "link", "absent link"} {
		t.Run(phase, func(t *testing.T) {
			store, pool := openHTMLReportWiringStore(t)
			seedProviderReceiptHTTP(t, pool)
			if phase == "absent link" {
				if _, err := pool.Exec(t.Context(), `DELETE FROM user_identity_links WHERE id='link'`); err != nil {
					t.Fatal(err)
				}
			}
			live := &providerReceiptWiringAPI{hook: func() {
				query := map[string]string{"provider": `UPDATE sso_providers SET issuer='https://changed.example.test' WHERE id='provider'`, "link": `UPDATE user_identity_links SET verified=false WHERE id='link'`, "absent link": `INSERT INTO user_identity_links(id,tenant_id,user_id,provider_id,subject,email,verified,schema_version,created_at)VALUES('new-link','tenant','user','provider','subject','person@example.test',true,'user-identity-link.v1',now())`}[phase]
				if _, err := pool.Exec(t.Context(), query); err != nil {
					t.Fatal(err)
				}
			}}
			commands, err := BuildProviderVerificationCommands(store, live)
			if err != nil {
				t.Fatal(err)
			}
			v, err := commands.VerifyProviderIdentity(t.Context(), domain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"identity:admin"}}, identityapp.VerifyProviderIdentityInput{ProviderType: "oidc", ProviderID: "provider", Subject: "subject", AccessToken: "access-token-secret"})
			if !errors.Is(err, identityapp.ErrConflict) || v.ID != "" || exchangeWiringCounts(t, pool) != [4]int{0, 1, 0, 0} {
				t.Fatal("stale provider receipt committed", v, err, exchangeWiringCounts(t, pool))
			}
		})
	}
}
