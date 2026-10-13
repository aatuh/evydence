package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	postgresrepositories "github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresOIDCAuthenticationRequestRechecksDeadlineAfterLockAndCancellation(t *testing.T) {
	for _, profile := range []string{"expiry", "cancel"} {
		t.Run(profile, func(t *testing.T) {
			store, _, request := oidcRequestStorageFixture(t)
			blocker, err := store.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = blocker.Rollback(context.Background()) }()
			if err := coordination.LockWorkerProjection(t.Context(), blocker, request.TenantID); err != nil {
				t.Fatal(err)
			}
			var clockValue, clockCalls atomic.Int64
			clockValue.Store(request.CreatedAt.Add(time.Minute).UnixNano())
			clock := application.ClockFunc(func() time.Time { clockCalls.Add(1); return time.Unix(0, clockValue.Load()).UTC() })
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				tx, err := store.pool.Begin(ctx)
				if err == nil {
					defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
					r := postgresrepositories.New(tx).Identity.(identityapp.OIDCAuthenticationRequestConsumer)
					_, err = r.ConsumeOIDCAuthenticationRequest(ctx, request, clock)
					if err == nil {
						err = tx.Commit(ctx)
					}
				}
				result <- err
			}()
			waitForSessionLockWait(t, store, blocker.Conn().PgConn().PID())
			if clockCalls.Load() != 0 {
				t.Fatal("consumption sampled admission time before the required locks")
			}
			want := app.ErrUnauthorized
			if profile == "cancel" {
				cancel()
				want = context.Canceled
			} else {
				clockValue.Store(request.ExpiresAt.UnixNano())
			}
			if err := blocker.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if !errors.Is(err, want) {
					t.Fatal("lock wait admitted invalid proof", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("consumption did not finish after lock release")
			}
			var consumed int
			if err := store.pool.QueryRow(t.Context(), `SELECT count(*) FROM oidc_authentication_requests WHERE consumed_at IS NOT NULL`).Scan(&consumed); err != nil || consumed != 0 {
				t.Fatal("failed admission committed a consumption marker", err)
			}
		})
	}
}

type oidcRequestTestRepository interface {
	ValidateOIDCProvider(context.Context, identitydomain.SSOProvider) error
	InsertOIDCAuthenticationRequest(context.Context, identitydomain.OIDCAuthenticationRequest, time.Time) error
	ReadOIDCAuthenticationRequest(context.Context, string, string, string) (identitydomain.OIDCAuthenticationRequest, error)
	ConsumeOIDCAuthenticationRequest(context.Context, identitydomain.OIDCAuthenticationRequest, application.Clock) (time.Time, error)
}

func oidcRequestRepositoryForTest(t *testing.T, tx pgx.Tx) oidcRequestTestRepository {
	t.Helper()
	r, ok := postgresrepositories.New(tx).Identity.(oidcRequestTestRepository)
	if !ok {
		t.Fatal("focused PostgreSQL identity repository does not implement login request storage and consumption")
	}
	return r
}

func oidcRequestStorageFixture(t *testing.T) (*Store, identitydomain.SSOProvider, identitydomain.OIDCAuthenticationRequest) {
	t.Helper()
	store, _, credentials, _ := sessionLifecycleFixture(t)
	if _, err := store.pool.Exec(t.Context(), `UPDATE sso_providers SET jwks='{"keys":[{"kid":"fixture-key"}]}' WHERE id='sso_lifecycle'`); err != nil {
		t.Fatal(err)
	}
	tx, err := store.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	r := oidcRequestRepositoryForTest(t, tx)
	reader := postgresrepositories.New(tx).Identity.(identityapp.SSOExchangeReader)
	provider, err := reader.SSOProviderByID(t.Context(), "sso_lifecycle")
	if err != nil {
		t.Fatal(err)
	}
	state, err := credentials.GenerateLoginState()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := credentials.GenerateLoginNonce()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := identityapp.OIDCProviderTrustFingerprint(provider)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	request := identitydomain.OIDCAuthenticationRequest{ID: "oidcreq_fixture", TenantID: provider.TenantID, ProviderID: provider.ID, Delivery: "api", TrustFingerprint: fingerprint, StateHash: state.Hash, NonceHash: nonce.Hash, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute), SchemaVersion: identitydomain.OIDCAuthenticationRequestSchemaVersion}
	if err := r.ValidateOIDCProvider(t.Context(), provider); err != nil {
		t.Fatal(err)
	}
	if err := r.InsertOIDCAuthenticationRequest(t.Context(), request, now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return store, provider, request
}

func TestPostgresOIDCAuthenticationRequestConsumptionIsScopedSingleUseAndRollbackSafe(t *testing.T) {
	store, _, request := oidcRequestStorageFixture(t)
	tx, err := store.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	r := oidcRequestRepositoryForTest(t, tx)
	if _, err := r.ReadOIDCAuthenticationRequest(t.Context(), "foreign", request.ProviderID, request.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("foreign tenant read was not concealed", err)
	}
	if _, err := r.ReadOIDCAuthenticationRequest(t.Context(), request.TenantID, "foreign", request.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("foreign provider read was not concealed", err)
	}
	used := request.CreatedAt.Add(time.Minute)
	if _, err := r.ConsumeOIDCAuthenticationRequest(t.Context(), request, application.ClockFunc(func() time.Time { return used })); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	tx, err = store.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	r = oidcRequestRepositoryForTest(t, tx)
	current, err := r.ReadOIDCAuthenticationRequest(t.Context(), request.TenantID, request.ProviderID, request.ID)
	if err != nil || current.ConsumedAt != nil {
		t.Fatal("rollback consumed the proof", err)
	}
	if at, err := r.ConsumeOIDCAuthenticationRequest(t.Context(), request, application.ClockFunc(func() time.Time { return used })); err != nil || !at.Equal(used) {
		t.Fatal("retry failed after rollback", err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	tx, err = store.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	r = oidcRequestRepositoryForTest(t, tx)
	if _, err := r.ConsumeOIDCAuthenticationRequest(t.Context(), request, application.ClockFunc(func() time.Time { return used })); !errors.Is(err, app.ErrUnauthorized) {
		t.Fatal("committed proof replay was accepted", err)
	}
}

func TestPostgresOIDCAuthenticationRequestCapacityIsFiniteAndExpiryReclaimsSpace(t *testing.T) {
	store, provider, request := oidcRequestStorageFixture(t)
	for i := 1; i < 64; i++ {
		tx, err := store.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		r := oidcRequestRepositoryForTest(t, tx)
		if err := r.ValidateOIDCProvider(t.Context(), provider); err != nil {
			t.Fatal(err)
		}
		v := request
		v.ID = fmt.Sprintf("oidcreq_%d", i)
		v.StateHash = fmt.Sprintf("%064x", i+100)
		v.NonceHash = fmt.Sprintf("%064x", i+200)
		if err := r.InsertOIDCAuthenticationRequest(t.Context(), v, request.CreatedAt); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := store.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	r := oidcRequestRepositoryForTest(t, tx)
	if err := r.ValidateOIDCProvider(t.Context(), provider); err != nil {
		t.Fatal(err)
	}
	full := request
	full.ID = "overflow"
	if err := r.InsertOIDCAuthenticationRequest(t.Context(), full, request.CreatedAt); !errors.Is(err, app.ErrRateLimited) {
		t.Fatal("request capacity was not enforced", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	at := request.ExpiresAt
	tx, err = store.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	r = oidcRequestRepositoryForTest(t, tx)
	if err := r.ValidateOIDCProvider(t.Context(), provider); err != nil {
		t.Fatal(err)
	}
	fresh := request
	fresh.ID = "fresh"
	fresh.CreatedAt = at
	fresh.ExpiresAt = at.Add(5 * time.Minute)
	if err := r.InsertOIDCAuthenticationRequest(t.Context(), fresh, at); err != nil {
		t.Fatal("expiry did not reclaim bounded capacity", err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.pool.QueryRow(t.Context(), `SELECT count(*) FROM oidc_authentication_requests`).Scan(&count); err != nil || count != 1 {
		t.Fatal("expired operational rows were not pruned", err)
	}
}

func TestPostgresOIDCAuthenticationRequestRejectsStaleTrustAndLifetime(t *testing.T) {
	for _, profile := range []string{"trust", "expired", "wrong nonce hash"} {
		t.Run(profile, func(t *testing.T) {
			store, _, request := oidcRequestStorageFixture(t)
			if profile == "trust" {
				if _, err := store.pool.Exec(t.Context(), `UPDATE sso_providers SET client_id='changed' WHERE id=$1`, request.ProviderID); err != nil {
					t.Fatal(err)
				}
			}
			if profile == "wrong nonce hash" {
				request.NonceHash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
			}
			at := request.CreatedAt.Add(time.Minute)
			if profile == "expired" {
				at = request.ExpiresAt
			}
			tx, err := store.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			r := oidcRequestRepositoryForTest(t, tx)
			if _, err := r.ConsumeOIDCAuthenticationRequest(t.Context(), request, application.ClockFunc(func() time.Time { return at })); !errors.Is(err, app.ErrUnauthorized) {
				t.Fatal("inactive or unbound proof was consumed", err)
			}
		})
	}
}

func TestPostgresOIDCAuthenticationRequestConcurrentConsumptionCommitsOnce(t *testing.T) {
	store, _, request := oidcRequestStorageFixture(t)
	results := make(chan error, 8)
	for range 8 {
		go func() {
			tx, err := store.pool.Begin(t.Context())
			if err != nil {
				results <- err
				return
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			r, ok := postgresrepositories.New(tx).Identity.(oidcRequestTestRepository)
			if !ok {
				results <- errors.New("request repository missing")
				return
			}
			_, err = r.ConsumeOIDCAuthenticationRequest(t.Context(), request, application.ClockFunc(func() time.Time { return request.CreatedAt.Add(time.Minute) }))
			if err == nil {
				err = tx.Commit(t.Context())
			}
			results <- err
		}()
	}
	successes := 0
	for range 8 {
		select {
		case err := <-results:
			if err == nil {
				successes++
			} else if !errors.Is(err, app.ErrUnauthorized) {
				t.Fatal("unexpected concurrent request result", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent consumption did not terminate")
		}
	}
	if successes != 1 {
		t.Fatal("single-use request admitted multiple concurrent consumers", successes)
	}
}
