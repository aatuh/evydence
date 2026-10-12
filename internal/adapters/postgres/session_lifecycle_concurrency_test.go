package postgres

import (
	"context"
	"database/sql"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func waitForSessionLockWait(t *testing.T, store *Store, blocker uint32) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var waiting bool
		if err := store.pool.QueryRow(t.Context(), `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1::integer = ANY(pg_blocking_pids(pid)))`, blocker).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("session operation never waited on the held database lock")
		}
	}
}

func TestPostgresSessionActivityCannotLoseRevocationOrRefreshAfterLockWait(t *testing.T) {
	for _, profile := range []string{"revoked", "idle elapsed", "absolute expiry"} {
		t.Run(profile, func(t *testing.T) {
			store, _, credentials, secret := sessionLifecycleFixture(t)
			candidates, err := store.SessionsByPrefix(t.Context(), credentials.Prefix(secret))
			if err != nil || len(candidates) != 1 {
				t.Fatal("candidate read failed", err)
			}
			session := candidates[0]
			identity, err := store.SessionIdentity(t.Context(), session)
			if err != nil {
				t.Fatal(err)
			}
			blocker, err := store.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = blocker.Rollback(context.Background()) }()
			if _, err := blocker.Exec(t.Context(), `SELECT 1 FROM sso_sessions WHERE id=$1 FOR UPDATE`, session.ID); err != nil {
				t.Fatal(err)
			}
			var clockValue atomic.Int64
			clockValue.Store(session.CreatedAt.UnixNano())
			clock := application.ClockFunc(func() time.Time { return time.Unix(0, clockValue.Load()).UTC() })
			result := make(chan error, 1)
			go func() { _, err := store.ValidateActiveSession(t.Context(), session, identity, clock); result <- err }()
			waitForSessionLockWait(t, store, blocker.Conn().PgConn().PID())
			if profile == "revoked" {
				if _, err := blocker.Exec(t.Context(), `UPDATE sso_sessions SET revoked_at=$2 WHERE id=$1`, session.ID, session.CreatedAt); err != nil {
					t.Fatal(err)
				}
			}
			if profile == "idle elapsed" {
				clockValue.Store(session.CreatedAt.Add(30 * time.Minute).UnixNano())
			}
			if profile == "absolute expiry" {
				clockValue.Store(session.ExpiresAt.UnixNano())
			}
			if err := blocker.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if !errors.Is(err, identityapp.ErrUnauthorized) {
					t.Fatal("lock wait admitted an inactive session", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("blocked session activity did not finish")
			}
			var used, revoked sql.NullTime
			if err := store.pool.QueryRow(t.Context(), `SELECT last_used_at,revoked_at FROM sso_sessions WHERE id=$1`, session.ID).Scan(&used, &revoked); err != nil {
				t.Fatal(err)
			}
			if used.Valid || (profile == "revoked") != revoked.Valid {
				t.Fatal("denied activity changed activity or lost revocation")
			}
		})
	}
}

func TestPostgresConcurrentSessionActivityIsMonotonicAndKeepsCredentialBinding(t *testing.T) {
	store, session, credentials, secret := sessionLifecycleFixture(t)
	results := make(chan error, 12)
	for i := 1; i <= 12; i++ {
		at := session.CreatedAt.Add(time.Duration(i) * time.Minute)
		go func() {
			authenticator, err := identityapp.NewAuthenticator(identityapp.AuthenticationConfig{Reader: store, Activity: store, Credentials: credentials, Clock: application.ClockFunc(func() time.Time { return at })})
			if err == nil {
				var actor identitydomain.Actor
				actor, err = authenticator.Authenticate(t.Context(), secret)
				if err == nil && actor.UserID != session.UserID {
					err = errors.New("wrong committed session actor")
				}
			}
			results <- err
		}()
	}
	for range 12 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal("concurrent session authentication failed", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent activity did not finish")
		}
	}
	var used time.Time
	var hash string
	var created, expires time.Time
	if err := store.pool.QueryRow(t.Context(), `SELECT last_used_at,hash,created_at,expires_at FROM sso_sessions WHERE id=$1`, session.ID).Scan(&used, &hash, &created, &expires); err != nil {
		t.Fatal(err)
	}
	if !used.Equal(session.CreatedAt.Add(12*time.Minute)) || hash != session.Hash || !created.Equal(session.CreatedAt) || !expires.Equal(session.ExpiresAt) {
		t.Fatal("concurrent admission lost activity or changed immutable credential fields")
	}
}

func TestPostgresSessionRevocationWaitsForCommittedActivity(t *testing.T) {
	store, original, credentials, secret := sessionLifecycleFixture(t)
	sessions, err := store.SessionsByPrefix(t.Context(), credentials.Prefix(secret))
	if err != nil || len(sessions) != 1 {
		t.Fatal("candidate read failed", err)
	}
	session := sessions[0]
	identity, err := store.SessionIdentity(t.Context(), session)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ready, release := make(chan struct{}), make(chan struct{})
	usedAt := session.CreatedAt.Add(10 * time.Minute)
	activityResult := make(chan error, 1)
	go func() {
		used, err := store.ValidateActiveSession(ctx, session, identity, application.ClockFunc(func() time.Time {
			close(ready)
			select {
			case <-release:
			case <-ctx.Done():
			}
			return usedAt
		}))
		if err == nil && !used.Equal(usedAt) {
			err = errors.New("wrong committed activity timestamp")
		}
		activityResult <- err
	}()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("activity did not acquire its selected locks")
	}
	revocation, err := store.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = revocation.Rollback(context.Background()) }()
	revokedAt := usedAt.Add(time.Minute)
	revocationResult := make(chan error, 1)
	go func() {
		_, err := revocation.Exec(ctx, `UPDATE sso_sessions SET revoked_at=$2 WHERE id=$1 AND revoked_at IS NULL`, session.ID, revokedAt)
		if err == nil {
			err = revocation.Commit(ctx)
		}
		revocationResult <- err
	}()
	waitForSessionBlockedPID(t, store, revocation.Conn().PgConn().PID())
	close(release)
	for _, result := range []<-chan error{activityResult, revocationResult} {
		select {
		case err := <-result:
			if err != nil {
				t.Fatal("ordered activity/revocation failed", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("ordered transaction did not finish")
		}
	}
	var used, revoked, created, expires time.Time
	var hash string
	if err := store.pool.QueryRow(t.Context(), `SELECT last_used_at,revoked_at,created_at,expires_at,hash FROM sso_sessions WHERE id=$1`, session.ID).Scan(&used, &revoked, &created, &expires, &hash); err != nil {
		t.Fatal(err)
	}
	if !used.Equal(usedAt) || !revoked.Equal(revokedAt) || !created.Equal(original.CreatedAt) || !expires.Equal(original.ExpiresAt) || hash != original.Hash {
		t.Fatal("revocation lost committed activity or changed credential binding")
	}
	authenticator, err := identityapp.NewAuthenticator(identityapp.AuthenticationConfig{Reader: store, Activity: store, Credentials: credentials, Clock: application.ClockFunc(func() time.Time { return revokedAt })})
	if err != nil {
		t.Fatal(err)
	}
	if actor, err := authenticator.Authenticate(t.Context(), secret); !errors.Is(err, identityapp.ErrUnauthorized) || actor.UserID != "" {
		t.Fatal("revoked credential survived ordered commits", err)
	}
}

func waitForSessionBlockedPID(t *testing.T, store *Store, pid uint32) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var blocked bool
		if err := store.pool.QueryRow(t.Context(), `SELECT cardinality(pg_blocking_pids($1::integer))>0`, pid).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("revocation never waited for activity's selected row")
		}
	}
}

func TestPostgresCancelledSessionActivityRollsBackAndReleasesLocks(t *testing.T) {
	store, _, credentials, secret := sessionLifecycleFixture(t)
	sessions, err := store.SessionsByPrefix(t.Context(), credentials.Prefix(secret))
	if err != nil || len(sessions) != 1 {
		t.Fatal("candidate read failed", err)
	}
	session := sessions[0]
	identity, err := store.SessionIdentity(t.Context(), session)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	used, err := store.ValidateActiveSession(ctx, session, identity, application.ClockFunc(func() time.Time { cancel(); return session.CreatedAt.Add(time.Minute) }))
	if err == nil || !used.IsZero() {
		t.Fatal("cancelled admission reported committed activity")
	}
	var persisted sql.NullTime
	if err := store.pool.QueryRow(t.Context(), `SELECT last_used_at FROM sso_sessions WHERE id=$1`, session.ID).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Valid {
		t.Fatal("cancelled activity committed")
	}
	check, cancelCheck := context.WithTimeout(t.Context(), time.Second)
	defer cancelCheck()
	tx, err := store.pool.Begin(check)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(check, `SELECT 1 FROM sso_sessions WHERE id=$1 FOR UPDATE NOWAIT`, session.ID); err != nil {
		t.Fatal("cancelled admission retained its row lock", err)
	}
}
