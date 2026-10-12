package postgres

import (
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

func executeSessionLifecycleMigration(t *testing.T, store *Store, direction string) error {
	t.Helper()
	statement, err := os.ReadFile("../../../migrations/20261012000100_sso_session_lifecycle." + direction + ".sql")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.pool.Exec(t.Context(), string(statement))
	return err
}

func TestPostgresSessionLifecycleMigrationPreservesHistoryWithoutRevivingSessions(t *testing.T) {
	for _, profile := range []string{"recent", "idle", "over lifetime"} {
		t.Run(profile, func(t *testing.T) {
			store, session, credentials, secret := sessionLifecycleFixture(t)
			if err := executeSessionLifecycleMigration(t, store, "down"); err != nil {
				t.Fatal(err)
			}
			created, expiry := session.CreatedAt, session.ExpiresAt
			if profile == "idle" {
				created = created.Add(-2 * time.Hour)
				expiry = session.CreatedAt.Add(time.Hour)
			}
			if profile == "over lifetime" {
				expiry = created.Add(30 * 24 * time.Hour)
			}
			if _, err := store.pool.Exec(t.Context(), `UPDATE sso_sessions SET created_at=$1,expires_at=$2,schema_version='sso-session.v1.0.0' WHERE id=$3`, created, expiry, session.ID); err != nil {
				t.Fatal(err)
			}
			if err := executeSessionLifecycleMigration(t, store, "up"); err != nil {
				t.Fatal(err)
			}
			var hash string
			var schemaVersion string
			var actualCreated, actualExpiry time.Time
			var used sql.NullTime
			var maximum, idle int64
			if err := store.pool.QueryRow(t.Context(), `SELECT hash,created_at,expires_at,last_used_at,maximum_lifetime_seconds,idle_timeout_seconds,schema_version FROM sso_sessions WHERE id=$1`, session.ID).Scan(&hash, &actualCreated, &actualExpiry, &used, &maximum, &idle, &schemaVersion); err != nil {
				t.Fatal(err)
			}
			if hash != session.Hash || !actualCreated.Equal(created) || !actualExpiry.Equal(expiry) || used.Valid || maximum != 43200 || idle != 1800 || schemaVersion != "sso-session.v1.0.0" {
				t.Fatal("upgrade rewrote history or refreshed activity")
			}
			authenticator, err := identityapp.NewAuthenticator(identityapp.AuthenticationConfig{Reader: store, Activity: store, Credentials: credentials, Clock: application.ClockFunc(func() time.Time { return session.CreatedAt })})
			if err != nil {
				t.Fatal(err)
			}
			actor, err := authenticator.Authenticate(t.Context(), secret)
			if profile == "recent" {
				if err != nil || actor.UserID != session.UserID {
					t.Fatal("recent compatible session rejected", err)
				}
				if err := executeSessionLifecycleMigration(t, store, "down"); err == nil {
					t.Fatal("downgrade discarded committed activity")
				}
			} else if !errors.Is(err, identityapp.ErrUnauthorized) || actor.UserID != "" {
				t.Fatal("historical inactive session revived", err)
			}
		})
	}
}

func TestPostgresSessionLifecycleRejectsUnsafePersistedPolicy(t *testing.T) {
	store, session, _, _ := sessionLifecycleFixture(t)
	for _, values := range [][2]int64{{0, 1800}, {43201, 1800}, {43200, 0}, {60, 61}, {43200, -1}} {
		if _, err := store.pool.Exec(t.Context(), `UPDATE sso_sessions SET maximum_lifetime_seconds=$2,idle_timeout_seconds=$3 WHERE id=$1`, session.ID, values[0], values[1]); err == nil {
			t.Fatal("unsafe persisted session policy accepted")
		}
	}
}
