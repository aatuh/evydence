package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
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
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

type samlRequestTestRepository interface {
	SAMLProviderBindingByID(context.Context, string) (identitydomain.SAMLProviderBinding, error)
	ReadOwnedSAMLProviderBinding(context.Context, string, string) (identitydomain.SAMLProviderBinding, error)
	UpsertSAMLProviderBinding(context.Context, identitydomain.SAMLProviderBinding) error
	ValidateSAMLProviderBinding(context.Context, identitydomain.SAMLProviderBinding) error
	InsertSAMLAuthenticationRequest(context.Context, identitydomain.SAMLAuthenticationRequest, time.Time) error
	ReadSAMLAuthenticationRequest(context.Context, string, string, string) (identitydomain.SAMLAuthenticationRequest, error)
	ConsumeSAMLAuthenticationRequest(context.Context, identitydomain.SAMLAuthenticationRequest, identitydomain.SAMLAssertionUse, application.Clock) (time.Time, error)
}

func TestPostgresSAMLBackupCommitsReplayMetadataWithoutStateCredentials(t *testing.T) {
	store, _, req, proof := samlRequestStorageFixture(t)
	tx, err := store.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err := samlRequestRepositoryForTest(t, tx).ConsumeSAMLAuthenticationRequest(t.Context(), req, proof, application.ClockFunc(func() time.Time { return req.CreatedAt.Add(time.Minute) })); err != nil {
		t.Fatal(err)
	}
	r := postgresrepositories.New(tx).Integrity.(verificationapp.BackupStateCommitmentReader)
	before, err := r.ReadBackupStateCommitment(t.Context(), req.TenantID)
	if err != nil || before.Profile != "tenant-relational-state.v5" {
		t.Fatal("SAML backup commitment failed", err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE saml_authentication_requests SET state_hash='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE id=$1`, req.ID); err != nil {
		t.Fatal(err)
	}
	privateChanged, err := r.ReadBackupStateCommitment(t.Context(), req.TenantID)
	if err != nil || privateChanged.StateHash != before.StateHash {
		t.Fatal("private state credential entered the commitment", err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE saml_assertion_consumptions SET expires_at=expires_at+interval '1 second' WHERE tenant_id=$1 AND provider_id=$2`, req.TenantID, req.ProviderID); err != nil {
		t.Fatal(err)
	}
	replayChanged, err := r.ReadBackupStateCommitment(t.Context(), req.TenantID)
	if err != nil || replayChanged.RowsRead != before.RowsRead || replayChanged.StateHash == before.StateHash {
		t.Fatal("replay retention was omitted from the commitment", err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE saml_provider_bindings SET recipient='https://other.example.test/consume' WHERE tenant_id=$1 AND provider_id=$2`, req.TenantID, req.ProviderID); err != nil {
		t.Fatal(err)
	}
	bindingChanged, err := r.ReadBackupStateCommitment(t.Context(), req.TenantID)
	if err != nil || bindingChanged.StateHash == replayChanged.StateHash {
		t.Fatal("SP binding was omitted from the commitment", err)
	}
}

func TestPostgresSAMLBindingRejectsAnOlderConfigurationClock(t *testing.T) {
	store, b, _, _ := samlRequestStorageFixture(t)
	tx, err := store.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) }()
	b.UpdatedAt = b.UpdatedAt.Add(-time.Second)
	b.Recipient = "https://other.example.test/consume"
	if err := samlRequestRepositoryForTest(t, tx).UpsertSAMLProviderBinding(t.Context(), b); !errors.Is(err, app.ErrConflict) {
		t.Fatal("older configuration was reported committed", err)
	}
}

func TestPostgresSAMLConsumptionRechecksDeadlinesAfterLocksAndCancellation(t *testing.T) {
	for _, phase := range []string{"request expiry", "proof expiry", "cancel"} {
		t.Run(phase, func(t *testing.T) {
			store, _, req, proof := samlRequestStorageFixture(t)
			blocker, err := store.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = blocker.Rollback(context.WithoutCancel(t.Context())) }()
			if err := coordination.LockWorkerProjection(t.Context(), blocker, req.TenantID); err != nil {
				t.Fatal(err)
			}
			var value, calls atomic.Int64
			value.Store(req.CreatedAt.Add(time.Minute).UnixNano())
			clock := application.ClockFunc(func() time.Time { calls.Add(1); return time.Unix(0, value.Load()).UTC() })
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				tx, err := store.pool.Begin(ctx)
				if err == nil {
					defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
					r, ok := postgresrepositories.New(tx).Identity.(samlRequestTestRepository)
					if !ok {
						result <- errors.New("SAML capability missing")
						return
					}
					_, err = r.ConsumeSAMLAuthenticationRequest(ctx, req, proof, clock)
					if err == nil {
						err = tx.Commit(ctx)
					}
				}
				result <- err
			}()
			waitForSessionLockWait(t, store, blocker.Conn().PgConn().PID())
			if calls.Load() != 0 {
				t.Fatal("proof clock sampled before required locks")
			}
			want := app.ErrUnauthorized
			switch phase {
			case "request expiry":
				value.Store(req.ExpiresAt.UnixNano())
			case "proof expiry":
				value.Store(proof.ExpiresAt.UnixNano())
			case "cancel":
				cancel()
				want = context.Canceled
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
				t.Fatal("consumption failed to finish after lock release")
			}
			if states, uses := samlStorageCounts(t, store); states != 0 || uses != 0 {
				t.Fatal("denied lock-wait admission left partial effects")
			}
		})
	}
}

func TestPostgresSAMLConsumptionRejectsStaleBindingAndAlteredState(t *testing.T) {
	for _, phase := range []string{"recipient", "certificate", "state"} {
		t.Run(phase, func(t *testing.T) {
			store, _, req, proof := samlRequestStorageFixture(t)
			var err error
			switch phase {
			case "recipient":
				_, err = store.pool.Exec(t.Context(), `UPDATE saml_provider_bindings SET recipient='https://other.example.test/consume'`)
			case "certificate":
				_, err = store.pool.Exec(t.Context(), `UPDATE sso_providers SET saml_signing_certificates='["rotated-public-certificate"]'`)
			case "state":
				req.StateHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			}
			if err != nil {
				t.Fatal(err)
			}
			tx, err := store.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) }()
			if _, err := samlRequestRepositoryForTest(t, tx).ConsumeSAMLAuthenticationRequest(t.Context(), req, proof, application.ClockFunc(func() time.Time { return req.CreatedAt.Add(time.Minute) })); !errors.Is(err, app.ErrUnauthorized) {
				t.Fatal("stale provider/binding/state retained authority", err)
			}
			if states, uses := samlStorageCounts(t, store); states != 0 || uses != 0 {
				t.Fatal("stale binding left partial consumption")
			}
		})
	}
}

func TestPostgresSAMLReplayMarkerSurvivesUntilSignedExpiry(t *testing.T) {
	store, _, req, proof := samlRequestStorageFixture(t)
	proof.IssuedAt = req.CreatedAt.Add(time.Minute)
	proof.ExpiresAt = proof.IssuedAt.Add(5 * time.Minute)
	tx, err := store.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := samlRequestRepositoryForTest(t, tx).ConsumeSAMLAuthenticationRequest(t.Context(), req, proof, application.ClockFunc(func() time.Time { return proof.IssuedAt })); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	c, err := identityapp.NewHMACAuthenticationCredentials("test-pepper")
	if err != nil {
		t.Fatal(err)
	}
	insert := func(id string, at time.Time) {
		t.Helper()
		v := req
		v.ID = id
		v.CreatedAt = at
		v.ExpiresAt = at.Add(5 * time.Minute)
		state, err := c.GenerateLoginState()
		if err != nil {
			t.Fatal(err)
		}
		v.StateHash = state.Hash
		tx, err := store.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) }()
		if err := samlRequestRepositoryForTest(t, tx).InsertSAMLAuthenticationRequest(t.Context(), v, at); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	insert("samlreq_during_marker", req.ExpiresAt.Add(time.Second))
	if states, uses := samlStorageCounts(t, store); states != 1 || uses != 1 {
		t.Fatal("request expiry erased a still-valid assertion replay marker")
	}
	insert("samlreq_after_marker", proof.ExpiresAt)
	if states, uses := samlStorageCounts(t, store); states != 0 || uses != 0 {
		t.Fatal("expired replay state was not reclaimed")
	}
}

func samlRequestRepositoryForTest(t *testing.T, tx pgx.Tx) samlRequestTestRepository {
	t.Helper()
	r, ok := postgresrepositories.New(tx).Identity.(samlRequestTestRepository)
	if !ok {
		t.Fatal("focused PostgreSQL identity repository lacks SAML request/replay capabilities")
	}
	return r
}

func samlRequestStorageFixture(t *testing.T) (*Store, identitydomain.SAMLProviderBinding, identitydomain.SAMLAuthenticationRequest, identitydomain.SAMLAssertionUse) {
	t.Helper()
	store, _, credentials, _ := sessionLifecycleFixture(t)
	if _, err := store.pool.Exec(t.Context(), `UPDATE sso_providers SET type='saml',saml_signing_certificates='["fixture-public-certificate"]' WHERE id='sso_lifecycle'`); err != nil {
		t.Fatal(err)
	}
	tx, err := store.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) }()
	r := samlRequestRepositoryForTest(t, tx)
	if err := coordination.LockWorkerProjection(t.Context(), tx, "ten_lifecycle"); err != nil {
		t.Fatal(err)
	}
	p, err := postgresrepositories.New(tx).Identity.(identityapp.SSOProviderWriteReader).ReadOwnedSSOProvider(t.Context(), "ten_lifecycle", "sso_lifecycle")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	b := identitydomain.SAMLProviderBinding{TenantID: p.TenantID, ProviderID: p.ID, Provider: p, Recipient: "https://sp.example.test/v1/sso/session-exchanges", NameIDFormat: identitydomain.SAMLNameIDUnspecified, SchemaVersion: identitydomain.SAMLProviderBindingSchemaVersion, UpdatedAt: now}
	if err := r.UpsertSAMLProviderBinding(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	b, err = r.ReadOwnedSAMLProviderBinding(t.Context(), p.TenantID, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	state, err := credentials.GenerateLoginState()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := identityapp.SAMLProviderTrustFingerprint(b)
	if err != nil {
		t.Fatal(err)
	}
	req := identitydomain.SAMLAuthenticationRequest{ID: "samlreq_storage", TenantID: p.TenantID, ProviderID: p.ID, Delivery: "api", Issuer: p.Issuer, Audience: p.ClientID, Recipient: b.Recipient, NameIDFormat: b.NameIDFormat, TrustFingerprint: fingerprint, StateHash: state.Hash, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute), SchemaVersion: identitydomain.SAMLAuthenticationRequestSchemaVersion}
	if err := r.ValidateSAMLProviderBinding(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	if err := r.InsertSAMLAuthenticationRequest(t.Context(), req, now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	hash, err := identityapp.SAMLAssertionFingerprint(req, "_assertion")
	if err != nil {
		t.Fatal(err)
	}
	return store, b, req, identitydomain.SAMLAssertionUse{AssertionHash: hash, IssuedAt: now, ExpiresAt: now.Add(4 * time.Minute)}
}

func samlStorageCounts(t *testing.T, store *Store) (int, int) {
	t.Helper()
	var requests, assertions int
	if err := store.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM saml_authentication_requests WHERE consumed_at IS NOT NULL),(SELECT count(*) FROM saml_assertion_consumptions)`).Scan(&requests, &assertions); err != nil {
		t.Fatal(err)
	}
	return requests, assertions
}

func TestPostgresSAMLStateConsumptionIsOwnedSingleUseAndRollbackSafe(t *testing.T) {
	store, _, req, proof := samlRequestStorageFixture(t)
	tx, err := store.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	r := samlRequestRepositoryForTest(t, tx)
	for _, scope := range [][2]string{{"foreign", req.ProviderID}, {req.TenantID, "foreign"}} {
		if _, err := r.ReadSAMLAuthenticationRequest(t.Context(), scope[0], scope[1], req.ID); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("foreign request was not concealed", err)
		}
		if _, err := r.ReadOwnedSAMLProviderBinding(t.Context(), scope[0], scope[1]); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("foreign SAML binding was not concealed", err)
		}
	}
	clock := application.ClockFunc(func() time.Time { return req.CreatedAt.Add(time.Minute) })
	if _, err := r.ConsumeSAMLAuthenticationRequest(t.Context(), req, proof, clock); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if states, uses := samlStorageCounts(t, store); states != 0 || uses != 0 {
		t.Fatal("rollback retained partial proof consumption")
	}
	tx, err = store.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	r = samlRequestRepositoryForTest(t, tx)
	if _, err := r.ConsumeSAMLAuthenticationRequest(t.Context(), req, proof, clock); err != nil {
		t.Fatal("rollback prevented retry", err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	tx, err = store.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err := samlRequestRepositoryForTest(t, tx).ConsumeSAMLAuthenticationRequest(t.Context(), req, proof, clock); !errors.Is(err, app.ErrUnauthorized) {
		t.Fatal("committed request replay was accepted", err)
	}
	if states, uses := samlStorageCounts(t, store); states != 1 || uses != 1 {
		t.Fatal("proof consumption was not atomic and single use")
	}
}

func TestPostgresSAMLAssertionReplayAcrossFreshRequestsIsRejected(t *testing.T) {
	store, _, req, proof := samlRequestStorageFixture(t)
	clock := application.ClockFunc(func() time.Time { return req.CreatedAt.Add(time.Minute) })
	tx, err := store.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	r := samlRequestRepositoryForTest(t, tx)
	if _, err := r.ConsumeSAMLAuthenticationRequest(t.Context(), req, proof, clock); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	second := req
	second.ID = "samlreq_second"
	c, err := identityapp.NewHMACAuthenticationCredentials("test-pepper")
	if err != nil {
		t.Fatal(err)
	}
	state, err := c.GenerateLoginState()
	if err != nil {
		t.Fatal(err)
	}
	second.StateHash = state.Hash
	tx, err = store.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	r = samlRequestRepositoryForTest(t, tx)
	if err := r.InsertSAMLAuthenticationRequest(t.Context(), second, req.CreatedAt); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	tx, err = store.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err := samlRequestRepositoryForTest(t, tx).ConsumeSAMLAuthenticationRequest(t.Context(), second, proof, clock); !errors.Is(err, app.ErrUnauthorized) {
		t.Fatal("assertion ID replay bypassed fresh request state", err)
	}
	if states, uses := samlStorageCounts(t, store); states != 1 || uses != 1 {
		t.Fatal("replayed assertion left partial effects")
	}
}

func TestPostgresSAMLConcurrentConsumersCommitExactlyOnce(t *testing.T) {
	store, _, req, proof := samlRequestStorageFixture(t)
	start := make(chan struct{})
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			<-start
			tx, err := store.pool.Begin(t.Context())
			if err == nil {
				defer func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) }()
				r, ok := postgresrepositories.New(tx).Identity.(samlRequestTestRepository)
				if !ok {
					errs <- errors.New("SAML capability missing")
					return
				}
				_, err = r.ConsumeSAMLAuthenticationRequest(t.Context(), req, proof, application.ClockFunc(func() time.Time { return req.CreatedAt.Add(time.Minute) }))
				if err == nil {
					err = tx.Commit(t.Context())
				}
			}
			errs <- err
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	success := 0
	for err := range errs {
		if err == nil {
			success++
		} else if !errors.Is(err, app.ErrUnauthorized) {
			t.Fatal("concurrent replay failed unexpectedly", err)
		}
	}
	states, uses := samlStorageCounts(t, store)
	if success != 1 || states != 1 || uses != 1 {
		t.Fatal("concurrent proof consumption was not exactly once", success, states, uses)
	}
}

func TestPostgresSAMLRequestCapacityAndCleanupRemainBounded(t *testing.T) {
	store, _, req, _ := samlRequestStorageFixture(t)
	c, err := identityapp.NewHMACAuthenticationCredentials("test-pepper")
	if err != nil {
		t.Fatal(err)
	}
	insert := func(index int, at time.Time) error {
		tx, err := store.pool.Begin(t.Context())
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) }()
		v := req
		v.ID = fmt.Sprintf("samlreq_%d", index)
		v.CreatedAt = at
		v.ExpiresAt = at.Add(5 * time.Minute)
		state, err := c.GenerateLoginState()
		if err != nil {
			return err
		}
		v.StateHash = state.Hash
		if err := samlRequestRepositoryForTest(t, tx).InsertSAMLAuthenticationRequest(t.Context(), v, at); err != nil {
			return err
		}
		return tx.Commit(t.Context())
	}
	for i := 1; i < identitydomain.MaximumSAMLAuthenticationRequestsPerProvider; i++ {
		if err := insert(i, req.CreatedAt); err != nil {
			t.Fatal(err)
		}
	}
	if err := insert(64, req.CreatedAt); !errors.Is(err, app.ErrRateLimited) {
		t.Fatal("SAML state capacity was not enforced", err)
	}
	if err := insert(65, req.ExpiresAt); err != nil {
		t.Fatal("expired state did not reclaim capacity", err)
	}
	var count int
	if err := store.pool.QueryRow(t.Context(), `SELECT count(*) FROM saml_authentication_requests`).Scan(&count); err != nil || count != 1 {
		t.Fatal("bounded cleanup left expired operational state", count, err)
	}
}
