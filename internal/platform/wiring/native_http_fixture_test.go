package wiring

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres"
)

// This registry contains only the isolated pools owned by individual tests.
// It lets request helpers install a real database canary without exposing a
// production Store connection or retaining an application aggregate.
var nativeHTTPFixturePools sync.Map

const aggregateLoadCanaryJSON = `"aggregate-load-forbidden"`

type aggregateLoadCanary struct {
	t     *testing.T
	store *postgres.Store
	pool  *pgxpool.Pool
}

func newAggregateLoadCanary(t *testing.T, ctx context.Context, store *postgres.Store) *aggregateLoadCanary {
	t.Helper()
	value, ok := nativeHTTPFixturePools.Load(store)
	if !ok {
		t.Fatal("native HTTP fixture requires a test-owned PostgreSQL pool")
	}
	pool := value.(*pgxpool.Pool)
	if _, err := pool.Exec(ctx, `INSERT INTO ledger_state(id,state)VALUES('default',$1::jsonb)ON CONFLICT(id)DO NOTHING`, aggregateLoadCanaryJSON); err != nil {
		t.Fatal(err)
	}
	canary := &aggregateLoadCanary{t: t, store: store, pool: pool}
	if !canary.Intact(ctx) {
		t.Fatal("aggregate-load canary was not activated")
	}
	t.Cleanup(func() {
		if !canary.Intact(ctx) {
			t.Error("native HTTP changed or disabled the aggregate-load canary")
		}
	})
	return canary
}

func (c *aggregateLoadCanary) Intact(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	var intact bool
	if err := c.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ledger_state WHERE id='default'AND state=$1::jsonb)`, aggregateLoadCanaryJSON).Scan(&intact); err != nil || !intact {
		return false
	}
	// A successful whole-aggregate load contradicts the premise of this
	// fixture, even if requests otherwise returned the expected HTTP status.
	_, _, err := c.store.LoadState(ctx)
	return err != nil
}

func newNativeHTTPFixture(ctx context.Context, options httpapi.ServerOptions) (*httpapi.Server, error) {
	if len(options.PaginationSecret) == 0 {
		options.PaginationSecret = []byte("native-http-fixture-stable-cursor-key")
	}
	server, err := httpapi.NewNativeServerWithOptionsContext(ctx, options)
	if err != nil {
		return nil, err
	}
	if err := nativeHTTPAggregateBindingError(server); err != nil {
		return nil, err
	}
	return server, nil
}

func nativeHTTPAggregateBindingError(server *httpapi.Server) error {
	if server == nil {
		return fmt.Errorf("native HTTP fixture is missing")
	}
	value := reflect.ValueOf(server).Elem()
	for _, name := range []string{"ledger", "idempotency", "identityAccess", "releaseCatalog", "evidenceIngestion", "riskDecisions", "packages", "verification", "localDeployments", "localEvidenceCreation", "localEvidenceRelationships", "localReportTemplates", "localBundleImport", "localEvidenceBundles"} {
		field := value.FieldByName(name)
		if field.IsValid() && !field.IsNil() {
			return fmt.Errorf("native HTTP fixture retains aggregate binding %s", name)
		}
	}
	return nil
}

func assertNativeHTTPHasNoAggregate(t *testing.T, server *httpapi.Server) {
	t.Helper()
	if err := nativeHTTPAggregateBindingError(server); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresAggregateLoadCanaryDetectsTampering(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	canary := newAggregateLoadCanary(t, t.Context(), store)
	if _, err := pool.Exec(t.Context(), `UPDATE ledger_state SET state='{}'WHERE id='default'`); err != nil {
		t.Fatal(err)
	}
	if canary.Intact(t.Context()) {
		t.Fatal("aggregate-load canary did not detect replacement")
	}
	if _, err := pool.Exec(t.Context(), `UPDATE ledger_state SET state=$1::jsonb WHERE id='default'`, aggregateLoadCanaryJSON); err != nil {
		t.Fatal(err)
	}
	if !canary.Intact(t.Context()) {
		t.Fatal("restored aggregate-load canary remained inactive")
	}
}
