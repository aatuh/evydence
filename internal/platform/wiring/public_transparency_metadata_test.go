package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	e "github.com/aatuh/evydence/internal/experimental/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func seedPublicTransparencyMetadata(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	if _, err := p.Exec(t.Context(), `
INSERT INTO tenants(id,name)VALUES('tenant','Tenant'),('other','Other') ON CONFLICT DO NOTHING;
INSERT INTO public_transparency_logs(id,tenant_id,name,endpoint,public_key,state,schema_version,created_at)VALUES('log','tenant',repeat('x',9437184),repeat('x',9437184),repeat('x',9437184),'configured','public-transparency-log.v1.0.0',now()),('foreign-log','other','Foreign','https://log.example.test','pub','configured','public-transparency-log.v1.0.0',now());
INSERT INTO merkle_batches(id,tenant_id,from_sequence,to_sequence,entry_count,leaf_hashes,root_hash,signature_refs,schema_version,created_at)VALUES('batch','tenant',1,1,1,ARRAY[repeat('x',9437184)],'sha256:'||repeat('A',64),'{}','merkle-batch.v1',now());
INSERT INTO transparency_checkpoints(id,tenant_id,batch_id,provider,external_id,timestamp_hash,state,schema_version,created_at)VALUES('checkpoint','tenant','batch','test','external','sha256:timestamp','recorded','transparency-checkpoint.v1',now()),('foreign-checkpoint','other','batch','test','foreign','sha256:timestamp','recorded','transparency-checkpoint.v1',now())`); err != nil {
		t.Fatal(err)
	}
}
func publicTransparencyMetadataCounts(t *testing.T, p *pgxpool.Pool) [4]int {
	t.Helper()
	var n [4]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM public_transparency_logs),(SELECT count(*)FROM public_transparency_log_entries),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&n[0], &n[1], &n[2], &n[3]); err != nil {
		t.Fatal(err)
	}
	return n
}
func TestPostgresPublicTransparencyMetadataCommandsBoundedRootsAndAtomicWrites(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedPublicTransparencyMetadata(t, p)
	c, err := BuildPublicTransparencyMetadataCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPublicTransparencyMetadataCommands(nil); err == nil {
		t.Fatal("nil factory accepted")
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"keys:admin"}}
	logIn := e.PublicTransparencyLogInput{Name: " public ", Endpoint: " https://log.example.test ", PublicKey: " pub "}
	pubIn := e.PublicTransparencyPublicationInput{LogID: " log ", CheckpointID: " checkpoint ", ExternalID: " external "}
	before := publicTransparencyMetadataCounts(t, p)
	if err := c.AuthorizePublishPublicTransparencyLogEntry(t.Context(), a, pubIn); err != nil || publicTransparencyMetadataCounts(t, p) != before {
		t.Fatal("bounded guard read oversized metadata or wrote", err)
	}
	log, err := c.CreatePublicTransparencyLog(t.Context(), a, logIn)
	if err != nil || log.Name != "public" || log.State != "configured" {
		t.Fatal("log contract changed", log, err)
	}
	v, err := c.PublishPublicTransparencyLogEntry(t.Context(), a, pubIn)
	want, _ := application.NormalizedJSONHash(map[string]any{"log_id": "log", "checkpoint_id": "checkpoint", "merkle_root": "sha256:" + strings.Repeat("A", 64), "external_id": "external"})
	if err != nil || v.EntryHash != want || v.State != "published" {
		t.Fatal("publication commitment differs", v, err)
	}
	var hash, actor string
	if err := p.QueryRow(t.Context(), `SELECT a.payload_hash,a.actor_id FROM public_transparency_log_entries e JOIN audit_chain_entries a ON a.subject_id=e.id AND a.tenant_id=e.tenant_id WHERE e.id=$1`, v.ID).Scan(&hash, &actor); err != nil || hash != want || actor != "operator" {
		t.Fatal("publication audit differs", err)
	}
	before = publicTransparencyMetadataCounts(t, p)
	for _, mode := range []string{"foreign-log", "foreign-checkpoint", "foreign-batch", "oversized-root", "human-product", "missing-tenant"} {
		actor, in := a, pubIn
		wantErr := e.ErrNotFound
		cleanup := ""
		switch mode {
		case "foreign-log":
			in.LogID = mode
		case "foreign-checkpoint":
			in.CheckpointID = mode
		case "foreign-batch":
			if _, err := p.Exec(t.Context(), `UPDATE merkle_batches SET tenant_id='other' WHERE id='batch'`); err != nil {
				t.Fatal(err)
			}
			cleanup = `UPDATE merkle_batches SET tenant_id='tenant' WHERE id='batch'`
		case "oversized-root":
			if _, err := p.Exec(t.Context(), `UPDATE merkle_batches SET root_hash=repeat('x',9437184) WHERE id='batch'`); err != nil {
				t.Fatal(err)
			}
			cleanup = `UPDATE merkle_batches SET root_hash='sha256:'||repeat('A',64) WHERE id='batch'`
			wantErr = e.ErrValidation
		case "human-product":
			actor.KeyID, actor.UserID = "", "user"
			actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: actor.Scopes}}
			wantErr = application.ErrForbidden
		case "missing-tenant":
			actor.TenantID = "missing"
		}
		if out, err := c.PublishPublicTransparencyLogEntry(t.Context(), actor, in); !errors.Is(err, wantErr) || out.ID != "" || publicTransparencyMetadataCounts(t, p) != before {
			t.Fatal("unowned or unbounded publication", mode, out, err)
		}
		if cleanup != "" {
			if _, err := p.Exec(t.Context(), cleanup); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, kind := range []string{"log", "entry"} {
		for _, phase := range []string{"insert", "audit", "commit"} {
			target := "public_transparency_logs"
			if kind == "entry" {
				target = "public_transparency_log_entries"
			}
			if phase == "audit" {
				target = "audit_chain_entries"
			}
			sql := `CREATE OR REPLACE FUNCTION reject_public_metadata()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private metadata storage';END$$;`
			if phase == "commit" {
				sql += `CREATE CONSTRAINT TRIGGER reject_public_metadata AFTER INSERT ON ` + target + ` DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_public_metadata()`
			} else {
				sql += `CREATE TRIGGER reject_public_metadata BEFORE INSERT ON ` + target + ` FOR EACH ROW EXECUTE FUNCTION reject_public_metadata()`
			}
			if _, err := p.Exec(t.Context(), sql); err != nil {
				t.Fatal(err)
			}
			if kind == "log" {
				out, err := c.CreatePublicTransparencyLog(t.Context(), a, logIn)
				if err == nil || out.ID != "" {
					t.Fatal("log failure returned success", phase)
				}
			} else {
				out, err := c.PublishPublicTransparencyLogEntry(t.Context(), a, pubIn)
				if err == nil || out.ID != "" {
					t.Fatal("publication failure returned success", phase)
				}
			}
			if publicTransparencyMetadataCounts(t, p) != before {
				t.Fatal("partial metadata effects", kind, phase)
			}
			if _, err := p.Exec(t.Context(), `DROP TRIGGER reject_public_metadata ON `+target); err != nil {
				t.Fatal(err)
			}
		}
	}
}
func TestPostgresPublicTransparencyMetadataHTTPRestartReplayCurrentHumanAuthority(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	seedPublicTransparencyMetadata(t, p)
	request := func(path, key, body string, want int) []byte {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.PublicTransparencyMetadataCommands == nil {
			t.Fatal("metadata remains Ledger-backed", err)
		}
		noReload := newAggregateLoadCanary(t, t.Context(), store)
		s, err := newNativeHTTPFixture(t.Context(), opts)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", path, strings.NewReader(body)).WithContext(t.Context())
		r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || !noReload.Intact(t.Context()) || strings.Contains(w.Body.String(), "evysso_receipt_fixture") {
			t.Fatal("legacy/unsafe metadata response", w.Code, want, noReload.Intact(t.Context()), w.Body.String())
		}
		return w.Body.Bytes()
	}
	cases := []struct{ path, body string }{{"/v1/public-transparency-logs", `{"name":"public","endpoint":"https://log.example.test","public_key":"pub"}`}, {"/v1/public-transparency-log-entries", `{"log_id":"log","checkpoint_id":"checkpoint","external_id":"external"}`}}
	for _, tc := range cases {
		first := request(tc.path, "metadata", tc.body, 201)
		before := publicTransparencyMetadataCounts(t, p)
		var left, right any
		if json.Unmarshal(first, &left) != nil || json.Unmarshal(request(tc.path, "metadata", tc.body, 201), &right) != nil || !reflect.DeepEqual(left, right) || publicTransparencyMetadataCounts(t, p) != before {
			t.Fatal("restart replay recreated metadata")
		}
		request(tc.path, "metadata", tc.body+" ", 409)
		if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='product',resource_id='product' WHERE id='grant'`); err != nil {
			t.Fatal(err)
		}
		request(tc.path, "metadata", tc.body, 403)
		request(tc.path, "new", tc.body, 403)
		if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant' WHERE id='grant'`); err != nil {
			t.Fatal(err)
		}
		target := "public_transparency_logs"
		if strings.HasSuffix(tc.path, "entries") {
			target = "public_transparency_log_entries"
		}
		if _, err := p.Exec(t.Context(), `CREATE OR REPLACE FUNCTION reject_public_commit()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private metadata commit';END$$;CREATE CONSTRAINT TRIGGER reject_public_commit AFTER INSERT ON `+target+` DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_public_commit()`); err != nil {
			t.Fatal(err)
		}
		failed := request(tc.path, "commit", tc.body, 500)
		if strings.Contains(string(failed), "private metadata commit") || strings.Contains(string(failed), `"state":`) || publicTransparencyMetadataCounts(t, p) != before {
			t.Fatal("failed outer commit published metadata")
		}
		if _, err := p.Exec(t.Context(), `DROP TRIGGER reject_public_commit ON `+target); err != nil {
			t.Fatal(err)
		}
	}
	before := publicTransparencyMetadataCounts(t, p)
	if _, err := p.Exec(t.Context(), `DELETE FROM transparency_checkpoints WHERE id='checkpoint'`); err != nil {
		t.Fatal(err)
	}
	request(cases[1].path, "metadata", cases[1].body, 404)
	if publicTransparencyMetadataCounts(t, p) != before {
		t.Fatal("reference replay guard wrote metadata")
	}
}
func TestPostgresPublicTransparencyMetadataLocksRootsAndWorkerFenceThroughCommit(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedPublicTransparencyMetadata(t, p)
	c, err := BuildPublicTransparencyMetadataCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"keys:admin"}}
	uow := app.IdempotencyUnitOfWork{Transactions: store}
	_, _, err = uow.WithBody(ctx, a, "POST", "/v1/public-transparency-log-entries", "locks", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		v, err := c.PublishPublicTransparencyLogEntry(ctx, a, e.PublicTransparencyPublicationInput{LogID: "log", CheckpointID: "checkpoint", ExternalID: "external"})
		if err != nil {
			return 0, nil, err
		}
		for _, table := range []string{"tenants", "public_transparency_logs", "transparency_checkpoints", "merkle_batches"} {
			id := map[string]string{"tenants": "tenant", "public_transparency_logs": "log", "transparency_checkpoints": "checkpoint", "merkle_batches": "batch"}[table]
			tx, err := p.Begin(ctx)
			if err != nil {
				return 0, nil, err
			}
			_, lockErr := tx.Exec(ctx, fmt.Sprintf("SELECT 1 FROM %s WHERE id=$1 FOR UPDATE NOWAIT", table), id)
			_ = tx.Rollback(ctx)
			var pgErr *pgconn.PgError
			if !errors.As(lockErr, &pgErr) || pgErr.Code != "55P03" {
				return 0, nil, errors.New("metadata root lock missing before commit")
			}
		}
		tx, err := p.Begin(ctx)
		if err != nil {
			return 0, nil, err
		}
		_, err = tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id='other' FOR UPDATE NOWAIT`)
		_ = tx.Rollback(ctx)
		if err != nil {
			return 0, nil, err
		}
		tx, err = p.Begin(ctx)
		if err != nil {
			return 0, nil, err
		}
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='200ms'`); err != nil {
			_ = tx.Rollback(ctx)
			return 0, nil, err
		}
		lockErr := coordination.LockWorkerProjection(ctx, tx, "tenant")
		_ = tx.Rollback(ctx)
		var pgErr *pgconn.PgError
		if !errors.As(lockErr, &pgErr) || pgErr.Code != "55P03" {
			return 0, nil, errors.New("metadata worker fence missing")
		}
		return 201, v, nil
	})
	if err != nil || publicTransparencyMetadataCounts(t, p) != [4]int{2, 1, 1, 1} {
		t.Fatal("outer metadata commit failed", err)
	}
}
