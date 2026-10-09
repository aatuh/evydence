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
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func graphWiringCounts(t *testing.T, p *pgxpool.Pool) [3]int {
	t.Helper()
	var out [3]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM evidence_graph_snapshots),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&out[0], &out[1], &out[2]); err != nil {
		t.Fatal(err)
	}
	return out
}
func TestPostgresGraphSelectionCanonicalHashAndAtomicPersistence(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSummaryMetadata(t, p)
	if _, err := p.Exec(t.Context(), `UPDATE evidence_items SET subject_refs='[{"type":"opaque","id":"external"},{"type":"artifact","digest":"sha256:only"}]',source_identity=jsonb_build_object('private',repeat('x',5242880)) WHERE id='a'`); err != nil {
		t.Fatal(err)
	}
	c, err := BuildGraphSnapshotCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildGraphSnapshotCommands(nil); err == nil {
		t.Fatal("nil factory accepted")
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"evidence:read"}}
	for _, test := range []struct {
		product, release string
		nodes            []domain.GraphNode
		edges            []domain.GraphEdge
	}{
		{"product", "", []domain.GraphNode{{ID: "product", Type: "product", Label: "Product"}, {ID: "a", Type: "evidence", Label: "Build"}}, []domain.GraphEdge{{From: "release", To: "a", Relationship: "has_evidence"}, {From: "a", To: "external", Relationship: "references_opaque"}}},
		{"", "release", []domain.GraphNode{{ID: "release", Type: "release", Label: "1"}, {ID: "a", Type: "evidence", Label: "Build"}, {ID: "b", Type: "evidence", Label: "SBOM"}}, []domain.GraphEdge{{From: "release", To: "a", Relationship: "has_evidence"}, {From: "a", To: "external", Relationship: "references_opaque"}, {From: "release", To: "b", Relationship: "has_evidence"}}},
		{"product", "release", []domain.GraphNode{{ID: "product", Type: "product", Label: "Product"}, {ID: "release", Type: "release", Label: "1"}, {ID: "a", Type: "evidence", Label: "Build"}}, []domain.GraphEdge{{From: "product", To: "release", Relationship: "has_release"}, {From: "release", To: "a", Relationship: "has_evidence"}, {From: "a", To: "external", Relationship: "references_opaque"}}},
	} {
		v, err := c.CreateGraphSnapshot(t.Context(), a, packageapp.CreateGraphSnapshotInput{ProductID: test.product, ReleaseID: test.release})
		if err != nil {
			t.Fatal(err)
		}
		// The old tagged wire structs are the versioned hash input, independently
		// of the new core models and projection encoder.
		material := struct {
			Nodes []domain.GraphNode `json:"nodes"`
			Edges []domain.GraphEdge `json:"edges"`
		}{test.nodes, test.edges}
		want, err := application.NormalizedJSONHash(material)
		if err != nil || v.GraphHash != want {
			t.Fatal("graph hash/selection contract changed", v, err)
		}
		var raw []byte
		var auditHash, actor string
		if err := p.QueryRow(t.Context(), `SELECT jsonb_build_object('nodes',g.nodes,'edges',g.edges),a.payload_hash,a.actor_id FROM evidence_graph_snapshots g JOIN audit_chain_entries a ON a.tenant_id=g.tenant_id AND a.subject_id=g.id WHERE g.id=$1`, v.ID).Scan(&raw, &auditHash, &actor); err != nil || auditHash != want || actor != "operator" {
			t.Fatal("graph and audit not persisted together", err)
		}
		var saved any
		if err := json.Unmarshal(raw, &saved); err != nil {
			t.Fatal(err)
		}
		savedHash, _ := application.NormalizedJSONHash(saved)
		if savedHash != want {
			t.Fatal("stored graph differs from hashed projection")
		}
	}
	before := graphWiringCounts(t, p)
	for _, in := range []packageapp.CreateGraphSnapshotInput{{ProductID: "other-product"}, {ProductID: "product", ReleaseID: "second-release"}, {ReleaseID: "missing"}} {
		v, err := c.CreateGraphSnapshot(t.Context(), a, in)
		if !errors.Is(err, packageapp.ErrNotFound) || v.ID != "" {
			t.Fatal("foreign/mismatched root accepted", v, err)
		}
	}
	if graphWiringCounts(t, p) != before {
		t.Fatal("invalid graph published effects")
	}
	if _, err := p.Exec(t.Context(), `UPDATE evidence_items SET release_id='second-release' WHERE id='a'`); err != nil {
		t.Fatal(err)
	}
	if v, err := c.CreateGraphSnapshot(t.Context(), a, packageapp.CreateGraphSnapshotInput{ProductID: "product"}); !errors.Is(err, packageapp.ErrNotFound) || v.ID != "" {
		t.Fatal("cross-product evidence parent created a false edge", err)
	}
}
func TestPostgresGraphHTTPRestartReplayCurrentGrantsAndNoLedgerReload(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	seedSummaryMetadata(t, p)
	request := func(key, body string, want int) []byte {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.GraphSnapshotCommands == nil {
			t.Fatal("graph still Ledger-backed", err)
		}
		notLoaded := newAggregateLoadCanary(t, t.Context(), store)
		s, err := newNativeHTTPFixture(t.Context(), opts)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/v1/evidence-graph-snapshots", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || !notLoaded.Intact(t.Context()) {
			t.Fatal("graph response or Ledger refresh differs", w.Code, want, notLoaded.Intact(t.Context()), w.Body.String())
		}
		return w.Body.Bytes()
	}
	const body = `{"product_id":"product","release_id":"release"}`
	first := request("graph", body, 201)
	before := graphWiringCounts(t, p)
	var firstValue, replayValue any
	if err := json.Unmarshal(first, &firstValue); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(t.Context(), `UPDATE evidence_items SET title='Changed after snapshot' WHERE id='a'`); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(request("graph", body, 201), &replayValue); err != nil || !reflect.DeepEqual(firstValue, replayValue) || graphWiringCounts(t, p) != before {
		t.Fatal("restart replay regenerated graph", err)
	}
	request("graph", `{"product_id":"product"}`, 409)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='product',resource_id='second-product' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	request("graph", body, 403)
	request("new-denied", body, 403)
	if graphWiringCounts(t, p) != before {
		t.Fatal("current grant denial wrote a graph")
	}
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='release',resource_id='release' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	request("graph", body, 201)
	if _, err := p.Exec(t.Context(), `UPDATE releases SET product_id='second-product' WHERE id='release'`); err != nil {
		t.Fatal(err)
	}
	request("graph", body, 404)
}
func TestPostgresGraphBoundsAndWriteAuditCommitRollback(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSummaryMetadata(t, p)
	c, err := BuildGraphSnapshotCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"evidence:read"}}
	in := packageapp.CreateGraphSnapshotInput{ProductID: "product"}
	for _, stage := range []string{"evidence_graph_snapshots", "audit_chain_entries", "commit"} {
		table := stage
		setup := `CREATE OR REPLACE FUNCTION reject_graph_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private graph storage';END$$;`
		if stage == "commit" {
			table = "evidence_graph_snapshots"
			setup += `CREATE CONSTRAINT TRIGGER reject_graph_stage AFTER INSERT ON evidence_graph_snapshots DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_graph_stage()`
		} else {
			setup += `CREATE TRIGGER reject_graph_stage BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_graph_stage()`
		}
		if _, err := p.Exec(t.Context(), setup); err != nil {
			t.Fatal(err)
		}
		v, err := c.CreateGraphSnapshot(t.Context(), a, in)
		if err == nil || v.ID != "" || graphWiringCounts(t, p) != [3]int{} {
			t.Fatal("uncommitted graph escaped", stage, err)
		}
		if _, err := p.Exec(t.Context(), `DROP TRIGGER reject_graph_stage ON `+table); err != nil {
			t.Fatal(err)
		}
	}
	for _, sql := range []string{`UPDATE evidence_items SET title=repeat('x',65537) WHERE id='a'`, `UPDATE evidence_items SET title='Build',subject_refs=jsonb_build_object('malformed','not-an-array') WHERE id='a'`, `UPDATE evidence_items SET subject_refs=jsonb_build_array(jsonb_build_object('type','opaque','id',repeat('x',5242880))) WHERE id='a'`, `UPDATE evidence_items SET subject_refs=(SELECT jsonb_agg(jsonb_build_object('type','opaque','id','ref'))FROM generate_series(1,8192)) WHERE id='a'`} {
		if _, err := p.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
		if v, err := c.CreateGraphSnapshot(t.Context(), a, in); err == nil || v.ID != "" || graphWiringCounts(t, p) != [3]int{} {
			t.Fatal("oversized/malformed graph accepted", err)
		}
	}
	if _, err := p.Exec(t.Context(), `UPDATE evidence_items SET subject_refs='[]' WHERE id='a';INSERT INTO evidence_items(id,tenant_id,product_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status)SELECT 'extra-'||n,'tenant','product','note','Note','ci',now(),'evidence.v1','sha256:payload','sha256:hash','v1','recorded','not_evaluated' FROM generate_series(1,4094)n`); err != nil {
		t.Fatal(err)
	}
	if v, err := c.CreateGraphSnapshot(t.Context(), a, in); err != nil || len(v.Nodes) != packageapp.MaxEvidenceGraphNodes {
		t.Fatal("exact node bound rejected", len(v.Nodes), err)
	}
	before := graphWiringCounts(t, p)
	if _, err := p.Exec(t.Context(), `INSERT INTO evidence_items(id,tenant_id,product_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status)VALUES('overflow','tenant','product','note','Note','ci',now(),'evidence.v1','sha256:payload','sha256:hash','v1','recorded','not_evaluated')`); err != nil {
		t.Fatal(err)
	}
	if v, err := c.CreateGraphSnapshot(t.Context(), a, in); !errors.Is(err, packageapp.ErrValidation) || v.ID != "" || graphWiringCounts(t, p) != before {
		t.Fatal("graph silently truncated overflow", err)
	}
}
func TestPostgresGraphHoldsParentsAndSelectedEvidenceThroughReplayCommit(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSummaryMetadata(t, p)
	c, err := BuildGraphSnapshotCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	a := domain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"evidence:read"}}
	in := packageapp.CreateGraphSnapshotInput{ProductID: "product", ReleaseID: "release"}
	uow := app.IdempotencyUnitOfWork{Transactions: store}
	_, _, err = uow.WithBody(ctx, a, "POST", "/graph", "lock", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		v, err := c.CreateGraphSnapshot(ctx, a, in)
		if err != nil {
			return 0, nil, err
		}
		for _, statement := range []string{`SELECT 1 FROM tenants WHERE id='tenant' FOR UPDATE NOWAIT`, `SELECT 1 FROM products WHERE id='product' FOR UPDATE NOWAIT`, `SELECT 1 FROM releases WHERE id='release' FOR UPDATE NOWAIT`, `SELECT 1 FROM evidence_items WHERE id='a' FOR UPDATE NOWAIT`} {
			tx, err := p.Begin(ctx)
			if err != nil {
				return 0, nil, err
			}
			_, lockErr := tx.Exec(ctx, statement)
			_ = tx.Rollback(ctx)
			var pgErr *pgconn.PgError
			if !errors.As(lockErr, &pgErr) || pgErr.Code != "55P03" {
				return 0, nil, fmt.Errorf("graph parent lock missing: %w", lockErr)
			}
		}
		tx, err := p.Begin(ctx)
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
			return 0, nil, errors.New("graph lacks worker projection fence")
		}
		return 201, v, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
