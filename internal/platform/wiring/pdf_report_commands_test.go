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

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func pdfWiringCounts(t *testing.T, p *pgxpool.Pool) [5]int {
	t.Helper()
	var out [5]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM pdf_report_packages),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM object_payloads),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&out[0], &out[1], &out[2], &out[3], &out[4]); err != nil {
		t.Fatal(err)
	}
	return out
}
func TestPDFReportCompositionRejectsUnstageableObjectStores(t *testing.T) {
	factory := &postgres.Store{}
	if c, err := BuildPDFReportCommands(factory, struct{ app.ObjectStore }{}, false); err == nil || c != nil {
		t.Fatal("non-transactional object store accepted")
	}
	if c, err := BuildPDFReportCommands(factory, nil, true); err == nil || c != nil {
		t.Fatal("production metadata-only PDF accepted")
	}
	if c, err := BuildPDFReportCommands(factory, nil, false); err != nil || c == nil {
		t.Fatal("explicit non-production metadata-only mode rejected", err)
	}
}
func TestPostgresPDFCreationStagesVerifiedBytesAndRollsBackMetadata(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSummaryMetadata(t, p)
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	objects := &countedSignatureStager{Store: fs}
	c, err := BuildPDFReportCommands(store, objects, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPDFReportCommands(nil, objects, false); err == nil {
		t.Fatal("nil transaction factory accepted")
	}
	if _, err := BuildPDFReportCommands(store, nil, true); err == nil {
		t.Fatal("production hash-only PDF profile accepted")
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"report:read"}}
	in := packageapp.CreatePDFReportInput{ReportType: "release_readiness", ProductID: "product", ReleaseID: "release", Title: "Readiness"}
	v, err := c.CreatePDFReportPackage(t.Context(), a, in)
	if err != nil || pdfWiringCounts(t, p) != [5]int{1, 1, 1, 1, 0} {
		t.Fatal("PDF lifecycle not atomic", v, pdfWiringCounts(t, p), err)
	}
	payload, err := store.GetObjectPayload(t.Context(), a.TenantID, v.PayloadHash)
	if err != nil || payload.Status != app.ObjectPayloadStaged || payload.Reference() != v.PayloadRef || payload.Size != v.PayloadSize || payload.MediaType != "application/pdf" {
		t.Fatal("unverified payload metadata", err)
	}
	if _, err := objects.Get(t.Context(), payload.FinalKey); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("PDF finalized before worker", err)
	}
	if err := app.FinalizeStagedObjectPayload(t.Context(), store, objects, a.TenantID, v.PayloadHash); err != nil {
		t.Fatal(err)
	}
	obj, err := objects.Get(t.Context(), payload.FinalKey)
	want, _ := packageapp.PDFReportPayload(in)
	if err != nil || string(obj.Bytes) != string(want) || obj.Digest != v.PayloadHash {
		t.Fatal("finalized PDF bytes differ", err)
	}
	before := pdfWiringCounts(t, p)
	for _, table := range []string{"object_payloads", "outbox_jobs", "pdf_report_packages", "audit_chain_entries", "commit"} {
		target := table
		sql := `CREATE OR REPLACE FUNCTION reject_pdf_write()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private PDF failure';END$$;`
		if table == "commit" {
			target = "pdf_report_packages"
			sql += `CREATE CONSTRAINT TRIGGER reject_pdf_write AFTER INSERT ON pdf_report_packages DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_pdf_write()`
		} else {
			sql += `CREATE TRIGGER reject_pdf_write BEFORE INSERT ON ` + target + ` FOR EACH ROW EXECUTE FUNCTION reject_pdf_write()`
		}
		if _, err := p.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
		bad := in
		bad.Title = "Failure " + table
		failed, err := c.CreatePDFReportPackage(t.Context(), a, bad)
		if err == nil || failed.ID != "" || pdfWiringCounts(t, p) != before {
			t.Fatal("uncommitted PDF escaped", table, failed.ID, err)
		}
		if _, err := p.Exec(t.Context(), `DROP TRIGGER reject_pdf_write ON `+target); err != nil {
			t.Fatal(err)
		}
	}
	stages := objects.stages
	for _, bad := range []packageapp.CreatePDFReportInput{{ReportType: "x", ProductID: "other-product", Title: "Foreign"}, {ReportType: "x", ProductID: "product", ReleaseID: "second-release", Title: "Mismatch"}} {
		if v, err := c.CreatePDFReportPackage(t.Context(), a, bad); !errors.Is(err, packageapp.ErrNotFound) || v.ID != "" {
			t.Fatal("invalid PDF ownership accepted", err)
		}
	}
	a.KeyID, a.UserID = "", "user"
	a.ResourceGrants = nil
	if _, err := c.CreatePDFReportPackage(t.Context(), a, in); !errors.Is(err, packageapp.ErrForbidden) {
		t.Fatal("missing human grant accepted", err)
	}
	if objects.stages != stages || pdfWiringCounts(t, p) != before {
		t.Fatal("denied PDF staged bytes or metadata")
	}
}
func TestPostgresPDFHTTPRestartReplayCurrentGrantAndNoLedgerReload(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	seedSummaryMetadata(t, p)
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	objects := &countedSignatureStager{Store: fs}
	request := func(key, body string, want int) []byte {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store, Objects: objects}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.PDFReportCommands == nil {
			t.Fatal("durable PDF still Ledger-backed", err)
		}
		notLoaded := newAggregateLoadCanary(t, t.Context(), store)
		s, err := newNativeHTTPFixture(t.Context(), opts)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/v1/reports/pdf", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || !notLoaded.Intact(t.Context()) {
			t.Fatal("PDF response or Ledger refresh differs", w.Code, want, notLoaded.Intact(t.Context()), w.Body.String())
		}
		return w.Body.Bytes()
	}
	const body = `{"report_type":"release_readiness","product_id":"product","release_id":"release","title":"Readiness"}`
	first := request("pdf", body, 201)
	before := pdfWiringCounts(t, p)
	stages := objects.stages
	var original, replayed any
	if err := json.Unmarshal(first, &original); err != nil {
		t.Fatal(err)
	}
	data := original.(map[string]any)["data"].(map[string]any)
	if data["payload_ref"] == nil {
		t.Fatal("initial authorized response omitted its object reference")
	}
	// Replay has always omitted this sensitive field. All other metadata must
	// equal the original, and replay must not stage or persist another report.
	delete(data, "payload_ref")
	rawReplay := request("pdf", body, 201)
	if strings.Contains(string(rawReplay), "payload_ref") || strings.Contains(string(rawReplay), "object://") {
		t.Fatal("replay leaked an object reference")
	}
	if err := json.Unmarshal(rawReplay, &replayed); err != nil || !reflect.DeepEqual(original, replayed) || pdfWiringCounts(t, p) != before || objects.stages != stages {
		t.Fatal("restart replay regenerated PDF", err)
	}
	request("pdf", strings.Replace(body, "Readiness", "Changed", 1), 409)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='product',resource_id='second-product' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	request("pdf", body, 403)
	request("new-denied", body, 403)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='release',resource_id='release' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	request("pdf", body, 201)
	if _, err := p.Exec(t.Context(), `UPDATE releases SET product_id='second-product' WHERE id='release'`); err != nil {
		t.Fatal(err)
	}
	request("pdf", body, 404)
	if pdfWiringCounts(t, p) != before || objects.stages != stages {
		t.Fatal("replay guard mutated durable PDF state")
	}
	if _, err := p.Exec(t.Context(), `UPDATE releases SET product_id='product' WHERE id='release';CREATE FUNCTION reject_pdf_commit()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private PDF commit failure';END$$;CREATE CONSTRAINT TRIGGER reject_pdf_commit AFTER INSERT ON pdf_report_packages DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_pdf_commit()`); err != nil {
		t.Fatal(err)
	}
	failed := request("commit-failure", strings.Replace(body, "Readiness", "Failed report", 1), 500)
	if strings.Contains(string(failed), "payload_hash") || strings.Contains(string(failed), "object://") || strings.Contains(string(failed), "private PDF commit failure") || pdfWiringCounts(t, p) != before {
		t.Fatal("HTTP commit failure exposed a PDF or partial metadata")
	}
}

func TestPostgresPDFHoldsRootLocksAndFenceWithoutLockingEvidence(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSummaryMetadata(t, p)
	c, err := BuildPDFReportCommands(store, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"report:read"}}
	in := packageapp.CreatePDFReportInput{ReportType: "release_readiness", ProductID: "product", ReleaseID: "release", Title: "Readiness"}
	uow := app.IdempotencyUnitOfWork{Transactions: store}
	_, _, err = uow.WithBody(ctx, a, "POST", "/v1/reports/pdf", "locks", []byte(`{}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
		v, err := c.CreatePDFReportPackage(ctx, a, in)
		if err != nil {
			return 0, nil, err
		}
		for _, statement := range []string{`SELECT 1 FROM tenants WHERE id='tenant' FOR UPDATE NOWAIT`, `SELECT 1 FROM products WHERE id='product' FOR UPDATE NOWAIT`, `SELECT 1 FROM releases WHERE id='release' FOR UPDATE NOWAIT`} {
			tx, err := p.Begin(ctx)
			if err != nil {
				return 0, nil, err
			}
			_, lockErr := tx.Exec(ctx, statement)
			_ = tx.Rollback(ctx)
			var pgErr *pgconn.PgError
			if !errors.As(lockErr, &pgErr) || pgErr.Code != "55P03" {
				return 0, nil, errors.New("PDF root lock missing")
			}
		}
		tx, err := p.Begin(ctx)
		if err != nil {
			return 0, nil, err
		}
		_, evidenceErr := tx.Exec(ctx, `SELECT 1 FROM evidence_items WHERE id='a' FOR UPDATE NOWAIT`)
		_ = tx.Rollback(ctx)
		if evidenceErr != nil {
			return 0, nil, errors.New("PDF creation locked unrelated evidence")
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
			return 0, nil, errors.New("PDF lacks worker projection fence")
		}
		return 201, v, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPostgresPDFMetadataOnlyPreservesSubmittedCoordinates(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSummaryMetadata(t, p)
	c, err := BuildPDFReportCommands(store, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"report:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"report:read"}}}}
	for _, coords := range [][2]string{{"product", ""}, {"", "release"}, {"product", "release"}} {
		in := packageapp.CreatePDFReportInput{ReportType: "custom_descriptive_type", ProductID: coords[0], ReleaseID: coords[1], Title: "Readiness"}
		v, err := c.CreatePDFReportPackage(t.Context(), a, in)
		if err != nil || v.ProductID != coords[0] || v.ReleaseID != coords[1] || v.PayloadRef != "" || v.ReportType != in.ReportType {
			t.Fatal("PDF scope or metadata-only mode changed", v, err)
		}
		var product, release string
		if err := p.QueryRow(t.Context(), `SELECT coalesce(product_id,''),coalesce(release_id,'') FROM pdf_report_packages WHERE id=$1 AND tenant_id=$2`, v.ID, a.TenantID).Scan(&product, &release); err != nil || product != coords[0] || release != coords[1] {
			t.Fatal("inferred parent leaked into submitted PDF scope", err)
		}
	}
	if pdfWiringCounts(t, p) != [5]int{3, 3, 0, 0, 0} {
		t.Fatal("hash-only mode staged object metadata")
	}
}
