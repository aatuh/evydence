package wiring

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

const wiringOpenAPIDocument = `{"openapi":"3.0.3","info":{"title":"API","version":"1"},"paths":{"/health":{"get":{"operationId":"health","responses":{"200":{"description":"OK"}}}}}}`

func TestPostgresOpenAPIIngestionUsesFocusedDurableUploadsAndReplay(t *testing.T) {
	if _, err := BuildOpenAPIIngestionCommands(nil, nil, false); err == nil {
		t.Fatal("nil factory accepted")
	}
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	objects := &countedSignatureStager{Store: fs}
	a := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"evidence:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"evidence:write"}}}}
	auth := &attestationHTTPActor{actor: a}
	body := `{"product_id":"product","release_id":"release","version":"v1","spec":` + wiringOpenAPIDocument + `}`
	counts := func() [5]int {
		t.Helper()
		var n [5]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM evidence_items),(SELECT count(*)FROM openapi_contracts),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM object_payloads)`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	baseline := counts()
	request := func(key, body string, native bool, version string, want int) domain.OpenAPIContract {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store, Objects: objects, WorkerOwnedParsers: true}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil {
			t.Fatal(err)
		}
		if opts.OpenAPIIngestionCommands == nil {
			t.Fatal("OpenAPI ingestion remains Ledger-backed")
		}
		opts.Authenticator = auth
		noReload := &decisionHTTPNoReloadStore{}
		ledger, err := newLegacyLedgerFixtureWithContext(ctx, app.Config{Store: noReload, UnitOfWork: store})
		if err != nil {
			t.Fatal(err)
		}
		server, err := httpapi.NewServerWithOptionsContext(ctx, ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/v1/openapi-contracts", strings.NewReader(body)).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer isolated-auth")
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("Content-Type", "application/json")
		if native {
			r.Header.Set("Content-Type", "application/vnd.oai.openapi+json")
			r.Header.Set("X-Evydence-Product-ID", "product")
			r.Header.Set("X-Evydence-Release-ID", "release")
			r.Header.Set("X-Evydence-Version", version)
		}
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private OpenAPI SQL") {
			t.Fatalf("got %d want %d loads=%d: %s", w.Code, want, noReload.loads, w.Body.String())
		}
		if want >= 400 {
			if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
				t.Fatal("unsafe problem")
			}
			return domain.OpenAPIContract{}
		}
		var result struct {
			Data domain.OpenAPIContract `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result.Data
	}
	v := request("wrapped", body, false, "", 201)
	if v.ID == "" || v.TenantID != "tenant" || v.ProductID != "product" || v.ReleaseID != "release" || v.Version != "v1" || v.PathCount != 1 || len(v.Operations) != 1 || v.Operations[0].Path != "/health" || v.Hash != app.BytesPayloadSource([]byte(wiringOpenAPIDocument)).Digest || v.CreatedAt.Nanosecond()%1000 != 0 {
		t.Fatal(v)
	}
	if replay := request("wrapped", body, false, "", 201); !reflect.DeepEqual(replay, v) {
		t.Fatal("wrapped replay changed", replay, v)
	}
	native := request("native", wiringOpenAPIDocument, true, "v1", 201)
	if replay := request("native", wiringOpenAPIDocument, true, "v1", 201); !reflect.DeepEqual(replay, native) {
		t.Fatal("native replay changed")
	}
	request("native", wiringOpenAPIDocument, true, "v2", 409)
	expected := [5]int{baseline[0] + 2, baseline[1] + 2, baseline[2] + 4, baseline[3] + 3, baseline[4] + 1}
	if counts() != expected || objects.stages != 2 {
		t.Fatal("replay mutated durable effects", counts(), objects.stages)
	}
	var paths int
	var ops []byte
	if err := pool.QueryRow(ctx, `SELECT path_count,operations FROM openapi_contracts WHERE id=$1`, v.ID).Scan(&paths, &ops); err != nil || paths != 0 || string(ops) != "null" {
		t.Fatal("worker-owned projection changed", paths, string(ops), err)
	}
	var rawEvidence []byte
	if err := pool.QueryRow(ctx, `SELECT to_jsonb(e)FROM evidence_items e WHERE id=$1`, v.EvidenceID).Scan(&rawEvidence); err != nil {
		t.Fatal(err)
	}
	var evidence domain.EvidenceItem
	if err := json.Unmarshal(rawEvidence, &evidence); err != nil {
		t.Fatal(err)
	}
	evidence.CreatedAt, evidence.ObservedAt = evidence.CreatedAt.UTC(), evidence.ObservedAt.UTC()
	hash, err := (evidenceCanonicalHasher{}).HashEvidence(ctx, domain.EvidenceToContextModel(evidence))
	if err != nil || hash != evidence.CanonicalHash || evidence.PayloadHash != v.Hash || evidence.VerificationStatus != "pending" || evidence.ChainEntryID == "" || evidence.Metadata["path_count"] != float64(1) {
		t.Fatal("durable evidence commitment changed", hash, evidence, err)
	}
	payload, err := store.GetObjectPayload(ctx, a.TenantID, v.Hash)
	if err != nil || payload.Status != app.ObjectPayloadStaged || payload.Size != int64(len(wiringOpenAPIDocument)) || payload.Reference() != evidence.PayloadRef {
		t.Fatal("staged lifecycle changed", payload, err)
	}
	if _, err := objects.Get(ctx, payload.FinalKey); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("payload finalized before worker", err)
	}
	// Retained pre-upgrade native replay uses the body digest. It may replay
	// only the exact original product/release/version and never execute anew.
	_, _, err = (app.IdempotencyUnitOfWork{Transactions: store}).WithBodyDigest(ctx, a, "POST", "/v1/openapi-contracts", "legacy", v.Hash, func(context.Context, app.Repositories) (int, any, error) { return 201, v, nil })
	if err != nil {
		t.Fatal(err)
	}
	if replay := request("legacy", wiringOpenAPIDocument, true, "v1", 201); !reflect.DeepEqual(replay, v) {
		t.Fatal("legacy replay changed")
	}
	request("legacy", wiringOpenAPIDocument, true, "v2", 409)
	auth.actor.ResourceGrants = nil
	request("wrapped", body, false, "", 403)
	request("native", wiringOpenAPIDocument, true, "v1", 403)
	auth.actor = a
	auth.actor.TenantID = "other"
	request("foreign", body, false, "", 404)
	auth.actor = a
	for i, bad := range []string{`null`, `[]`, `{}`, `{} {}`, strings.Replace(body, `"product"`, `null`, 1), strings.Replace(body, `"release"`, `null`, 1), strings.Replace(body, `"v1"`, `null`, 1), strings.Replace(body, wiringOpenAPIDocument, `null`, 1), strings.Replace(body, `"product"`, `"bad\u0000"`, 1), strings.Replace(body, `"product"`, `"`+strings.Repeat("x", 1025)+`"`, 1), strings.Replace(body, `"version":`, `"unknown":true,"version":`, 1), strings.Replace(body, `"version":`, `"version":"v1","version":`, 1), strings.Replace(body, wiringOpenAPIDocument, `{}`, 1)} {
		request(fmt.Sprintf("bad-%d", i), bad, false, "", 400)
	}
	request("bad-native", `{}`, true, "v1", 400)
	if counts() != expected || objects.stages != 2 {
		t.Fatal("invalid request reached staging or persistence", counts(), objects.stages)
	}
	if _, err := pool.Exec(ctx, `UPDATE releases SET product_id='other-product' WHERE id='release'`); err != nil {
		t.Fatal(err)
	}
	request("wrapped", body, false, "", 404)
	request("native", wiringOpenAPIDocument, true, "v1", 404)
	if _, err := pool.Exec(ctx, `UPDATE releases SET product_id='product' WHERE id='release'`); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"object_payloads", "outbox_jobs", "audit_chain_entries", "evidence_items", "openapi_contracts", "idempotency_records", "commit"} {
		table, op := stage, "INSERT"
		if stage == "idempotency_records" {
			op = "UPDATE"
		}
		trigger := `CREATE TRIGGER reject_openapi_upload BEFORE ` + op + ` ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_openapi_upload()`
		if stage == "commit" {
			table = "openapi_contracts"
			trigger = `CREATE CONSTRAINT TRIGGER reject_openapi_upload AFTER INSERT ON openapi_contracts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_openapi_upload()`
		}
		if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_openapi_upload()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private OpenAPI SQL';END$$;`+trigger); err != nil {
			t.Fatal(err)
		}
		request("fault-"+stage, body, false, "", 500)
		if counts() != expected {
			t.Fatal("partial upload effects", stage, counts())
		}
		if _, err := pool.Exec(ctx, `DROP TRIGGER reject_openapi_upload ON `+table+`;DROP FUNCTION reject_openapi_upload()`); err != nil {
			t.Fatal(err)
		}
	}
	request("fault-commit", body, false, "", 201)
	if counts() != [5]int{baseline[0] + 3, baseline[1] + 3, baseline[2] + 6, baseline[3] + 4, baseline[4] + 1} {
		t.Fatal("commit retry changed effects", counts())
	}
	if err := app.FinalizeStagedObjectPayload(ctx, store, objects, a.TenantID, v.Hash); err != nil {
		t.Fatal(err)
	}
	stored, err := objects.Get(ctx, payload.FinalKey)
	if err != nil || !bytes.Equal(stored.Bytes, []byte(wiringOpenAPIDocument)) || stored.Digest != v.Hash || stored.TenantID != a.TenantID {
		t.Fatal("finalized payload bytes changed", stored, err)
	}
	inline, err := BuildOpenAPIIngestionCommands(store, objects, false)
	if err != nil {
		t.Fatal(err)
	}
	inlineContract, err := inline.UploadOpenAPIContractPayload(ctx, a, evidenceapp.OpenAPIIngestionInput{ProductID: "product", ReleaseID: "release", Version: "v2"}, evidenceapp.BytesPayloadSource([]byte(wiringOpenAPIDocument)))
	if err != nil || inlineContract.PathCount != 1 || len(inlineContract.Operations) != 1 {
		t.Fatal("inline compatibility changed", inlineContract, err)
	}
	if err := pool.QueryRow(ctx, `SELECT path_count,operations FROM openapi_contracts WHERE id=$1`, inlineContract.ID).Scan(&paths, &ops); err != nil || paths != 1 || string(ops) == "null" {
		t.Fatal("inline projection not durable", paths, string(ops), err)
	}
	if counts() != [5]int{baseline[0] + 4, baseline[1] + 4, baseline[2] + 8, baseline[3] + 5, baseline[4] + 1} {
		t.Fatal("finalized payload reuse duplicated lifecycle", counts())
	}
}

func TestPostgresOpenAPIIngestionJoinsPendingParentsAndOuterRollback(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	at := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		return repos.Identity.InsertTenant(ctx, domain.Tenant{ID: "tenant", Name: "Pending parents", CreatedAt: at})
	}); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildOpenAPIIngestionCommands(store, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	actor := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"evidence:write"}}
	source := evidenceapp.BytesPayloadSource([]byte(wiringOpenAPIDocument))
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	counts := func() [6]int {
		t.Helper()
		var n [6]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM products),(SELECT count(*)FROM releases),(SELECT count(*)FROM evidence_items),(SELECT count(*)FROM openapi_contracts),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs)`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	rollback := errors.New("outer command rolled back")
	for _, key := range []string{"rollback", "commit"} {
		actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: key + "-product", Scopes: []string{"evidence:write"}}}
		_, _, err := executor.WithBody(ctx, actor, "POST", "/compound-openapi", key, []byte(key), func(txCtx context.Context, repos app.Repositories) (int, any, error) {
			if err := repos.ReleaseCatalog.InsertProduct(txCtx, domain.Product{ID: key + "-product", TenantID: "tenant", Name: key, Slug: key, CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			if err := repos.ReleaseCatalog.InsertRelease(txCtx, domain.Release{ID: key + "-release", TenantID: "tenant", ProductID: key + "-product", Version: "1", State: "draft", Revision: 1, CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			in := evidenceapp.OpenAPIIngestionInput{ProductID: key + "-product", ReleaseID: key + "-release", Version: "1"}
			if err := commands.AuthorizeUploadOpenAPIContract(txCtx, actor, in); err != nil {
				return 0, nil, err
			}
			v, err := commands.UploadOpenAPIContractPayload(txCtx, actor, in, source)
			if err != nil {
				return 0, nil, err
			}
			if v.PathCount != 1 || len(v.Operations) != 1 {
				t.Fatal("missing-object mode lost projection", v)
			}
			if key == "rollback" {
				return 0, nil, rollback
			}
			return 201, domain.OpenAPIContractFromContext(v), nil
		})
		if key == "rollback" {
			if !errors.Is(err, rollback) || counts() != [6]int{} {
				t.Fatal("pending parent command escaped outer rollback", counts(), err)
			}
		} else if err != nil || counts() != [6]int{1, 1, 1, 1, 2, 1} {
			t.Fatal("pending parents not visible or committed atomically", counts(), err)
		}
	}
}
