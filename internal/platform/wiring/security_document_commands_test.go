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

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresSecurityDocumentsUseFocusedAtomicCommandsWithoutLedger(t *testing.T) {
	if _, err := BuildSecurityDocumentCommands(nil, nil); err == nil {
		t.Fatal("missing transaction factory accepted")
	}
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	objects := &countedSignatureStager{Store: fs}
	a := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"security:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"security:write"}}}}
	auth := &attestationHTTPActor{actor: a}
	counts := func() [8]int {
		t.Helper()
		var n [8]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM evidence_items),(SELECT count(*)FROM security_scans),(SELECT count(*)FROM manual_security_documents),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM object_payloads),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5], &n[6], &n[7]); err != nil {
			t.Fatal(err)
		}
		var unsafe int
		if err := pool.QueryRow(ctx, `SELECT count(*)FROM idempotency_records WHERE state='pending' OR response ? 'payload_ref' OR (state='failed' AND (response<>'null'::jsonb OR status<>0 OR owner_token_hash<>'' OR failed_at IS NULL))`).Scan(&unsafe); err != nil || unsafe != 0 {
			t.Fatal("unsafe terminal replay record", unsafe, err)
		}
		return n
	}
	request := func(path, key, body string, want int) map[string]any {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store, Objects: objects}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.SecurityDocumentCommands == nil {
			t.Fatal("security documents remain Ledger-backed", err)
		}
		opts.Authenticator = auth
		noReload := &decisionHTTPNoReloadStore{}
		ledger, err := app.NewLedgerWithContext(ctx, app.Config{Store: noReload, UnitOfWork: store})
		if err != nil {
			t.Fatal(err)
		}
		s, err := httpapi.NewServerWithOptionsContext(ctx, ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", path, strings.NewReader(body)).WithContext(ctx)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer isolated-auth")
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private") {
			t.Fatal(w.Code, w.Body.String(), noReload.loads)
		}
		if want >= 400 {
			if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
				t.Fatal("error contract")
			}
			return nil
		}
		var out struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Data
	}
	scan := `{"product_id":"product","release_id":"release","artifact_id":"artifact","category":"secret_scan","scanner":"scanner","target_ref":"target","payload":{"findings":[{"severity":"critical"},{"severity":""}]}}`
	api := `{"product_id":"product","release_id":"release","artifact_id":"artifact","format":"sarif","scanner":"scanner","target_ref":"target","payload":{"version":"2.1.0","runs":[{"results":[{"level":"error"}]}]}}`
	manual := `{"product_id":"product","release_id":"release","document_type":"security_review","title":"Review","sensitivity":"restricted","payload":{"private":"manual review"}}`
	base := counts()
	for i, tc := range []struct{ path, body string }{{"/v1/security-scans", scan}, {"/v1/api-security-scans", api}, {"/v1/security-documents", manual}} {
		key := []string{"scan", "api", "manual"}[i]
		v := request(tc.path, key, tc.body, 201)
		if v["tenant_id"] != "tenant" || v["product_id"] != "product" || v["release_id"] != "release" || v["evidence_id"] == "" {
			t.Fatal("coordinates changed", v)
		}
		if i == 0 && (v["finding_count"] != float64(2) || v["redacted"] != true || v["quarantined"] != true || v["format"] != "generic") {
			t.Fatal("secret scan semantics", v)
		}
		if i == 1 && (v["category"] != "api_security" || v["format"] != "sarif" || v["finding_count"] != float64(1)) {
			t.Fatal("API scan semantics", v)
		}
		generated, err := time.Parse(time.RFC3339Nano, v["created_at"].(string))
		if err != nil || generated.Nanosecond()%1000 != 0 {
			t.Fatal("timestamp precision", v)
		}
		before, staged := counts(), objects.stages
		if ref, ok := v["payload_ref"].(string); !ok || !strings.HasPrefix(ref, "object://tenants/tenant/payloads/sha256/") {
			t.Fatal("initial response lost tenant-scoped payload metadata", v)
		}
		// Central replay privacy deliberately omits object references. Compare
		// every other field, and assert that the reference is absent, not blank.
		safe := make(map[string]any, len(v)-1)
		for field, value := range v {
			if field != "payload_ref" {
				safe[field] = value
			}
		}
		if replay := request(tc.path, key, tc.body, 201); !reflect.DeepEqual(safe, replay) || counts() != before || objects.stages != staged {
			t.Fatal("restart replay changed safe response/effects", replay, safe)
		}
		request(tc.path, key, strings.Replace(tc.body, `"product"`, `"missing"`, 1), 404)
		changed := strings.Replace(tc.body, `"scanner":"scanner"`, `"scanner":"changed"`, 1)
		if i == 2 {
			changed = strings.Replace(tc.body, `"title":"Review"`, `"title":"Changed"`, 1)
		}
		request(tc.path, key, changed, 409)
		if counts() != before || objects.stages != staged {
			t.Fatal("failed replay staged/wrote")
		}
	}
	now := counts()
	if now != [8]int{base[0] + 3, base[1] + 2, base[2] + 1, base[3] + 6, base[4] + 3, base[5] + 3, base[6] + 3, base[7]} {
		t.Fatal("partial accepted effects", base, now)
	}
	baseline, staged := counts(), objects.stages
	auth.actor.ResourceGrants = nil
	request("/v1/security-scans", "scan", scan, 403)
	request("/v1/api-security-scans", "api", api, 403)
	request("/v1/security-documents", "manual", manual, 403)
	auth.actor = a
	auth.actor.Scopes = []string{"evidence:write"}
	request("/v1/security-scans", "wrong-scope", scan, 403)
	auth.actor = a
	auth.actor.TenantID = "other"
	request("/v1/security-scans", "foreign", scan, 404)
	request("/v1/api-security-scans", "foreign", api, 404)
	request("/v1/security-documents", "foreign", manual, 404)
	auth.actor = a
	for i, bad := range []string{strings.Replace(scan, `"scanner":"scanner"`, `"scanner":"bad\u0000"`, 1), strings.Replace(scan, `"severity":"critical"`, `"severity":"bad\u0000"`, 1), strings.Replace(scan, `"payload":{"findings":[{"severity":"critical"},{"severity":""}]}`, `"payload":null`, 1), strings.Replace(scan, `"product_id":"product"`, `"product_id":null`, 1), strings.Replace(scan, `"severity":"critical"`, `"severity":"critical","unexpected":true`, 1)} {
		request("/v1/security-scans", string(rune('a'+i)), bad, 400)
	}
	request("/v1/security-documents", "null-doc", strings.Replace(manual, `"title":"Review"`, `"title":null`, 1), 400)
	request("/v1/security-documents", "null-media", strings.Replace(manual, `"payload":`, `"media_type":null,"payload":`, 1), 400)
	request("/v1/api-security-scans", "unknown-api", strings.Replace(api, `"format":`, `"category":"sast","format":`, 1), 400)
	if _, err := pool.Exec(ctx, `INSERT INTO artifacts(id,tenant_id,name,media_type,digest,size)VALUES('unlinked','tenant','Hidden','application/json','sha256:a',1)`); err != nil {
		t.Fatal(err)
	}
	request("/v1/security-scans", "unlinked", strings.Replace(scan, `"artifact"`, `"unlinked"`, 1), 403)
	// Parser failures execute after reservation. Only their response-free
	// failed-key records survive; guard failures do not reserve a key.
	baseline[7] += 2
	if counts() != baseline || objects.stages != staged {
		t.Fatal("denied upload persisted/staged", baseline, counts())
	}
	// A parent created by the enclosing command is visible without publication
	// to Ledger; an outer failure rolls it and all document/replay effects back.
	commands, err := BuildSecurityDocumentCommands(store, objects)
	if err != nil {
		t.Fatal(err)
	}
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	_, _, err = executor.WithBody(ctx, a, "POST", "/pending-security-document", "pending", []byte(`{}`), func(ctx context.Context, repos app.Repositories) (int, any, error) {
		if err := repos.ReleaseCatalog.InsertRelease(ctx, domain.Release{ID: "pending", TenantID: "tenant", ProductID: "product", Version: "pending", State: "draft", CreatedAt: time.Now().UTC()}); err != nil {
			return 0, nil, err
		}
		v, err := commands.UploadManualSecurityDocument(ctx, a, evidenceapp.UploadManualSecurityDocumentInput{ProductID: "product", ReleaseID: "pending", DocumentType: "threat_model", Title: "Model", Sensitivity: "internal", Raw: []byte("private pending model")})
		if err != nil || v.ID == "" {
			t.Fatal("pending parent invisible", v, err)
		}
		return 0, nil, app.ErrValidation
	})
	baseline[7]++
	if !errors.Is(err, app.ErrValidation) || counts() != baseline {
		t.Fatal("outer failure leaked document effects", err, counts())
	}
	// Failure after evidence/audit/payload/outbox insertion must roll back the
	// accepted projection and idempotency reservation in that same transaction.
	if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_security_document()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private security document SQL';END$$;CREATE TRIGGER reject_security_document BEFORE INSERT ON manual_security_documents FOR EACH ROW EXECUTE FUNCTION reject_security_document()`); err != nil {
		t.Fatal(err)
	}
	request("/v1/security-documents", "rollback", manual, 500)
	baseline[7]++
	if counts() != baseline {
		t.Fatal("record failure leaked effects", baseline, counts())
	}
	staged = objects.stages
	request("/v1/security-documents", "rollback", manual, 409)
	if counts() != baseline || objects.stages != staged {
		t.Fatal("failed-key retry executed or leaked effects")
	}
}
