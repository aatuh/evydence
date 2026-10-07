package wiring

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type countedVEXIngestionCommands struct {
	httpapi.VEXIngestionCommands
	uploads *int
}

func (c countedVEXIngestionCommands) UploadVEXPayload(ctx context.Context, a identitydomain.Actor, in evidenceapp.VEXIngestionInput, source evidenceapp.PayloadSource) (evidencedomain.VEXDocument, error) {
	*c.uploads++
	return c.VEXIngestionCommands.UploadVEXPayload(ctx, a, in, source)
}

func TestPostgresVEXIngestionUsesFocusedAtomicUploadsAndRestartReplay(t *testing.T) {
	if _, err := BuildVEXIngestionCommands(nil, nil); err == nil {
		t.Fatal("missing transactions accepted")
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
	uploads := 0
	counts := func() [7]int {
		t.Helper()
		var n [7]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM evidence_items),(SELECT count(*)FROM vex_documents),(SELECT count(*)FROM vex_import_reports),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM object_payloads),(SELECT count(*)FROM vulnerability_decisions)`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5], &n[6]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	base := counts()
	request := func(key, body, format string, native bool, want int) domain.VEXDocument {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store, Objects: objects, WorkerOwnedParsers: true}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil || opts.VEXIngestionCommands == nil {
			t.Fatal("VEX remains Ledger-backed", err)
		}
		opts.Authenticator = auth
		opts.VEXIngestionCommands = countedVEXIngestionCommands{opts.VEXIngestionCommands, &uploads}
		noReload := newAggregateLoadCanary(t, ctx, store)
		server, err := newNativeHTTPFixture(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		path := "/v1/vex"
		if format == "cyclonedx" {
			path += "/cyclonedx"
		}
		r := httptest.NewRequest("POST", path, strings.NewReader(body)).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer isolated-auth")
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("Content-Type", "application/json")
		if native {
			r.Header.Set("Content-Type", evidenceapp.OpenVEXMediaType)
			r.Header.Set("X-Evydence-Release-ID", "release")
			r.Header.Set("X-Evydence-Artifact-ID", "artifact")
		}
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		if w.Code != want || !noReload.Intact(ctx) || strings.Contains(w.Body.String(), "private VEX SQL") {
			t.Fatalf("got %d want %d canary=%t: %s", w.Code, want, noReload.Intact(ctx), w.Body.String())
		}
		if want >= 400 {
			if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
				t.Fatal("unsafe VEX error envelope")
			}
			return domain.VEXDocument{}
		}
		var result struct {
			Data domain.VEXDocument `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result.Data
	}
	raw, err := os.ReadFile("../../app/parsers/vex/testdata/openvex/openvex-spec-minimal.json")
	if err != nil {
		t.Fatal(err)
	}
	wrapped := `{"release_id":"release","artifact_id":"artifact","payload":` + string(raw) + `}`
	var envelope struct {
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal([]byte(wrapped), &envelope); err != nil {
		t.Fatal(err)
	}
	// Wrapped uploads retain the JSON value, including its internal formatting,
	// not surrounding whitespace in the envelope. Native uploads retain all bytes.
	wrappedSource := string(envelope.Payload)
	native := strings.Repeat(" ", int(app.SmallJSONRequestLimit)+1) + string(raw)
	cdx := `{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[{"id":"CVE-2026-1","affects":[{"ref":"pkg:generic/api@1"}],"analysis":{"state":"resolved"}},{"analysis":{"state":"resolved"}}]}`
	for _, tc := range []struct {
		key, body, format string
		native            bool
		source            string
	}{{"openvex", wrapped, "openvex", false, wrappedSource}, {"native", native, "openvex", true, native}, {"cyclonedx", `{"release_id":"release","artifact_id":"artifact","payload":` + cdx + `}`, "cyclonedx", false, cdx}} {
		v := request(tc.key, tc.body, tc.format, tc.native, 201)
		parsed, err := (app.VEXPayloadParser{}).ParseVEX(ctx, tc.format, evidenceapp.BytesPayloadSource([]byte(tc.source)))
		if err != nil || v.ID == "" || v.TenantID != "tenant" || v.ReleaseID != "release" || v.ArtifactID != "artifact" || v.Format != tc.format || v.Author != parsed.Author || v.Version != parsed.Version || v.StatementCount != parsed.StatementCount || !reflect.DeepEqual(v.StatusSummary, parsed.StatusSummary) || v.CreatedAt.Nanosecond()%1000 != 0 {
			t.Fatal("VEX response changed", v, parsed, err)
		}
		before := uploads
		if replay := request(tc.key, tc.body, tc.format, tc.native, 201); !reflect.DeepEqual(replay, v) || uploads != before {
			t.Fatal("restart replay normalized VEX", replay, v, uploads)
		}
		request(tc.key, tc.body+" ", tc.format, tc.native, 409)
		var encoded []byte
		if err := pool.QueryRow(ctx, `SELECT to_jsonb(r)FROM vex_import_reports r WHERE vex_document_id=$1`, v.ID).Scan(&encoded); err != nil {
			t.Fatal(err)
		}
		var report domain.VEXImportReport
		if err := json.Unmarshal(encoded, &report); err != nil {
			t.Fatal(err)
		}
		if report.Status != "accepted" || report.EvidenceID != v.EvidenceID || report.StatementCount != v.StatementCount || report.ParserVersion != parsed.ParserVersion || report.DecisionsCreated+report.DecisionsSuperseded != 0 || len(report.InvalidStatements) != len(parsed.InvalidStatements) || len(report.Warnings) == 0 || report.CreatedAt.Nanosecond()%1000 != 0 || report.UpdatedAt.Nanosecond()%1000 != 0 {
			t.Fatal("report changed or decisions created inline", report)
		}
		if err := pool.QueryRow(ctx, `SELECT payload FROM outbox_jobs WHERE kind='parse_vex' AND subject_id=$1`, v.ID).Scan(&encoded); err != nil {
			t.Fatal(err)
		}
		var job map[string]any
		if err := json.Unmarshal(encoded, &job); err != nil {
			t.Fatal(err)
		}
		if job["worker_create_decisions"] != true || job["decision_request_schema"] != evidenceapp.VEXDecisionRequestSchemaVersion || job["actor_id"] != "human" || job["actor_type"] != "human_user" || job["import_report_id"] != report.ID || job["parser_version"] != parsed.ParserVersion || len(job["decision_statements"].([]any)) != parsed.ValidStatementCount {
			t.Fatal("worker decision request changed", job)
		}
		if err := pool.QueryRow(ctx, `SELECT to_jsonb(e)FROM evidence_items e WHERE id=$1`, v.EvidenceID).Scan(&encoded); err != nil {
			t.Fatal(err)
		}
		var item domain.EvidenceItem
		if err := json.Unmarshal(encoded, &item); err != nil {
			t.Fatal(err)
		}
		item.ObservedAt, item.CreatedAt = item.ObservedAt.UTC(), item.CreatedAt.UTC()
		hash, err := (evidenceCanonicalHasher{}).HashEvidence(ctx, domain.EvidenceToContextModel(item))
		if err != nil || hash != item.CanonicalHash || item.PayloadHash != evidenceapp.BytesPayloadSource([]byte(tc.source)).Digest || item.ChainEntryID == "" || item.VerificationStatus != "pending" {
			t.Fatal("VEX durable commitment changed", item, hash, err)
		}
		payload, err := store.GetObjectPayload(ctx, a.TenantID, item.PayloadHash)
		if err != nil || payload.Status != app.ObjectPayloadStaged || payload.Size != int64(len(tc.source)) || payload.Reference() != item.PayloadRef {
			t.Fatal("VEX payload binding changed", payload, err)
		}
		if _, err := objects.Get(ctx, payload.FinalKey); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("VEX finalized before worker", err)
		}
		if tc.native {
			legacyKey := tc.key + "-body-only"
			_, _, err := (app.IdempotencyUnitOfWork{Transactions: store}).WithBodyDigest(ctx, a, "POST", "/v1/vex", legacyKey, item.PayloadHash, func(context.Context, app.Repositories) (int, any, error) { return 201, v, nil })
			if err != nil {
				t.Fatal(err)
			}
			if replay := request(legacyKey, tc.body, tc.format, true, 201); !reflect.DeepEqual(replay, v) || uploads != before {
				t.Fatal("body-only receipt was not replay-only", replay, v, uploads)
			}
			for _, coordinate := range []string{"tenant", "release", "artifact", "format"} {
				foreign := v
				switch coordinate {
				case "tenant":
					foreign.TenantID = "other"
				case "release":
					foreign.ReleaseID = "other"
				case "artifact":
					foreign.ArtifactID = "other"
				case "format":
					foreign.Format = "cyclonedx"
				}
				key := legacyKey + "-" + coordinate
				_, _, err := (app.IdempotencyUnitOfWork{Transactions: store}).WithBodyDigest(ctx, a, "POST", "/v1/vex", key, item.PayloadHash, func(context.Context, app.Repositories) (int, any, error) { return 201, foreign, nil })
				if err != nil {
					t.Fatal(err)
				}
				request(key, tc.body, tc.format, true, 409)
			}
			request(legacyKey, tc.body+" ", tc.format, true, 409)
			auth.actor.ResourceGrants = nil
			request(legacyKey, tc.body, tc.format, true, 403)
			auth.actor = a
		}
		auth.actor.ResourceGrants = nil
		request(tc.key, tc.body, tc.format, tc.native, 403)
		auth.actor = a
		auth.actor.TenantID = "other"
		request(tc.key+"-foreign", tc.body, tc.format, tc.native, 404)
		auth.actor = a
		if uploads != before {
			t.Fatal("denied replay normalized VEX")
		}
	}
	expected := [7]int{base[0] + 3, base[1] + 3, base[2] + 3, base[3] + 6, base[4] + 6, base[5] + 3, base[6]}
	if counts() != expected || objects.stages != 3 {
		t.Fatal("replay/denial added effects", counts(), objects.stages)
	}
	for i, bad := range []string{`null`, `{"release_id":null,"payload":{}}`, `{"release_id":"release","artifact_id":null,"payload":{}}`, `{"release_id":"release","payload":null}`, strings.Replace(wrapped, `"release"`, `"bad\u0000"`, 1), strings.Replace(wrapped, `"release"`, `"`+strings.Repeat("x", 1025)+`"`, 1), strings.Replace(wrapped, `"author":`, `"author":"bad\u0000","author":`, 1)} {
		request(fmt.Sprintf("invalid-%d", i), bad, "openvex", false, 400)
	}
	request("missing-parent", `{"release_id":"missing","payload":{}}`, "openvex", false, 404)
	if counts() != expected || objects.stages != 3 {
		t.Fatal("invalid VEX reached staging", counts(), objects.stages)
	}
	before := uploads
	if _, err := pool.Exec(ctx, `UPDATE releases SET product_id='other-product' WHERE id='release'`); err != nil {
		t.Fatal(err)
	}
	request("openvex", wrapped, "openvex", false, 404)
	if _, err := pool.Exec(ctx, `INSERT INTO products(id,tenant_id,name,slug)VALUES('vex-sibling','tenant','Sibling','vex-sibling');UPDATE releases SET product_id='vex-sibling' WHERE id='release'`); err != nil {
		t.Fatal(err)
	}
	request("openvex", wrapped, "openvex", false, 403)
	if uploads != before || counts() != expected {
		t.Fatal("stale VEX parent replay normalized", uploads, counts())
	}
	if _, err := pool.Exec(ctx, `UPDATE releases SET product_id='product' WHERE id='release'`); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"object_payloads", "outbox_jobs", "audit_chain_entries", "evidence_items", "vex_documents", "vex_import_reports", "idempotency_records", "commit"} {
		table, op := stage, "INSERT"
		if stage == "idempotency_records" {
			op = "UPDATE"
		}
		trigger := `CREATE TRIGGER reject_vex_upload BEFORE ` + op + ` ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_vex_upload()`
		if stage == "commit" {
			table = "vex_documents"
			trigger = `CREATE CONSTRAINT TRIGGER reject_vex_upload AFTER INSERT ON vex_documents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_vex_upload()`
		}
		if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_vex_upload()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private VEX SQL';END$$;`+trigger); err != nil {
			t.Fatal(err)
		}
		request("fault-"+stage, wrapped, "openvex", false, 500)
		if counts() != expected {
			t.Fatal("partial VEX transaction effects", stage, counts())
		}
		if _, err := pool.Exec(ctx, `DROP TRIGGER reject_vex_upload ON `+table+`;DROP FUNCTION reject_vex_upload()`); err != nil {
			t.Fatal(err)
		}
	}
	request("fault-commit", wrapped, "openvex", false, 201)
	if counts() != [7]int{base[0] + 4, base[1] + 4, base[2] + 4, base[3] + 8, base[4] + 7, base[5] + 3, base[6]} {
		t.Fatal("commit retry duplicated effects", counts())
	}
	digest := evidenceapp.BytesPayloadSource([]byte(wrappedSource)).Digest
	if err := app.FinalizeStagedObjectPayload(ctx, store, objects, a.TenantID, digest); err != nil {
		t.Fatal(err)
	}
	payload, err := store.GetObjectPayload(ctx, a.TenantID, digest)
	if err != nil {
		t.Fatal(err)
	}
	object, err := objects.Get(ctx, payload.FinalKey)
	if err != nil || !bytes.Equal(object.Bytes, []byte(wrappedSource)) || object.TenantID != a.TenantID || object.Digest != digest {
		t.Fatal("VEX finalized bytes changed", object, err)
	}
	if counts()[6] != base[6] {
		t.Fatal("payload finalization created decisions")
	}
}

func TestPostgresVEXIngestionJoinsPendingParentsAndOuterRollback(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	at := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		return repos.Identity.InsertTenant(ctx, domain.Tenant{ID: "tenant", Name: "Pending VEX", CreatedAt: at})
	}); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildVEXIngestionCommands(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"evidence:write"}}
	raw, err := os.ReadFile("../../app/parsers/vex/testdata/openvex/openvex-spec-minimal.json")
	if err != nil {
		t.Fatal(err)
	}
	source := evidenceapp.BytesPayloadSource(raw)
	counts := func() [9]int {
		t.Helper()
		var n [9]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM products),(SELECT count(*)FROM releases),(SELECT count(*)FROM artifacts),(SELECT count(*)FROM evidence_items),(SELECT count(*)FROM vex_documents),(SELECT count(*)FROM vex_import_reports),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM vulnerability_decisions)`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5], &n[6], &n[7], &n[8]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	rollback := errors.New("outer VEX command rolled back")
	for _, key := range []string{"rollback", "commit"} {
		_, _, err := (app.IdempotencyUnitOfWork{Transactions: store}).WithBody(ctx, a, "POST", "/compound-vex", key, []byte(key), func(txCtx context.Context, repos app.Repositories) (int, any, error) {
			if err := repos.ReleaseCatalog.InsertProduct(txCtx, domain.Product{ID: key + "-product", TenantID: "tenant", Name: key, Slug: key, CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			if err := repos.ReleaseCatalog.InsertRelease(txCtx, domain.Release{ID: key + "-release", TenantID: "tenant", ProductID: key + "-product", Version: "1", State: "draft", Revision: 1, CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			if err := repos.ReleaseCatalog.InsertArtifact(txCtx, domain.Artifact{ID: key + "-artifact", TenantID: "tenant", Name: key, MediaType: "application/json", Digest: "sha256:" + strings.Repeat("a", 64), Size: 1, CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			in := evidenceapp.VEXIngestionInput{ReleaseID: key + "-release", ArtifactID: key + "-artifact", Format: "openvex"}
			if err := commands.AuthorizeUploadVEX(txCtx, a, in); err != nil {
				return 0, nil, err
			}
			v, err := commands.UploadVEXPayload(txCtx, a, in, source)
			if err != nil {
				return 0, nil, err
			}
			if v.StatementCount != 1 || v.StatusSummary["fixed"] != 1 {
				t.Fatal("missing-object mode lost VEX projection", v)
			}
			if key == "rollback" {
				return 0, nil, rollback
			}
			return 201, domain.VEXDocumentFromContext(v), nil
		})
		if key == "rollback" {
			if !errors.Is(err, rollback) || counts() != [9]int{} {
				t.Fatal("VEX escaped outer rollback", counts(), err)
			}
		} else if err != nil || counts() != [9]int{1, 1, 1, 1, 1, 1, 2, 1, 0} {
			t.Fatal("pending VEX parents unavailable or non-atomic", counts(), err)
		}
	}
}
