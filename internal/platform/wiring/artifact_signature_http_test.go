package wiring

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func seedArtifactSignatureHTTP(t *testing.T, p *pgxpool.Pool) *countedSignatureStager {
	t.Helper()
	seedProviderReceiptHTTP(t, p)
	for _, sql := range []string{
		`INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant','Product','product')`,
		`INSERT INTO projects(id,tenant_id,product_id,name)VALUES('project','tenant','product','Project')`,
		`INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('release','tenant','product','1','draft')`,
		`INSERT INTO artifacts(id,tenant_id,name,media_type,digest,size)VALUES('artifact','tenant','Artifact','application/json','sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',1),('foreign','other','Foreign','application/json','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',1)`,
		`INSERT INTO build_runs(id,tenant_id,project_id,release_id,provider,commit_sha,status,started_at,outputs,schema_version)VALUES('build','tenant','project','release','generic_ci','1111111111111111111111111111111111111111','passed',now(),'[{"artifact_id":"artifact","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]','build-run.v1.0.0')`,
	} {
		if _, err := p.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &countedSignatureStager{Store: fs}
}

func artifactSignatureHTTP(t *testing.T, store *postgres.Store, objects app.ObjectStore, key, body string, want int) string {
	t.Helper()
	opts := subjectVerificationOptions(t, store, objects)
	if opts.ArtifactSignatureCommands == nil {
		t.Fatal("missing native signature creation composition")
	}
	noReload := &decisionHTTPNoReloadStore{}
	l, err := app.NewLedgerWithContext(t.Context(), app.Config{Store: noReload, UnitOfWork: store})
	if err != nil {
		t.Fatal(err)
	}
	s, err := httpapi.NewServerWithOptionsContext(t.Context(), l, opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/artifact-signatures", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private-") || want != 201 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("signature create status=%d want=%d loads=%d body=%s", w.Code, want, noReload.loads, w.Body.String())
	}
	if want == 201 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("missing signature replay key")
	}
	return w.Body.String()
}

func artifactSignatureHTTPCounts(t *testing.T, p *pgxpool.Pool) [6]int {
	t.Helper()
	var v [6]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM artifact_signatures),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM object_payloads),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&v[0], &v[1], &v[2], &v[3], &v[4], &v[5]); err != nil {
		t.Fatal(err)
	}
	return v
}

const artifactSignatureHTTPBody = `{"artifact_id":"artifact","algorithm":"cosign","key_id":"public-key","signature":"opaque-recorded","payload":{"bundle":"opaque","size":9007199254740993},"payload_media_type":"application/json"}`

func TestPostgresArtifactSignatureHTTPRestartReplayAndCurrentGrants(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	objects := seedArtifactSignatureHTTP(t, p)
	one := artifactSignatureHTTP(t, store, objects, "record", artifactSignatureHTTPBody, 201)
	var e struct {
		Data domain.ArtifactSignature `json:"data"`
	}
	if err := json.Unmarshal([]byte(one), &e); err != nil {
		t.Fatal(err)
	}
	v := e.Data
	if v.VerificationStatus != "recorded" || v.Algorithm != "cosign" || v.Signature != "opaque-recorded" || v.KeyID != "public-key" || v.PayloadRef == "" || v.PayloadHash == "" || v.SubjectDigest != "sha256:"+strings.Repeat("a", 64) || objects.stages != 1 || artifactSignatureHTTPCounts(t, p) != [6]int{1, 1, 1, 1, 1, 0} {
		t.Fatal("signature recording/staging contract changed", one, objects.stages)
	}
	payload, err := store.GetObjectPayload(t.Context(), "tenant", v.PayloadHash)
	if err != nil || payload.Status != app.ObjectPayloadStaged || payload.Reference() != v.PayloadRef {
		t.Fatal("signature payload lifecycle changed", payload, err)
	}
	var actor, entry, job, subject, replayRef string
	if err := p.QueryRow(t.Context(), `SELECT a.actor_id,a.entry_type,o.kind,o.subject_id,i.response->>'payload_ref' FROM audit_chain_entries a JOIN outbox_jobs o ON o.tenant_id=a.tenant_id AND o.kind='finalize_payload' JOIN idempotency_records i ON i.tenant_id=a.tenant_id AND i.idempotency_key='record'WHERE a.subject_id=$1`, v.ID).Scan(&actor, &entry, &job, &subject, &replayRef); err != nil || actor != "user" || entry != "artifact_signature.created" || job != "finalize_payload" || subject != v.PayloadHash || replayRef != v.PayloadRef {
		t.Fatal("signature caller/audit/job/replay binding changed", err)
	}
	assertRetentionHTTPReplay(t, one, artifactSignatureHTTP(t, store, nil, "record", artifactSignatureHTTPBody, 201))
	if err := app.FinalizeStagedObjectPayload(t.Context(), store, objects, "tenant", v.PayloadHash); err != nil {
		t.Fatal(err)
	}
	object, err := objects.Get(t.Context(), payload.FinalKey)
	if err != nil || string(object.Bytes) != `{"bundle":"opaque","size":9007199254740993}` {
		t.Fatal("staging changed exact signed payload bytes", string(object.Bytes), err)
	}
	if _, err := p.Exec(t.Context(), `UPDATE artifacts SET name=repeat('private-',1200000),digest=repeat('x',1025)WHERE id='artifact'`); err != nil {
		t.Fatal(err)
	}
	assertRetentionHTTPReplay(t, one, artifactSignatureHTTP(t, store, nil, "record", artifactSignatureHTTPBody, 201))
	artifactSignatureHTTP(t, store, objects, "oversized-current", artifactSignatureHTTPBody, 409)
	artifactSignatureHTTP(t, store, nil, "record", artifactSignatureHTTPBody+" ", 409)
	if _, err := p.Exec(t.Context(), `UPDATE artifacts SET digest=$1 WHERE id='artifact'`, "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	for _, grant := range []struct{ kind, id string }{{"product", "product"}, {"project", "project"}, {"release", "release"}, {"tenant", "tenant"}} {
		if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type=$1,resource_id=$2 WHERE id='grant'`, grant.kind, grant.id); err != nil {
			t.Fatal(err)
		}
		assertRetentionHTTPReplay(t, one, artifactSignatureHTTP(t, store, nil, "record", artifactSignatureHTTPBody, 201))
		if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_id='unrelated'WHERE id='grant'`); err != nil {
			t.Fatal(err)
		}
		artifactSignatureHTTP(t, store, nil, "record", artifactSignatureHTTPBody, 403)
		artifactSignatureHTTP(t, store, objects, "denied-fresh", artifactSignatureHTTPBody, 403)
	}
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='product',resource_id='product'WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"products", "projects", "releases"} {
		if _, err := p.Exec(t.Context(), "UPDATE "+table+" SET tenant_id='other'"); err != nil {
			t.Fatal(err)
		}
		artifactSignatureHTTP(t, store, nil, "record", artifactSignatureHTTPBody, 403)
		if _, err := p.Exec(t.Context(), "UPDATE "+table+" SET tenant_id='tenant'"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Exec(t.Context(), `UPDATE build_runs SET outputs='[]'WHERE id='build'`); err != nil {
		t.Fatal(err)
	}
	artifactSignatureHTTP(t, store, nil, "record", artifactSignatureHTTPBody, 403)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant'WHERE id='grant';UPDATE artifacts SET tenant_id='other'WHERE id='artifact'`); err != nil {
		t.Fatal(err)
	}
	artifactSignatureHTTP(t, store, nil, "record", artifactSignatureHTTPBody, 404)
	if _, err := p.Exec(t.Context(), `UPDATE artifacts SET tenant_id='tenant'WHERE id='artifact';UPDATE role_bindings SET role='viewer'WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	artifactSignatureHTTP(t, store, nil, "record", artifactSignatureHTTPBody, 403)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET role='tenant_admin'WHERE id='grant';UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`); err != nil {
		t.Fatal(err)
	}
	artifactSignatureHTTP(t, store, nil, "record", artifactSignatureHTTPBody, 401)
	if objects.stages != 1 || artifactSignatureHTTPCounts(t, p) != [6]int{1, 1, 1, 1, 1, 1} {
		t.Fatal("replay/denial staged payload or changed effects", objects.stages, artifactSignatureHTTPCounts(t, p))
	}
}

func TestPostgresArtifactSignatureHTTPRollbackAndRecovery(t *testing.T) {
	for _, stage := range []string{"signature", "payload", "audit", "outbox", "replay", "commit"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			objects := seedArtifactSignatureHTTP(t, p)
			table := map[string]string{"signature": "artifact_signatures", "payload": "object_payloads", "audit": "audit_chain_entries", "outbox": "outbox_jobs", "replay": "idempotency_records", "commit": "audit_chain_entries"}[stage]
			trigger := fmt.Sprintf("CREATE TRIGGER reject_signature_http BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_signature_http()", table)
			if stage == "replay" {
				trigger = `CREATE TRIGGER reject_signature_http BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_signature_http()`
			}
			if stage == "commit" {
				trigger = `CREATE CONSTRAINT TRIGGER reject_signature_http AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_signature_http()`
			}
			if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_signature_http()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-signature-write-failure';END$$;`+trigger); err != nil {
				t.Fatal(err)
			}
			artifactSignatureHTTP(t, store, objects, "failed", artifactSignatureHTTPBody, 500)
			want := [6]int{}
			if stage != "replay" && stage != "commit" {
				want[5] = 1
			}
			if artifactSignatureHTTPCounts(t, p) != want || objects.stages != 1 {
				t.Fatal("partial signature success", artifactSignatureHTTPCounts(t, p), objects.stages)
			}
			if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_signature_http ON "+table); err != nil {
				t.Fatal(err)
			}
			key := "failed"
			if want[5] == 1 {
				artifactSignatureHTTP(t, store, nil, key, artifactSignatureHTTPBody, 409)
				if objects.stages != 1 {
					t.Fatal("failed key restaged payload")
				}
				key = "recovered"
			}
			artifactSignatureHTTP(t, store, objects, key, artifactSignatureHTTPBody, 201)
			want[0], want[1], want[2], want[3], want[4] = 1, 1, 1, 1, 1
			if artifactSignatureHTTPCounts(t, p) != want || objects.stages != 2 {
				t.Fatal("recovered signature not atomic", artifactSignatureHTTPCounts(t, p), objects.stages)
			}
		})
	}
}
