package wiring

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type vexPreviewSnapshotHook struct {
	*postgres.Store
	hook func()
}

func (s vexPreviewSnapshotHook) ReadVEXPreviewSnapshot(ctx context.Context, tenant, release, artifact string, prepare evidencequery.VEXPreviewPreparation) (evidencequery.VEXPreviewSnapshot, error) {
	return s.Store.ReadVEXPreviewSnapshot(ctx, tenant, release, artifact, func(refs application.ResourceReferences, auth application.Authorizer) ([]string, error) {
		ids, err := prepare(refs, auth)
		if err == nil {
			s.hook()
		}
		return ids, err
	})
}

func TestPostgresVEXPreviewsUseBoundedReadOnlySnapshotsWithoutLedger(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	findings := `[{"id":"finding","vulnerability":"CVE-TEST","component":"pkg:generic/api@1","severity":"high","state":"open"}]`
	exec(`UPDATE vulnerability_scans SET findings='` + findings + `';UPDATE evidence_items SET metadata=jsonb_build_object('unrelated',repeat('x',9000000)) WHERE id='ev-scan';UPDATE vulnerability_decisions SET internal_notes=repeat('n',9000000)`)
	a := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"evidence:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"evidence:read"}}}}
	auth := &attestationHTTPActor{actor: a}
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil || opts.VEXPreviewQuery == nil {
		t.Fatal("VEX preview is Ledger-backed", err)
	}
	opts.Authenticator = auth
	noReload := &decisionHTTPNoReloadStore{}
	ledger, err := app.NewLedgerWithContext(ctx, app.Config{Store: noReload, UnitOfWork: store})
	if err != nil {
		t.Fatal(err)
	}
	server, err := httpapi.NewServerWithOptionsContext(ctx, ledger, opts)
	if err != nil {
		t.Fatal(err)
	}
	counts := func() [7]int {
		t.Helper()
		var n [7]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM evidence_items),(SELECT count(*)FROM vex_documents),(SELECT count(*)FROM vex_import_reports),(SELECT count(*)FROM vulnerability_decisions),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM idempotency_records)`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5], &n[6]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	base := counts()
	request := func(format, body string, want int) domain.VEXImportPreview {
		t.Helper()
		path := "/v1/vex/preview"
		if format == "cyclonedx" {
			path = "/v1/vex/cyclonedx/preview"
		}
		r := httptest.NewRequest("POST", path, strings.NewReader(body)).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer isolated-auth")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private") {
			t.Fatal(w.Code, w.Body.String(), noReload.loads)
		}
		if want >= 400 {
			return domain.VEXImportPreview{}
		}
		var out struct {
			Data domain.VEXImportPreview `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Data
	}
	openPayload := `{"@context":"https://openvex.dev/ns/v0.2.0","author":"author","timestamp":"2026-10-03T12:00:00Z","statements":[{"vulnerability":{"name":"CVE-TEST"},"products":[{"@id":"pkg:generic/api@1"}],"status":"fixed"},{"vulnerability":{"name":"CVE-MISSING"},"products":[{"@id":"pkg:missing"}],"status":"affected"}]}`
	cdxPayload := `{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[{"id":"CVE-TEST","affects":[{"ref":"pkg:generic/api@1"}],"analysis":{"state":"resolved"}},{"id":"CVE-MISSING","analysis":{"state":"resolved"}},{"analysis":{"state":"resolved"}}]}`
	wrapped := func(payload string) string {
		return `{"release_id":"release","artifact_id":"artifact","payload":` + payload + `}`
	}
	for _, tc := range []struct {
		format, payload string
		count           int
	}{{"openvex", openPayload, 2}, {"cyclonedx", cdxPayload, 3}} {
		for i := 0; i < 2; i++ {
			out := request(tc.format, wrapped(tc.payload), 200)
			if !out.Advisory || out.Format != tc.format || out.StatementCount != tc.count || out.DecisionsWouldCreate != 1 || out.DecisionsWouldSupersede != 1 || len(out.MappingFailures) != 1 || out.MappingFailures[0].StatementIndex != 2 || out.MappingFailures[0].Code != "finding_not_found" || len(out.Assumptions) != 2 || len(out.Limitations) != 2 || out.GeneratedAt.Nanosecond()%1000 != 0 {
				t.Fatal("preview changed", out)
			}
			if tc.format == "cyclonedx" && (len(out.InvalidStatements) != 1 || out.InvalidStatements[0].StatementIndex != 3) {
				t.Fatal("invalid statement indexes changed", out)
			}
		}
	}
	if out := request("openvex", wrapped(strings.ReplaceAll(openPayload, "CVE-TEST", "CVE-MISSING")), 200); out.DecisionsWouldCreate != 0 || out.DecisionsWouldSupersede != 0 || len(out.MappingFailures) != 2 {
		t.Fatal("empty candidate preview changed", out)
	}
	auth.actor.ResourceGrants = nil
	request("openvex", wrapped(openPayload), 403)
	auth.actor = a
	auth.actor.TenantID = "other"
	request("openvex", wrapped(`{}`), 404)
	auth.actor = a
	for _, bad := range []string{`null`, `{"release_id":null,"payload":{}}`, `{"release_id":"release","artifact_id":null,"payload":{}}`, `{"release_id":"release","payload":null}`, wrapped(`{}`), strings.Replace(wrapped(openPayload), `"release"`, `"bad\u0000"`, 1)} {
		request("openvex", bad, 400)
	}
	exec(`INSERT INTO artifacts(id,tenant_id,name,media_type,digest,size)VALUES('unlinked','tenant','Hidden','application/json','sha256:a',1)`)
	request("openvex", strings.Replace(wrapped(openPayload), `"artifact"`, `"unlinked"`, 1), 403)
	exec(`UPDATE vulnerability_scans SET findings='[{"vulnerability":"CVE-TEST"}]'`)
	request("openvex", wrapped(openPayload), 409)
	exec(`UPDATE vulnerability_scans SET findings='` + findings + `'`)
	exec(`UPDATE vulnerability_scans SET findings=(SELECT jsonb_agg(jsonb_build_object('id','finding-'||n,'vulnerability','CVE-TEST','component','pkg:generic/api@1'))FROM generate_series(1,4096)n)`)
	edge, err := store.ReadVEXPreviewSnapshot(ctx, "tenant", "release", "", func(application.ResourceReferences, application.Authorizer) ([]string, error) {
		return []string{"CVE-TEST"}, nil
	})
	if err != nil || len(edge.Findings) != 4096 {
		t.Fatal("exact candidate limit changed", len(edge.Findings), err)
	}
	exec(`UPDATE vulnerability_scans SET findings='` + findings + `'`)
	exec(`INSERT INTO vulnerability_scans SELECT(jsonb_populate_record(NULL::vulnerability_scans,to_jsonb(s)||jsonb_build_object('id','preview-overflow-'||n))).*FROM vulnerability_scans s CROSS JOIN generate_series(1,4096)n WHERE s.id='scan'`)
	request("openvex", wrapped(openPayload), 409)
	exec(`DELETE FROM vulnerability_scans WHERE id LIKE 'preview-overflow-%'`)
	exec(`UPDATE vulnerability_scans SET findings=(SELECT jsonb_agg(jsonb_build_object('id','large-'||n,'vulnerability','CVE-TEST','component',repeat('x',1048576)))FROM generate_series(1,9)n)`)
	request("openvex", wrapped(openPayload), 409)
	exec(`UPDATE vulnerability_scans SET findings='` + findings + `'`)
	for _, bad := range []string{`UPDATE vulnerability_scans SET evidence_id='ev-sbom'`, `UPDATE vulnerability_scans SET findings='[{"id":"finding","vulnerability":"CVE-TEST","component":1}]'`, `UPDATE vulnerability_scans SET findings=jsonb_build_array(jsonb_build_object('id','finding','vulnerability','CVE-TEST','component',repeat('x',1048577)))`, `UPDATE vulnerability_scans SET findings=(SELECT jsonb_agg(jsonb_build_object('id','finding-'||n,'vulnerability','CVE-TEST','component','pkg:generic/api@1'))FROM generate_series(1,4097)n)`} {
		exec(bad)
		want := 409
		if strings.Contains(bad, "evidence_id") {
			want = 404
		}
		request("openvex", wrapped(openPayload), want)
		exec(`UPDATE vulnerability_scans SET evidence_id='ev-scan',findings='` + findings + `'`)
	}
	query, err := BuildVEXPreviewQuery(vexPreviewSnapshotHook{Store: store, hook: func() {
		exec(`UPDATE vulnerability_scans SET findings=findings||jsonb_build_array(jsonb_build_object('id','second','vulnerability','CVE-TEST','component','pkg:generic/api@1'))`)
	}})
	if err != nil {
		t.Fatal(err)
	}
	in := evidencequery.VEXPreviewInput{ReleaseID: "release", ArtifactID: "artifact", Format: "openvex", Payload: []byte(openPayload)}
	out, err := query.PreviewVEXImport(ctx, a, in)
	if err != nil || out.DecisionsWouldCreate != 1 || out.DecisionsWouldSupersede != 1 {
		t.Fatal("mixed snapshots", out, err)
	}
	fresh := request("openvex", wrapped(openPayload), 200)
	if fresh.DecisionsWouldCreate != 0 || fresh.DecisionsWouldSupersede != 0 || len(fresh.MappingFailures) != 2 || fresh.MappingFailures[0].Code != "ambiguous_finding" {
		t.Fatal("fresh snapshot missed changes", fresh)
	}
	if counts() != base {
		t.Fatal("read-only previews persisted side effects", base, counts())
	}
}
