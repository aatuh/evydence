package wiring

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func seedNativeControlEvidence(t *testing.T, store *postgres.Store, p *pgxpool.Pool) {
	t.Helper()
	seedProviderReceiptHTTP(t, p)
	seedControlEvidenceSubjects(t, t.Context(), store, p)
}

func controlEvidenceNativeHTTP(t *testing.T, store *postgres.Store, key, body string, want int) string {
	t.Helper()
	opts := subjectVerificationOptions(t, store, nil)
	if opts.ControlEvidenceCommands == nil {
		t.Fatal("missing native linking composition")
	}
	noReload := newAggregateLoadCanary(t, t.Context(), store)
	s, err := newNativeHTTPFixture(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/controls/control/evidence", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || !noReload.Intact(t.Context()) || strings.Contains(w.Body.String(), "private-") || want != 201 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("native link status=%d want=%d canary=%t: %s", w.Code, want, noReload.Intact(t.Context()), w.Body.String())
	}
	if want == 201 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("link lost replay key")
	}
	if want >= 400 && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatal("link lost problem contract")
	}
	return w.Body.String()
}

func controlEvidenceNativeCounts(t *testing.T, p *pgxpool.Pool) [5]int {
	t.Helper()
	var v [5]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM control_evidence),(SELECT count(*)FROM audit_chain_entries WHERE entry_type='control_evidence.linked'),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&v[0], &v[1], &v[2], &v[3], &v[4]); err != nil {
		t.Fatal(err)
	}
	return v
}

func nativeControlEvidenceBody(kind, id string) string {
	return fmt.Sprintf(`{"evidence_type":"sbom","subject_type":%q,"subject_id":%q,"product_id":"product","confidence":"high","notes":"reviewed"}`, kind, id)
}

func TestPostgresControlEvidenceNativeHTTPEverySubjectRestartReplayAndCurrentGrants(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedNativeControlEvidence(t, store, p)
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='product',resource_id='product'WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	subjects := []struct{ kind, id string }{{"evidence", "ev-sbom"}, {"evidence_item", "ev-sbom"}, {"product", "product"}, {"release", "release"}, {"artifact", "artifact"}, {"sbom", "sbom"}, {"vulnerability_scan", "scan"}, {"vex", "vex"}, {"vulnerability_decision", "decision"}, {"finding", "finding"}, {"vulnerability_finding", "finding"}, {"exception", "exception"}, {"build", "build"}, {"build_attestation", "attestation"}, {"openapi_contract", "contract"}, {"release_bundle", "bundle"}}
	first := map[string]string{}
	for i, tc := range subjects {
		body := nativeControlEvidenceBody(tc.kind, tc.id)
		one := controlEvidenceNativeHTTP(t, store, tc.kind, body, 201)
		first[tc.kind] = one
		var e struct {
			Data domain.ControlEvidence `json:"data"`
		}
		if err := json.Unmarshal([]byte(one), &e); err != nil || e.Data.ID == "" || e.Data.TenantID != "tenant" || e.Data.ControlID != "control" || e.Data.EvidenceType != "sbom" || e.Data.SubjectType != tc.kind || e.Data.SubjectID != tc.id || e.Data.ProductID != "product" || e.Data.ReleaseID != "" || e.Data.Confidence != "high" || e.Data.Notes != "reviewed" || e.Data.SchemaVersion != domain.ControlEvidenceSchemaVersion || e.Data.CreatedAt.IsZero() || e.Data.CreatedAt.Nanosecond()%1000 != 0 {
			t.Fatal("native link changed DTO", one, err)
		}
		assertRetentionHTTPReplay(t, one, controlEvidenceNativeHTTP(t, store, tc.kind, body, 201))
		controlEvidenceNativeHTTP(t, store, tc.kind, body+" ", 409)
		duplicate := strings.ReplaceAll(strings.ReplaceAll(body, "reviewed", "changed"), `"high"`, `"low"`)
		assertRetentionHTTPReplay(t, one, controlEvidenceNativeHTTP(t, store, tc.kind+"-duplicate", duplicate, 201))
		if got := controlEvidenceNativeCounts(t, p); got != [5]int{i + 1, i + 1, 0, 2 * (i + 1), 0} {
			t.Fatal("link/natural duplicate repeated effects", got)
		}
	}
	var principals int
	if err := p.QueryRow(t.Context(), `SELECT count(*)FROM audit_chain_entries WHERE entry_type='control_evidence.linked'AND actor_type='human_user'AND actor_id='user'`).Scan(&principals); err != nil || principals != len(subjects) {
		t.Fatal("link audit lost caller", principals, err)
	}
	// Synthetic pre-upgrade replay tests exact public JSON number preservation,
	// without attributing another business effect to that historical fixture.
	opts := subjectVerificationOptions(t, store, nil)
	a, err := opts.Authenticator.Authenticate(t.Context(), "evysso_receipt_fixture")
	if err != nil {
		t.Fatal(err)
	}
	hBody := nativeControlEvidenceBody("product", "product")
	in := riskapp.LinkControlEvidenceInput{EvidenceType: "sbom", SubjectType: "product", SubjectID: "product", ProductID: "product", Confidence: "high", Notes: "reviewed"}
	if _, _, err := opts.DurableCommandExecutor.WithBody(t.Context(), a, "POST", "/v1/controls/control/evidence", "historical", []byte(hBody), func(ctx context.Context) error {
		return opts.ControlEvidenceCommands.AuthorizeControlEvidenceLink(ctx, a, "control", in)
	}, func(context.Context) (int, any, error) {
		return 201, map[string]any{"id": "historical", "exact_number": json.Number("9007199254740993")}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(t.Context(), `UPDATE control_evidence SET notes=repeat('private-',1200000);UPDATE control_frameworks SET name=repeat('private-',1200000),description=repeat('private-',1200000);UPDATE security_controls SET title=repeat('private-',1200000),objective=repeat('private-',1200000);UPDATE evidence_items SET title=repeat('private-',1200000)`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range subjects {
		assertRetentionHTTPReplay(t, first[tc.kind], controlEvidenceNativeHTTP(t, store, tc.kind, nativeControlEvidenceBody(tc.kind, tc.id), 201))
	}
	if out := controlEvidenceNativeHTTP(t, store, "historical", hBody, 201); !strings.Contains(out, "9007199254740993") {
		t.Fatal("historical exact number rounded", out)
	}
	for _, grant := range []struct{ kind, id string }{{"project", "project"}, {"release", "release"}, {"tenant", "tenant"}, {"product", "unrelated"}} {
		if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type=$1,resource_id=$2 WHERE id='grant'`, grant.kind, grant.id); err != nil {
			t.Fatal(err)
		}
		for _, tc := range subjects {
			allowed := grant.kind == "tenant" || grant.kind == "project" && (tc.kind == "artifact" || tc.kind == "build" || tc.kind == "build_attestation") || grant.kind == "release" && tc.kind != "product"
			want := 403
			if allowed {
				want = 201
			}
			out := controlEvidenceNativeHTTP(t, store, tc.kind, nativeControlEvidenceBody(tc.kind, tc.id), want)
			if allowed {
				assertRetentionHTTPReplay(t, first[tc.kind], out)
			}
		}
	}
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant'WHERE id='grant';UPDATE control_frameworks SET tenant_id='other'WHERE id='fw'`); err != nil {
		t.Fatal(err)
	}
	controlEvidenceNativeHTTP(t, store, "product", hBody, 404)
	if _, err := p.Exec(t.Context(), `UPDATE control_frameworks SET tenant_id='tenant'WHERE id='fw';UPDATE security_controls SET tenant_id='other'WHERE id='control'`); err != nil {
		t.Fatal(err)
	}
	controlEvidenceNativeHTTP(t, store, "product", hBody, 404)
	if _, err := p.Exec(t.Context(), `UPDATE security_controls SET tenant_id='tenant'WHERE id='control';UPDATE products SET tenant_id='other'WHERE id='product'`); err != nil {
		t.Fatal(err)
	}
	controlEvidenceNativeHTTP(t, store, "product", hBody, 404)
	if _, err := p.Exec(t.Context(), `UPDATE products SET tenant_id='tenant'WHERE id='product';UPDATE role_bindings SET role='viewer'WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	controlEvidenceNativeHTTP(t, store, "product", hBody, 403)
	if _, err := p.Exec(t.Context(), `DELETE FROM role_bindings WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	controlEvidenceNativeHTTP(t, store, "product", hBody, 403)
	if _, err := p.Exec(t.Context(), `UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`); err != nil {
		t.Fatal(err)
	}
	controlEvidenceNativeHTTP(t, store, "product", hBody, 401)
	if got := controlEvidenceNativeCounts(t, p); got != [5]int{len(subjects), len(subjects), 0, 2*len(subjects) + 1, 0} {
		t.Fatal("replay or current denial changed effects", got)
	}
}

func TestPostgresControlEvidenceNativeHTTPRollbackAndRecovery(t *testing.T) {
	for _, stage := range []string{"link", "audit", "replay", "commit"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedNativeControlEvidence(t, store, p)
			table := map[string]string{"link": "control_evidence", "audit": "audit_chain_entries", "replay": "idempotency_records", "commit": "audit_chain_entries"}[stage]
			trigger := fmt.Sprintf("CREATE TRIGGER reject_link_native BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_link_native()", table)
			if stage == "replay" {
				trigger = `CREATE TRIGGER reject_link_native BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_link_native()`
			}
			if stage == "commit" {
				trigger = `CREATE CONSTRAINT TRIGGER reject_link_native AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_link_native()`
			}
			if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_link_native()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-link-write-failure';END$$;`+trigger); err != nil {
				t.Fatal(err)
			}
			body := nativeControlEvidenceBody("product", "product")
			controlEvidenceNativeHTTP(t, store, "failed", body, 500)
			want := [5]int{}
			if stage == "link" || stage == "audit" {
				want[4] = 1
			}
			if got := controlEvidenceNativeCounts(t, p); got != want {
				t.Fatal("link partially committed", got, want)
			}
			if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_link_native ON "+table); err != nil {
				t.Fatal(err)
			}
			key := "failed"
			if want[4] == 1 {
				controlEvidenceNativeHTTP(t, store, key, body, 409)
				key = "recovered"
			}
			one := controlEvidenceNativeHTTP(t, store, key, body, 201)
			assertRetentionHTTPReplay(t, one, controlEvidenceNativeHTTP(t, store, key, body, 201))
			want[0], want[1], want[3] = 1, 1, 1
			if got := controlEvidenceNativeCounts(t, p); got != want {
				t.Fatal("link recovery changed effects", got, want)
			}
		})
	}
}
