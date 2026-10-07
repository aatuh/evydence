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
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func controlTemplateNativeHTTP(t *testing.T, store *postgres.Store, slug, key, body string, want int) string {
	t.Helper()
	opts := subjectVerificationOptions(t, store, nil)
	if opts.ControlTemplateCommands == nil {
		t.Fatal("missing native template composition")
	}
	noReload := newAggregateLoadCanary(t, t.Context(), store)
	s, err := newNativeHTTPFixture(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/control-framework-template-packs/"+slug+"/install", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || !noReload.Intact(t.Context()) || strings.Contains(w.Body.String(), "private-") || want != 201 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("native template status=%d want=%d canary=%t: %s", w.Code, want, noReload.Intact(t.Context()), w.Body.String())
	}
	if want == 201 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("template lost replay key")
	}
	if want >= 400 && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatal("template lost problem contract")
	}
	return w.Body.String()
}

func controlTemplateNativeCounts(t *testing.T, p *pgxpool.Pool) [6]int {
	t.Helper()
	var v [6]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM control_frameworks),(SELECT count(*)FROM security_controls),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&v[0], &v[1], &v[2], &v[3], &v[4], &v[5]); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestPostgresControlTemplateNativeHTTPAllPacksRestartReplayAndCurrentAuthority(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	first := map[string]string{}
	totalControls := 0
	packs := riskdomain.BuiltinTemplatePacks()
	for i, pack := range packs {
		body := ""
		if i%2 != 0 {
			body = "{}"
		}
		one := controlTemplateNativeHTTP(t, store, pack.Slug, pack.Slug, body, 201)
		first[pack.Slug] = one
		var e struct {
			Data domain.ControlFramework `json:"data"`
		}
		if err := json.Unmarshal([]byte(one), &e); err != nil || e.Data.ID == "" || e.Data.TenantID != "tenant" || e.Data.Name != pack.Name || e.Data.Description != pack.Description || e.Data.Slug != pack.Slug || e.Data.Version != pack.Version || e.Data.Status != "active" || e.Data.SchemaVersion != domain.ControlFrameworkSchemaVersion || e.Data.CreatedAt.IsZero() || e.Data.CreatedAt.Nanosecond()%1000 != 0 {
			t.Fatal("starter framework changed", one, err)
		}
		var actor, kind, entry string
		if err := p.QueryRow(t.Context(), `SELECT actor_id,actor_type,entry_type FROM audit_chain_entries WHERE subject_id=$1`, e.Data.ID).Scan(&actor, &kind, &entry); err != nil || actor != "user" || kind != "human_user" || entry != "control_framework_template.installed" {
			t.Fatal("template audit lost caller", actor, kind, entry, err)
		}
		assertRetentionHTTPReplay(t, one, controlTemplateNativeHTTP(t, store, pack.Slug, pack.Slug, body, 201))
		controlTemplateNativeHTTP(t, store, pack.Slug, pack.Slug, body+" ", 409)
		totalControls += len(pack.Controls)
		if got := controlTemplateNativeCounts(t, p); got != [6]int{i + 1, totalControls, i + 1, 0, i + 1, 0} {
			t.Fatal("native installation effects changed", got)
		}
	}
	// A completed pre-upgrade JSON response may contain exact integers and
	// arbitrary public fields. Replay must preserve it without reinstallation.
	opts := subjectVerificationOptions(t, store, nil)
	a, err := opts.Authenticator.Authenticate(t.Context(), "evysso_receipt_fixture")
	if err != nil {
		t.Fatal(err)
	}
	pack := packs[0]
	path := "/v1/control-framework-template-packs/" + pack.Slug + "/install"
	if _, _, err := opts.DurableCommandExecutor.WithBody(t.Context(), a, "POST", path, "historical", nil, func(ctx context.Context) error {
		return opts.ControlTemplateCommands.AuthorizeControlTemplateInstallation(ctx, a, pack.Slug)
	}, func(context.Context) (int, any, error) {
		return 201, map[string]any{"id": "historical", "exact_number": json.Number("9007199254740993")}, nil
	}); err != nil {
		t.Fatal(err)
	}
	historical := controlTemplateNativeHTTP(t, store, pack.Slug, "historical", "", 201)
	if !strings.Contains(historical, "9007199254740993") {
		t.Fatal("historical number rounded", historical)
	}
	if _, err := p.Exec(t.Context(), `UPDATE control_frameworks SET name=repeat('private-',1200000),description=repeat('private-',1200000);UPDATE security_controls SET objective=repeat('private-',1200000)`); err != nil {
		t.Fatal(err)
	}
	for i, pack := range packs {
		body := ""
		if i%2 != 0 {
			body = "{}"
		}
		assertRetentionHTTPReplay(t, first[pack.Slug], controlTemplateNativeHTTP(t, store, pack.Slug, pack.Slug, body, 201))
	}
	assertRetentionHTTPReplay(t, historical, controlTemplateNativeHTTP(t, store, pack.Slug, "historical", "", 201))
	for _, grant := range []struct{ kind, id string }{{"product", "product"}, {"project", "project"}, {"release", "release"}, {"tenant", "other"}} {
		if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type=$1,resource_id=$2 WHERE id='grant'`, grant.kind, grant.id); err != nil {
			t.Fatal(err)
		}
		controlTemplateNativeHTTP(t, store, pack.Slug, pack.Slug, "", 403)
		controlTemplateNativeHTTP(t, store, pack.Slug, "denied-fresh", "", 403)
	}
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant',role='viewer' WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	controlTemplateNativeHTTP(t, store, pack.Slug, pack.Slug, "", 403)
	if _, err := p.Exec(t.Context(), `DELETE FROM role_bindings WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	controlTemplateNativeHTTP(t, store, pack.Slug, pack.Slug, "", 403)
	if _, err := p.Exec(t.Context(), `UPDATE sso_sessions SET revoked_at=now() WHERE id='operator-session'`); err != nil {
		t.Fatal(err)
	}
	controlTemplateNativeHTTP(t, store, pack.Slug, pack.Slug, "", 401)
	if got := controlTemplateNativeCounts(t, p); got != [6]int{len(packs), totalControls, len(packs), 0, len(packs) + 1, 0} {
		t.Fatal("replay or revoked authorization changed effects", got)
	}
}

func TestPostgresControlTemplateNativeHTTPRollbackAndRecovery(t *testing.T) {
	for _, stage := range []string{"framework", "late-control", "audit", "replay", "commit"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedProviderReceiptHTTP(t, p)
			pack := riskdomain.BuiltinTemplatePacks()[0]
			table := map[string]string{"framework": "control_frameworks", "late-control": "security_controls", "audit": "audit_chain_entries", "replay": "idempotency_records", "commit": "audit_chain_entries"}[stage]
			trigger := fmt.Sprintf("CREATE TRIGGER reject_template_native BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_template_native()", table)
			if stage == "late-control" {
				late := false
				for i, c := range pack.Controls {
					if c.Code == "CRA-VULN" && i > 0 {
						late = true
					}
				}
				if !late {
					t.Fatal("fixture no longer fails after at least one installed control")
				}
				trigger = `CREATE TRIGGER reject_template_native BEFORE INSERT ON security_controls FOR EACH ROW WHEN(NEW.code='CRA-VULN')EXECUTE FUNCTION reject_template_native()`
			}
			if stage == "replay" {
				trigger = `CREATE TRIGGER reject_template_native BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_template_native()`
			}
			if stage == "commit" {
				trigger = `CREATE CONSTRAINT TRIGGER reject_template_native AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_template_native()`
			}
			if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_template_native()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-template-write-failure';END$$;`+trigger); err != nil {
				t.Fatal(err)
			}
			controlTemplateNativeHTTP(t, store, pack.Slug, "failed", "", 500)
			want := [6]int{}
			if stage != "replay" && stage != "commit" {
				want[5] = 1
			}
			if got := controlTemplateNativeCounts(t, p); got != want {
				t.Fatal("failed install partially committed", got, want)
			}
			if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_template_native ON "+table); err != nil {
				t.Fatal(err)
			}
			key := "failed"
			if want[5] == 1 {
				controlTemplateNativeHTTP(t, store, pack.Slug, key, "", 409)
				key = "recovered"
			}
			one := controlTemplateNativeHTTP(t, store, pack.Slug, key, "", 201)
			assertRetentionHTTPReplay(t, one, controlTemplateNativeHTTP(t, store, pack.Slug, key, "", 201))
			want[0], want[1], want[2], want[4] = 1, len(pack.Controls), 1, 1
			if got := controlTemplateNativeCounts(t, p); got != want {
				t.Fatal("recovered install not atomic", got, want)
			}
		})
	}
}
