package wiring

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func controlCreationNativeHTTP(t *testing.T, store *postgres.Store, path, key, body string, want int) string {
	t.Helper()
	opts := subjectVerificationOptions(t, store, nil)
	if opts.ControlCommands == nil {
		t.Fatal("missing native control composition")
	}
	noReload := &decisionHTTPNoReloadStore{}
	l, err := newLegacyLedgerFixtureWithContext(t.Context(), app.Config{Store: noReload, UnitOfWork: store})
	if err != nil {
		t.Fatal(err)
	}
	s, err := httpapi.NewServerWithOptionsContext(t.Context(), l, opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", path, strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private-") || want != 201 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("native control status=%d want=%d loads=%d: %s", w.Code, want, noReload.loads, w.Body.String())
	}
	if want >= 400 && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatal("control lost problem contract")
	}
	if want == 201 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("control lost replay key")
	}
	return w.Body.String()
}

func TestPostgresControlCreationNativeHTTPRestartReplayAndCurrentAuthority(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	fBody := `{"name":" Framework ","version":" 1 ","description":" Description "}`
	fOne := controlCreationNativeHTTP(t, store, "/v1/control-frameworks", "framework", fBody, 201)
	var f struct {
		Data domain.ControlFramework `json:"data"`
	}
	if err := json.Unmarshal([]byte(fOne), &f); err != nil || f.Data.ID == "" || f.Data.TenantID != "tenant" || f.Data.Name != "Framework" || f.Data.Slug != "framework" || f.Data.Version != "1" || f.Data.Description != "Description" || f.Data.Status != "active" || f.Data.SchemaVersion != domain.ControlFrameworkSchemaVersion || f.Data.CreatedAt.IsZero() || f.Data.CreatedAt.Nanosecond()%1000 != 0 {
		t.Fatal("native framework changed", fOne, err)
	}
	cBody := `{"framework_id":"` + f.Data.ID + `","code":" C ","title":" Title ","objective":" Objective ","evidence_requirements":[{"type":"build","required":false}],"applicability":[" z ",""," a ","a"],"limitations":[" second "," "," first ","first"]}`
	cOne := controlCreationNativeHTTP(t, store, "/v1/controls", "control", cBody, 201)
	var c struct {
		Data domain.SecurityControl `json:"data"`
	}
	if err := json.Unmarshal([]byte(cOne), &c); err != nil || c.Data.ID == "" || c.Data.TenantID != "tenant" || c.Data.FrameworkID != f.Data.ID || c.Data.Code != "C" || c.Data.Title != "Title" || c.Data.Objective != "Objective" || c.Data.SchemaVersion != domain.SecurityControlSchemaVersion || c.Data.CreatedAt.IsZero() || c.Data.CreatedAt.Nanosecond()%1000 != 0 || !reflect.DeepEqual(c.Data.EvidenceRequirements, []domain.ControlEvidenceRequirement{{Type: "build", Required: false}}) || !reflect.DeepEqual(c.Data.Applicability, []string{"", "a", "a", "z"}) || !reflect.DeepEqual(c.Data.Limitations, []string{"second", "first", "first"}) {
		t.Fatal("native control changed", cOne, err)
	}
	var audits int
	if err := p.QueryRow(t.Context(), `SELECT count(*)FROM audit_chain_entries WHERE actor_type='human_user'AND actor_id='user'AND entry_type IN('control_framework.created','security_control.created')`).Scan(&audits); err != nil || audits != 2 {
		t.Fatal("native control audit lost caller", audits, err)
	}
	cases := []struct{ path, key, body, first string }{{"/v1/control-frameworks", "framework", fBody, fOne}, {"/v1/controls", "control", cBody, cOne}}
	for _, tc := range cases {
		assertRetentionHTTPReplay(t, tc.first, controlCreationNativeHTTP(t, store, tc.path, tc.key, tc.body, 201))
		controlCreationNativeHTTP(t, store, tc.path, tc.key, tc.body+" ", 409)
		controlCreationNativeHTTP(t, store, tc.path, "duplicate", tc.body, 409)
	}
	// Historical replay envelopes can retain exact public integer fields.
	opts := subjectVerificationOptions(t, store, nil)
	a, err := opts.Authenticator.Authenticate(t.Context(), "evysso_receipt_fixture")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		_, _, err := opts.DurableCommandExecutor.WithBody(t.Context(), a, "POST", tc.path, "historical", []byte(tc.body), func(ctx context.Context) error {
			if tc.path == "/v1/controls" {
				return opts.ControlCommands.AuthorizeSecurityControlCreation(ctx, a, riskapp.CreateSecurityControlInput{FrameworkID: f.Data.ID, Code: "C", Title: "Title", Objective: "Objective"})
			}
			return opts.ControlCommands.AuthorizeControlFrameworkCreation(ctx, a, riskapp.CreateControlFrameworkInput{Name: "Framework", Version: "1"})
		}, func(context.Context) (int, any, error) {
			return 201, map[string]any{"id": "historical", "exact_number": json.Number("9007199254740993")}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Exec(t.Context(), `UPDATE control_frameworks SET name=repeat('private-',1200000),description=repeat('private-',1200000);UPDATE security_controls SET title=repeat('private-',1200000),objective=repeat('private-',1200000)`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		assertRetentionHTTPReplay(t, tc.first, controlCreationNativeHTTP(t, store, tc.path, tc.key, tc.body, 201))
		out := controlCreationNativeHTTP(t, store, tc.path, "historical", tc.body, 201)
		if !strings.Contains(out, "9007199254740993") {
			t.Fatal("historical replay number rounded", out)
		}
	}
	if _, err := p.Exec(t.Context(), `UPDATE control_frameworks SET tenant_id='other'WHERE id=$1`, f.Data.ID); err != nil {
		t.Fatal(err)
	}
	controlCreationNativeHTTP(t, store, "/v1/controls", "control", cBody, 404)
	controlCreationNativeHTTP(t, store, "/v1/controls", "denied-parent", cBody, 404)
	if _, err := p.Exec(t.Context(), `UPDATE control_frameworks SET tenant_id='tenant'WHERE id=$1`, f.Data.ID); err != nil {
		t.Fatal(err)
	}
	for _, grant := range []struct{ kind, id string }{{"product", "product"}, {"project", "project"}, {"release", "release"}, {"tenant", "other"}} {
		if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type=$1,resource_id=$2 WHERE id='grant'`, grant.kind, grant.id); err != nil {
			t.Fatal(err)
		}
		for _, tc := range cases {
			controlCreationNativeHTTP(t, store, tc.path, tc.key, tc.body, 403)
			controlCreationNativeHTTP(t, store, tc.path, "denied-grant", tc.body, 403)
		}
	}
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant',role='viewer'WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		controlCreationNativeHTTP(t, store, tc.path, tc.key, tc.body, 403)
	}
	if _, err := p.Exec(t.Context(), `DELETE FROM role_bindings WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		controlCreationNativeHTTP(t, store, tc.path, tc.key, tc.body, 403)
	}
	if _, err := p.Exec(t.Context(), `UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		controlCreationNativeHTTP(t, store, tc.path, tc.key, tc.body, 401)
	}
	if got := controlTemplateNativeCounts(t, p); got != [6]int{1, 1, 2, 0, 4, 2} {
		t.Fatal("native control replay changed effects", got)
	}
}

func TestPostgresControlCreationNativeHTTPRollbackAndRecovery(t *testing.T) {
	for _, control := range []bool{false, true} {
		for _, stage := range []string{"record", "audit", "replay", "commit"} {
			t.Run(fmt.Sprintf("control-%t/%s", control, stage), func(t *testing.T) {
				store, p := openHTMLReportWiringStore(t)
				seedProviderReceiptHTTP(t, p)
				path, body, table := "/v1/control-frameworks", `{"name":"F","version":"1"}`, "control_frameworks"
				parent := 0
				if control {
					path, body, table = "/v1/controls", `{"framework_id":"parent","code":"C","title":"T","objective":"O"}`, "security_controls"
					parent = 1
					if _, err := p.Exec(t.Context(), `INSERT INTO control_frameworks(id,tenant_id,name,slug,version,status,schema_version,created_at)VALUES('parent','tenant','Parent','parent','1','active','control-framework.v1.0.0',now())`); err != nil {
						t.Fatal(err)
					}
				}
				if stage == "audit" || stage == "commit" {
					table = "audit_chain_entries"
				}
				if stage == "replay" {
					table = "idempotency_records"
				}
				trigger := fmt.Sprintf("CREATE TRIGGER reject_control_native BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_control_native()", table)
				if stage == "replay" {
					trigger = `CREATE TRIGGER reject_control_native BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_control_native()`
				}
				if stage == "commit" {
					trigger = `CREATE CONSTRAINT TRIGGER reject_control_native AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_control_native()`
				}
				if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_control_native()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-control-write-failure';END$$;`+trigger); err != nil {
					t.Fatal(err)
				}
				controlCreationNativeHTTP(t, store, path, "failed", body, 500)
				want := [6]int{parent, 0, 0, 0, 0, 0}
				if stage == "record" || stage == "audit" {
					want[5] = 1
				}
				if got := controlTemplateNativeCounts(t, p); got != want {
					t.Fatal("control partially committed", got, want)
				}
				if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_control_native ON "+table); err != nil {
					t.Fatal(err)
				}
				key := "failed"
				if want[5] == 1 {
					controlCreationNativeHTTP(t, store, path, key, body, 409)
					key = "recovered"
				}
				one := controlCreationNativeHTTP(t, store, path, key, body, 201)
				assertRetentionHTTPReplay(t, one, controlCreationNativeHTTP(t, store, path, key, body, 201))
				if control {
					want[1] = 1
				} else {
					want[0]++
				}
				want[2], want[4] = 1, 1
				if got := controlTemplateNativeCounts(t, p); got != want {
					t.Fatal("control recovery not atomic", got, want)
				}
			})
		}
	}
}
