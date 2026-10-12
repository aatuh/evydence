package wiring

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func TestPostgresControlTemplateCommandsInstallAllPacksAtomicallyAndReplay(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Templates')`); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildControlTemplateCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildControlTemplateCommands(nil); err == nil {
		t.Fatal("nil template factory accepted")
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"controls:admin", "controls:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"controls:admin", "controls:read"}}}}
	counts := func(wf, wc, wa, wk int) {
		t.Helper()
		var f, c, a, k int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM control_frameworks),(SELECT count(*)FROM security_controls),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&f, &c, &a, &k); err != nil || f != wf || c != wc || a != wa || k != wk {
			t.Fatal("template effects changed", f, c, a, k, err)
		}
	}
	query, err := BuildControlsQuery(store)
	if err != nil {
		t.Fatal(err)
	}
	idem := app.IdempotencyUnitOfWork{Transactions: store}
	rollback := errors.New("outer template rollback")
	_, _, err = idem.WithBody(ctx, actor, "POST", "/template-install", "rollback", nil, func(ctx context.Context, _ app.Repositories) (int, any, error) {
		if _, err := commands.InstallControlFrameworkTemplatePack(ctx, actor, riskdomain.BuiltinTemplatePacks()[0].Slug); err != nil {
			return 0, nil, err
		}
		return 0, nil, rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal("installation failed before outer rollback", err)
	}
	counts(0, 0, 0, 0)
	controlCount := 0
	for i, pack := range riskdomain.BuiltinTemplatePacks() {
		runs := 0
		callback := func(ctx context.Context, _ app.Repositories) (int, any, error) {
			runs++
			fw, err := commands.InstallControlFrameworkTemplatePack(ctx, actor, pack.Slug)
			return 201, fw, err
		}
		status, response, err := idem.WithBody(ctx, actor, "POST", "/template-install/"+pack.Slug, pack.Slug, nil, callback)
		if err != nil || status != 201 {
			t.Fatal("template create failed", pack.Slug, status, err)
		}
		fw := response.(riskdomain.ControlFramework)
		if !strings.HasPrefix(fw.ID, "cf_") || fw.TenantID != actor.TenantID || fw.Name != pack.Name || fw.Slug != pack.Slug || fw.Version != pack.Version || fw.Description != pack.Description || fw.Status != "active" || fw.SchemaVersion != riskdomain.ControlFrameworkSchemaVersion || fw.CreatedAt.IsZero() || fw.CreatedAt.Nanosecond()%1000 != 0 {
			t.Fatal("template framework changed", fw)
		}
		for _, template := range pack.Controls {
			var id string
			if err := pool.QueryRow(ctx, `SELECT id FROM security_controls WHERE tenant_id=$1 AND framework_id=$2 AND code=$3`, actor.TenantID, fw.ID, template.Code).Scan(&id); err != nil {
				t.Fatal(err)
			}
			stored, err := query.GetSecurityControl(ctx, actor, id)
			if err != nil {
				t.Fatal(err)
			}
			want := template
			want.ID = id
			want.TenantID = actor.TenantID
			want.FrameworkID = fw.ID
			want.SchemaVersion = riskdomain.SecurityControlSchemaVersion
			want.CreatedAt = stored.CreatedAt
			if stored.CreatedAt.IsZero() || stored.CreatedAt.Nanosecond()%1000 != 0 || !reflect.DeepEqual(stored, want) {
				t.Fatal("durable starter control differs", stored, want)
			}
		}
		if _, _, err := idem.WithBody(ctx, actor, "POST", "/template-install/"+pack.Slug, pack.Slug, nil, callback); err != nil || runs != 1 {
			t.Fatal("template replay executed twice", runs, err)
		}
		if _, err := commands.InstallControlFrameworkTemplatePack(ctx, actor, pack.Slug); !errors.Is(err, riskapp.ErrConflict) {
			t.Fatal("duplicate version install accepted", err)
		}
		controlCount += len(pack.Controls)
		counts(i+1, controlCount, i+1, i+1)
	}
	var invalidAudits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_chain_entries WHERE entry_type<>'control_framework_template.installed' OR subject_type<>'control_framework' OR actor_type<>'human_user' OR actor_id<>'human'`).Scan(&invalidAudits); err != nil || invalidAudits != 0 {
		t.Fatal("template audit actor/type differs", invalidAudits, err)
	}
}

func TestPostgresControlTemplateCommandsRollbackLateWritesAndSerializeDuplicates(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Templates'),('other','Other')`)
	first, err := BuildControlTemplateCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildControlTemplateCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"controls:admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"controls:admin"}}}}
	pack := riskdomain.BuiltinTemplatePacks()[0]
	counts := func(wf, wc, wa int) {
		t.Helper()
		var f, c, a int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM control_frameworks),(SELECT count(*)FROM security_controls),(SELECT count(*)FROM audit_chain_entries)`).Scan(&f, &c, &a); err != nil || f != wf || c != wc || a != wa {
			t.Fatal("partial template published", f, c, a, err)
		}
	}
	for _, bad := range []identitydomain.Actor{{TenantID: "tenant", UserID: "human", Scopes: actor.Scopes}, {TenantID: "tenant", UserID: "human", Scopes: actor.Scopes, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: actor.Scopes}}}} {
		if _, err := first.InstallControlFrameworkTemplatePack(ctx, bad, pack.Slug); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("restricted actor installed tenant pack", err)
		}
	}
	for _, table := range []string{"control_frameworks", "security_controls", "audit_chain_entries"} {
		condition := "true"
		if table == "security_controls" {
			condition = "NEW.code='CRA-VULN'"
		}
		exec(`CREATE FUNCTION reject_template_insert() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF ` + condition + ` THEN RAISE EXCEPTION 'private template SQL';END IF;RETURN NEW;END$$`)
		exec(`CREATE TRIGGER reject_template_insert BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_template_insert()`)
		if v, err := first.InstallControlFrameworkTemplatePack(ctx, actor, pack.Slug); err == nil || v.ID != "" {
			t.Fatal("failed installation returned framework", v, err)
		}
		counts(0, 0, 0)
		exec(`DROP TRIGGER reject_template_insert ON ` + table)
		exec(`DROP FUNCTION reject_template_insert()`)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		commands := first
		if i%2 != 0 {
			commands = second
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := commands.InstallControlFrameworkTemplatePack(ctx, actor, pack.Slug)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	wins, conflicts := 0, 0
	for err := range results {
		if err == nil {
			wins++
		} else if errors.Is(err, riskapp.ErrConflict) {
			conflicts++
		} else {
			t.Fatal("unexpected template race result", err)
		}
	}
	if wins != 1 || conflicts != 7 {
		t.Fatal("duplicate template race changed", wins, conflicts)
	}
	counts(1, len(pack.Controls), 1)
	foreign := actor
	foreign.TenantID = "other"
	foreign.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "other", Scopes: actor.Scopes}}
	if _, err := second.InstallControlFrameworkTemplatePack(ctx, foreign, pack.Slug); err != nil {
		t.Fatal("other tenant could not independently install", err)
	}
	counts(2, 2*len(pack.Controls), 2)
}
