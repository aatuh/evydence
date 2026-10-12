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
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func TestPostgresControlCommandsUsePendingRowsInOneAtomicReplayTransaction(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	commands, err := BuildControlCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildControlCommands(nil); err == nil {
		t.Fatal("nil factory accepted")
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"controls:admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"controls:admin"}}}}
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		return repos.Identity.InsertTenant(ctx, domain.Tenant{ID: "tenant", Name: "Controls", CreatedAt: time.Now().UTC()})
	}); err != nil {
		t.Fatal(err)
	}
	type result struct {
		Framework riskdomain.ControlFramework
		Control   riskdomain.SecurityControl
	}
	create := func(ctx context.Context, repos app.Repositories) (result, error) {
		fw, err := commands.CreateControlFramework(ctx, actor, riskapp.CreateControlFrameworkInput{Name: " Pending Framework ", Version: " 1 ", Description: " Description "})
		if err != nil {
			return result{}, err
		}
		control, err := commands.CreateSecurityControl(ctx, actor, riskapp.CreateSecurityControlInput{FrameworkID: fw.ID, Code: " C-1 ", Title: " Title ", Objective: " Objective ", EvidenceRequirements: []riskdomain.ControlEvidenceRequirement{{Type: " sbom ", FreshnessDays: 90, Required: true}}, Applicability: []string{" z ", " a ", "a"}, Limitations: []string{" second ", " ", " first "}})
		return result{fw, control}, err
	}
	counts := func(want []int) {
		t.Helper()
		got := make([]int, 5)
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM tenants),(SELECT count(*)FROM control_frameworks),(SELECT count(*)FROM security_controls),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&got[0], &got[1], &got[2], &got[3], &got[4]); err != nil || !reflect.DeepEqual(got, want) {
			t.Fatal("compound effects changed", got, want, err)
		}
	}
	rollback := errors.New("outer rollback")
	idem := app.IdempotencyUnitOfWork{Transactions: store}
	_, _, err = idem.WithBody(ctx, actor, "POST", "/v1/control-frameworks", "rollback", []byte(`{"name":"Rollback"}`), func(ctx context.Context, repos app.Repositories) (int, any, error) {
		if _, err := create(ctx, repos); err != nil {
			return 0, nil, err
		}
		return 0, nil, rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal("pending transaction failed before rollback", err)
	}
	counts([]int{1, 0, 0, 0, 0})
	runs := 0
	callback := func(ctx context.Context, repos app.Repositories) (int, any, error) {
		runs++
		v, err := create(ctx, repos)
		return 201, v, err
	}
	status, response, err := idem.WithBody(ctx, actor, "POST", "/v1/control-frameworks", "compound", []byte(`{"name":"Pending"}`), callback)
	if err != nil || status != 201 {
		t.Fatal("compound durable command failed", status, err)
	}
	v := response.(result)
	if v.Framework.Slug != "pending-framework" || v.Framework.Description != "Description" || v.Framework.Status != "active" || v.Framework.SchemaVersion != domain.ControlFrameworkSchemaVersion || v.Control.FrameworkID != v.Framework.ID || v.Control.Code != "C-1" || v.Control.Title != "Title" || v.Control.Objective != "Objective" || !reflect.DeepEqual(v.Control.Applicability, []string{"a", "a", "z"}) || !reflect.DeepEqual(v.Control.Limitations, []string{"second", "first"}) {
		t.Fatal("compound response lost fields", v)
	}
	query, err := BuildControlsQuery(store)
	if err != nil {
		t.Fatal(err)
	}
	readActor := actor
	readActor.Scopes = append(readActor.Scopes, "controls:read")
	readActor.ResourceGrants[0].Scopes = append(readActor.ResourceGrants[0].Scopes, "controls:read")
	stored, err := query.GetSecurityControl(ctx, readActor, v.Control.ID)
	stored.CreatedAt = stored.CreatedAt.UTC()
	if err != nil || !reflect.DeepEqual(stored, v.Control) {
		t.Fatal("stored control differs", stored, v.Control, err)
	}
	if v.Framework.CreatedAt.Nanosecond()%1000 != 0 || v.Control.CreatedAt.Nanosecond()%1000 != 0 {
		t.Fatal("timestamps lose storage precision")
	}
	counts([]int{1, 1, 1, 2, 1})
	if _, _, err := idem.WithBody(ctx, actor, "POST", "/v1/control-frameworks", "compound", []byte(`{"name":"Pending"}`), callback); err != nil || runs != 1 {
		t.Fatal("replay reexecuted command", runs, err)
	}
	if _, _, err := idem.WithBody(ctx, actor, "POST", "/v1/control-frameworks", "compound", []byte(`{"name":"Changed"}`), callback); !errors.Is(err, app.ErrIdempotencyConflict) || runs != 1 {
		t.Fatal("changed replay identity accepted", runs, err)
	}
	counts([]int{1, 1, 1, 2, 1})
}

func TestPostgresControlCommandsEnforceTenantGrantsAndRollbackStorageFailures(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Controls'),('other','Other');INSERT INTO control_frameworks(id,tenant_id,name,slug,version,status,schema_version)VALUES('fw','tenant',repeat('x',9000000),'existing','1','active','control-framework.v1.0.0'),('foreign','other','Foreign','existing','1','active','control-framework.v1.0.0')`)
	commands, err := BuildControlCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"controls:admin"}}
	input := riskapp.CreateSecurityControlInput{FrameworkID: "fw", Code: "C", Title: "Control", Objective: "Objective"}
	counts := func(wantControls, wantAudits int) {
		t.Helper()
		var c, a int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM security_controls),(SELECT count(*)FROM audit_chain_entries)`).Scan(&c, &a); err != nil || c != wantControls || a != wantAudits {
			t.Fatal("failed command published", c, a, err)
		}
	}
	for _, id := range []string{"foreign", "missing"} {
		bad := input
		bad.FrameworkID = id
		if v, err := commands.CreateSecurityControl(ctx, actor, bad); !errors.Is(err, riskapp.ErrNotFound) || v.ID != "" {
			t.Fatal("foreign/missing parent accepted", id, v, err)
		}
	}
	for _, human := range []identitydomain.Actor{
		{TenantID: "tenant", UserID: "human", Scopes: []string{"controls:admin"}},
		{TenantID: "tenant", UserID: "human", Scopes: []string{"controls:admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"controls:admin"}}}},
		{TenantID: "tenant", UserID: "human", Scopes: []string{"controls:admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "other", Scopes: []string{"controls:admin"}}}},
	} {
		if v, err := commands.CreateSecurityControl(ctx, human, input); !errors.Is(err, application.ErrForbidden) || v.ID != "" {
			t.Fatal("restricted human created tenant controls", v, err)
		}
		if v, err := commands.CreateControlFramework(ctx, human, riskapp.CreateControlFrameworkInput{Name: "Denied", Version: "1"}); !errors.Is(err, application.ErrForbidden) || v.ID != "" {
			t.Fatal("restricted human created framework", v, err)
		}
	}
	counts(0, 0)
	for _, table := range []string{"security_controls", "audit_chain_entries"} {
		exec(`CREATE FUNCTION reject_control_insert() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private control SQL';END$$`)
		exec(`CREATE TRIGGER reject_control_insert BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_control_insert()`)
		if v, err := commands.CreateSecurityControl(ctx, actor, input); err == nil || v.ID != "" {
			t.Fatal("storage/audit failure accepted", v, err)
		}
		counts(0, 0)
		exec(`DROP TRIGGER reject_control_insert ON ` + table)
		exec(`DROP FUNCTION reject_control_insert()`)
	}
	created, err := commands.CreateSecurityControl(ctx, actor, input)
	if err != nil || created.FrameworkID != "fw" {
		t.Fatal("large parent metadata crossed existence boundary", created, err)
	}
	counts(1, 1)
	exec(`UPDATE security_controls SET title=repeat('x',9000000),objective=repeat('y',9000000) WHERE id=$1`, created.ID)
	if v, err := commands.CreateSecurityControl(ctx, actor, input); !errors.Is(err, riskapp.ErrConflict) || v.ID != "" {
		t.Fatal("duplicate control failed bounded lookup", v, err)
	}
	if v, err := commands.CreateControlFramework(ctx, actor, riskapp.CreateControlFrameworkInput{Name: "Duplicate", Slug: "existing", Version: "1"}); !errors.Is(err, riskapp.ErrConflict) || v.ID != "" {
		t.Fatal("duplicate framework failed bounded lookup", v, err)
	}
	counts(1, 1)
	// An explicit different version and another tenant retain their own keys.
	if _, err := commands.CreateControlFramework(ctx, actor, riskapp.CreateControlFrameworkInput{Name: "New version", Slug: "existing", Version: "2"}); err != nil {
		t.Fatal(err)
	}
	foreignActor := actor
	foreignActor.TenantID = "other"
	if _, err := commands.CreateSecurityControl(ctx, foreignActor, riskapp.CreateSecurityControlInput{FrameworkID: "foreign", Code: "C", Title: "Other", Objective: "Other"}); err != nil {
		t.Fatal(err)
	}
	counts(2, 3)
}

func TestPostgresControlCommandsSerializeCompetingUniqueKeys(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Concurrent')`); err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"controls:admin"}}
	commands, err := BuildControlCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := commands.CreateControlFramework(ctx, actor, riskapp.CreateControlFrameworkInput{Name: "Race", Slug: "race", Version: "1"})
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	wins, conflicts := 0, 0
	for err := range errs {
		if err == nil {
			wins++
		} else if errors.Is(err, riskapp.ErrConflict) {
			conflicts++
		} else {
			t.Fatal("unexpected competing write error", err)
		}
	}
	var f, a int
	if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM control_frameworks),(SELECT count(*)FROM audit_chain_entries)`).Scan(&f, &a); err != nil || wins != 1 || conflicts != 7 || f != 1 || a != 1 {
		t.Fatal("unique-key race lost atomicity", wins, conflicts, f, a, err)
	}
	// Bounds must reject unsupported index inputs before PostgreSQL raises errors.
	if _, err := commands.CreateControlFramework(ctx, actor, riskapp.CreateControlFrameworkInput{Name: "Big", Slug: strings.Repeat("x", 1024), Version: "1"}); !errors.Is(err, riskapp.ErrValidation) {
		t.Fatal("indexed tuple budget not enforced", err)
	}
}
