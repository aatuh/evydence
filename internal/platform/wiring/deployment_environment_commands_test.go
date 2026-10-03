package wiring

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

func TestPostgresDeploymentEnvironmentCreationSerializesNamesAndAuditsAtomically(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Environments'),('other','Other')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant',repeat('x',9000000),'product'),('foreign','other','Other','other')`)
	one, err := BuildDeploymentEnvironmentCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	two, err := BuildDeploymentEnvironmentCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"deployment:write"}}
	in := operationsapp.CreateEnvironmentInput{ProductID: "product", Name: "Production", Kind: "production"}
	type result struct {
		v   operationsdomain.DeploymentEnvironment
		err error
	}
	const callers = 8
	results := make(chan result, callers)
	for i := 0; i < callers; i++ {
		go func(i int) {
			c := one
			if i%2 != 0 {
				c = two
			}
			v, err := c.CreateDeploymentEnvironment(ctx, a, in)
			results <- result{v, err}
		}(i)
	}
	id := ""
	for i := 0; i < callers; i++ {
		r := <-results
		if r.err != nil || r.v.ID == "" {
			t.Fatal(r)
		}
		if id == "" {
			id = r.v.ID
		}
		if r.v.ID != id {
			t.Fatal("duplicate environment identity", r.v, id)
		}
	}
	counts := func() [3]int {
		t.Helper()
		var n [3]int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM deployment_environments WHERE tenant_id='tenant'),(SELECT count(*) FROM audit_chain_entries WHERE tenant_id='tenant'),(SELECT count(*) FROM outbox_jobs WHERE tenant_id='tenant')`).Scan(&n[0], &n[1], &n[2]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if counts() != [3]int{1, 1, 0} {
		t.Fatal("name reuse duplicated side effects", counts())
	}
	changed := in
	changed.Kind = "different"
	if v, err := one.CreateDeploymentEnvironment(ctx, a, changed); err != nil || v.ID != id || v.Kind != "production" || counts() != [3]int{1, 1, 0} {
		t.Fatal("existing environment mutated", v, err)
	}
	for _, tc := range []struct {
		a       identitydomain.Actor
		product string
		want    error
	}{
		{a, "foreign", operationsapp.ErrNotFound},
		{a, "missing", operationsapp.ErrNotFound},
		{identitydomain.Actor{TenantID: "tenant", KeyID: "reader", Scopes: []string{"deployment:read"}}, "product", application.ErrForbidden},
		{identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"deployment:write"}}, "product", application.ErrForbidden},
		{identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"deployment:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "foreign", Scopes: []string{"deployment:write"}}}}, "product", application.ErrForbidden},
	} {
		request := in
		request.ProductID = tc.product
		if _, err := one.CreateDeploymentEnvironment(ctx, tc.a, request); !errors.Is(err, tc.want) {
			t.Fatal(tc, err)
		}
	}
	if counts() != [3]int{1, 1, 0} {
		t.Fatal("denied calls mutated state")
	}
	// High-entropy text cannot rely on PostgreSQL index compression to fit
	// the tenant/product/name unique key. Reject it before insertion.
	var oversizedName strings.Builder
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&oversizedName, "%x", sha256.Sum256([]byte(fmt.Sprint(i))))
	}
	largeRequest := in
	largeRequest.Name = oversizedName.String()
	if v, err := one.CreateDeploymentEnvironment(ctx, a, largeRequest); !errors.Is(err, operationsapp.ErrValidation) || v.ID != "" || counts() != [3]int{1, 1, 0} {
		t.Fatalf("oversized indexed name must be validation, not a database error: id=%q err=%v counts=%v", v.ID, err, counts())
	}
	for _, table := range []string{"deployment_environments", "audit_chain_entries"} {
		exec(`CREATE OR REPLACE FUNCTION reject_environment_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected environment failure'; END $$`)
		exec(`CREATE TRIGGER reject_environment_write BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_environment_write()`)
		request := in
		request.Name = "Failed"
		if v, err := one.CreateDeploymentEnvironment(ctx, a, request); err == nil || v.ID != "" || counts() != [3]int{1, 1, 0} {
			t.Fatal("partial environment write", v, err, counts())
		}
		exec(`DROP TRIGGER reject_environment_write ON ` + table)
	}
	human := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"deployment:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"deployment:write"}}}}
	request := in
	request.Name = "Canary"
	v, err := one.CreateDeploymentEnvironment(ctx, human, request)
	if err != nil {
		t.Fatal(err)
	}
	var actorType, actorID string
	if err := pool.QueryRow(ctx, `SELECT actor_type,actor_id FROM audit_chain_entries WHERE tenant_id='tenant' AND subject_id=$1`, v.ID).Scan(&actorType, &actorID); err != nil || actorType != "human_user" || actorID != "user" {
		t.Fatal(actorType, actorID, err)
	}
	before := counts()
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	for i := 0; i < 2; i++ {
		if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/environments", "environment-replay", []byte(`{"name":"Replay"}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			request := in
			request.Name = "Replay"
			v, err := one.CreateDeploymentEnvironment(ctx, a, request)
			return 201, v, err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if counts() != [3]int{before[0] + 1, before[1] + 1, 0} {
		t.Fatal("replay duplicated environments or audit", counts())
	}
	exec(`UPDATE deployment_environments SET kind=repeat('x',9000000) WHERE id=$1`, id)
	if v, err := one.CreateDeploymentEnvironment(ctx, a, in); !errors.Is(err, operationsapp.ErrConflict) || v.ID != "" || strings.Contains(v.Kind, "x") {
		t.Fatal("oversized stored metadata returned", v, err)
	}
}
