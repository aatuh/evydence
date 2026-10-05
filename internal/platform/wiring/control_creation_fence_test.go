package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func seedControlCreationParent(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	if _, err := p.Exec(t.Context(), `INSERT INTO control_frameworks(id,tenant_id,name,slug,version,status,description,schema_version,created_at)VALUES('parent','tenant',repeat('private-',1200000),'parent','1','active',repeat('private-',1200000),'control-framework.v1.0.0',now())`); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresControlCreationGuardLocksJoinOuterReplay(t *testing.T) {
	for _, control := range []bool{false, true} {
		t.Run(map[bool]string{false: "framework", true: "control"}[control], func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedProviderReceiptHTTP(t, p)
			seedControlCreationParent(t, p)
			opts := subjectVerificationOptions(t, store, nil)
			a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"controls:admin"}}
			f := riskapp.CreateControlFrameworkInput{Name: "Fresh", Version: "1"}
			c := riskapp.CreateSecurityControlInput{FrameworkID: "parent", Code: "C", Title: "T", Objective: "O"}
			path := "/v1/control-frameworks"
			if control {
				path = "/v1/controls"
			}
			calls, guards := 0, 0
			for range 2 {
				_, _, err := opts.DurableCommandExecutor.WithBody(t.Context(), a, "POST", path, "joined", []byte(`{}`), func(ctx context.Context) error {
					var err error
					if control {
						err = opts.ControlCommands.AuthorizeSecurityControlCreation(ctx, a, c)
					} else {
						err = opts.ControlCommands.AuthorizeControlFrameworkCreation(ctx, a, f)
					}
					if err != nil {
						return err
					}
					guards++
					for _, tc := range []struct {
						table   string
						blocked bool
					}{{"tenants", true}, {"control_frameworks", control}, {"security_controls", false}, {"sso_sessions", false}} {
						probe, err := p.Begin(ctx)
						if err != nil {
							return err
						}
						_, err = probe.Exec(ctx, "SELECT 1 FROM "+tc.table+" FOR NO KEY UPDATE NOWAIT")
						_ = probe.Rollback(context.WithoutCancel(ctx))
						var pe *pgconn.PgError
						if tc.blocked && (!errors.As(err, &pe) || pe.Code != "55P03") || !tc.blocked && err != nil {
							t.Fatal("control guard lost reparenting lock or locked unrelated rows", tc, err)
						}
					}
					return nil
				}, func(ctx context.Context) (int, any, error) {
					calls++
					if control {
						v, err := opts.ControlCommands.CreateSecurityControl(ctx, a, c)
						return 201, map[string]any{"id": v.ID, "tenant_id": v.TenantID}, err
					}
					v, err := opts.ControlCommands.CreateControlFramework(ctx, a, f)
					return 201, map[string]any{"id": v.ID, "tenant_id": v.TenantID}, err
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			want := [6]int{2, 0, 1, 0, 1, 0}
			if control {
				want[0], want[1] = 1, 1
			}
			if got := controlTemplateNativeCounts(t, p); got != want || calls != 1 || guards != 2 {
				t.Fatal("control replay repeated effects", got, want, calls, guards)
			}
		})
	}
}

func TestPostgresControlCreationConcurrentDeliveryCreatesOnce(t *testing.T) {
	for _, control := range []bool{false, true} {
		t.Run(map[bool]string{false: "framework", true: "control"}[control], func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedProviderReceiptHTTP(t, p)
			seedControlCreationParent(t, p)
			opts := subjectVerificationOptions(t, store, nil)
			a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"controls:admin"}}
			f := riskapp.CreateControlFrameworkInput{Name: "Fresh", Version: "1"}
			c := riskapp.CreateSecurityControlInput{FrameworkID: "parent", Code: "C", Title: "T", Objective: "O"}
			path := "/v1/control-frameworks"
			if control {
				path = "/v1/controls"
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var calls atomic.Int32
			type reply struct {
				status int
				value  any
				err    error
			}
			done := make(chan reply, 2)
			start := make(chan struct{})
			for range 2 {
				go func() {
					<-start
					s, v, err := opts.DurableCommandExecutor.WithBody(ctx, a, "POST", path, "concurrent", []byte(`{}`), func(ctx context.Context) error {
						if control {
							return opts.ControlCommands.AuthorizeSecurityControlCreation(ctx, a, c)
						}
						return opts.ControlCommands.AuthorizeControlFrameworkCreation(ctx, a, f)
					}, func(ctx context.Context) (int, any, error) {
						calls.Add(1)
						if control {
							v, err := opts.ControlCommands.CreateSecurityControl(ctx, a, c)
							return 201, map[string]any{"id": v.ID, "tenant_id": v.TenantID}, err
						}
						v, err := opts.ControlCommands.CreateControlFramework(ctx, a, f)
						return 201, map[string]any{"id": v.ID, "tenant_id": v.TenantID}, err
					})
					done <- reply{s, v, err}
				}()
			}
			close(start)
			var out [2]string
			for i := range out {
				select {
				case r := <-done:
					if r.status != 201 || r.err != nil {
						t.Fatal("concurrent control creation failed", r.status, r.err)
					}
					b, err := json.Marshal(r.value)
					if err != nil {
						t.Fatal(err)
					}
					out[i] = string(b)
				case <-ctx.Done():
					t.Fatal("control creation leaked transaction", ctx.Err())
				}
			}
			assertRetentionHTTPReplay(t, out[0], out[1])
			want := [6]int{2, 0, 1, 0, 1, 0}
			if control {
				want[0], want[1] = 1, 1
			}
			if got := controlTemplateNativeCounts(t, p); got != want || calls.Load() != 1 {
				t.Fatal("concurrent control creation repeated effects", got, want, calls.Load())
			}
		})
	}
}

func TestPostgresControlCreationScopeFencePrecedesTenantLock(t *testing.T) {
	_, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	leader, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = leader.Rollback(context.WithoutCancel(ctx)) }()
	if err := coordination.LockWorkerProjection(ctx, leader, "tenant"); err != nil {
		t.Fatal(err)
	}
	child, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Rollback(context.WithoutCancel(ctx)) }()
	childPID, leaderPID := child.Conn().PgConn().PID(), leader.Conn().PgConn().PID()
	done := make(chan error, 1)
	go func() {
		done <- repositories.New(child).Controls.(riskapp.ControlCreationReader).LockControlCreationTenant(ctx, "tenant")
	}()
	waitForControlTemplateFence(t, ctx, func(ctx context.Context) (bool, error) {
		var blocked bool
		err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event='advisory'AND $2=ANY(pg_blocking_pids(pid)))`, childPID, leaderPID).Scan(&blocked)
		return blocked, err
	}, done)
	if _, err := leader.Exec(ctx, `SELECT 1 FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`); err != nil {
		t.Fatal("control tenant lock preceded common fence", err)
	}
	if err := leader.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("control scope did not release fence")
	}
}

func TestPostgresControlCreationCancelledGuardReleasesFence(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	seedControlCreationParent(t, p)
	commands, err := BuildControlCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"controls:admin"}}
	leader, err := p.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = leader.Rollback(context.WithoutCancel(t.Context())) }()
	if err := coordination.LockWorkerProjection(t.Context(), leader, "tenant"); err != nil {
		t.Fatal(err)
	}
	leaderPID := leader.Conn().PgConn().PID()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	in := riskapp.CreateSecurityControlInput{FrameworkID: "parent", Code: "C", Title: "T", Objective: "O"}
	go func() { done <- commands.AuthorizeSecurityControlCreation(ctx, a, in) }()
	waitForControlTemplateFence(t, ctx, func(ctx context.Context) (bool, error) {
		var blocked bool
		err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()AND wait_event='advisory'AND $1=ANY(pg_blocking_pids(pid)))`, leaderPID).Scan(&blocked)
		return blocked, err
	}, done)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("control cancellation lost", err)
		}
	case <-time.After(time.Second):
		t.Fatal("control guard leaked transaction")
	}
	if err := leader.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := commands.AuthorizeSecurityControlCreation(t.Context(), a, in); err != nil {
		t.Fatal("cancelled control guard left ownership locks", err)
	}
	if got := controlTemplateNativeCounts(t, p); got != [6]int{1, 0, 0, 0, 0, 0} {
		t.Fatal("cancelled control guard wrote effects", got)
	}
}
