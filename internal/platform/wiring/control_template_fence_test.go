package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func waitForControlTemplateFence(t *testing.T, ctx context.Context, predicate func(context.Context) (bool, error), done <-chan error) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			t.Fatal("template scope bypassed writer fence", err)
		case <-ctx.Done():
			t.Fatal("template scope did not reach fence", ctx.Err())
		case <-ticker.C:
			blocked, err := predicate(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if blocked {
				return
			}
		}
	}
}

func TestPostgresControlTemplateFencePrecedesTenantLocks(t *testing.T) {
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
		done <- repositories.New(child).Controls.(interface {
			LockControlTemplateTenant(context.Context, string) error
		}).LockControlTemplateTenant(ctx, "tenant")
	}()
	waitForControlTemplateFence(t, ctx, func(ctx context.Context) (bool, error) {
		var blocked bool
		err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event='advisory'AND $2=ANY(pg_blocking_pids(pid)))`, childPID, leaderPID).Scan(&blocked)
		return blocked, err
	}, done)
	if _, err := leader.Exec(ctx, `SELECT 1 FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`); err != nil {
		t.Fatal("tenant row lock preceded common fence", err)
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
		t.Fatal("template fence did not release")
	}
}

func TestPostgresControlTemplateGuardLocksJoinOuterReplayWithoutInventoryLocks(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	if _, err := p.Exec(t.Context(), `INSERT INTO control_frameworks(id,tenant_id,name,slug,version,status,schema_version,created_at)VALUES('probe-framework','tenant','Probe','probe','1','active','control-framework.v1.0.0',now());INSERT INTO security_controls(id,tenant_id,framework_id,code,title,objective,evidence_requirements,applicability,limitations,schema_version,created_at)VALUES('probe-control','tenant','probe-framework','P','Probe','Probe','[]','[]','[]','security-control.v1.0.0',now())`); err != nil {
		t.Fatal(err)
	}
	opts := subjectVerificationOptions(t, store, nil)
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"controls:admin"}}
	pack := riskdomain.BuiltinTemplatePacks()[0]
	path := "/v1/control-framework-template-packs/" + pack.Slug + "/install"
	calls, guards := 0, 0
	for range 2 {
		_, _, err := opts.DurableCommandExecutor.WithBody(t.Context(), a, "POST", path, "joined", nil, func(ctx context.Context) error {
			if err := opts.ControlTemplateCommands.AuthorizeControlTemplateInstallation(ctx, a, pack.Slug); err != nil {
				return err
			}
			guards++
			for _, tc := range []struct {
				table   string
				blocked bool
			}{{"tenants", true}, {"control_frameworks", false}, {"security_controls", false}, {"sso_sessions", false}} {
				probe, err := p.Begin(ctx)
				if err != nil {
					return err
				}
				_, err = probe.Exec(ctx, "SELECT 1 FROM "+tc.table+" FOR UPDATE NOWAIT")
				_ = probe.Rollback(context.WithoutCancel(ctx))
				var pe *pgconn.PgError
				if tc.blocked && (!errors.As(err, &pe) || pe.Code != "55P03") || !tc.blocked && err != nil {
					t.Fatal("template guard lost tenant lock or locked inventory", tc, err)
				}
			}
			return nil
		}, func(ctx context.Context) (int, any, error) {
			calls++
			v, err := opts.ControlTemplateCommands.InstallControlFrameworkTemplatePack(ctx, a, pack.Slug)
			return 201, domain.ControlFramework{ID: v.ID, TenantID: v.TenantID}, err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := controlTemplateNativeCounts(t, p); calls != 1 || guards != 2 || got != [6]int{2, len(pack.Controls) + 1, 1, 0, 1, 0} {
		t.Fatal("joined template replay changed effects", calls, guards, got)
	}
}

func TestPostgresControlTemplateConcurrentDeliveryInstallsOnce(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	opts := subjectVerificationOptions(t, store, nil)
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"controls:admin"}}
	pack := riskdomain.BuiltinTemplatePacks()[0]
	path := "/v1/control-framework-template-packs/" + pack.Slug + "/install"
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
			s, v, err := opts.DurableCommandExecutor.WithBody(ctx, a, "POST", path, "duplicate", nil, func(ctx context.Context) error {
				return opts.ControlTemplateCommands.AuthorizeControlTemplateInstallation(ctx, a, pack.Slug)
			}, func(ctx context.Context) (int, any, error) {
				calls.Add(1)
				v, err := opts.ControlTemplateCommands.InstallControlFrameworkTemplatePack(ctx, a, pack.Slug)
				return 201, domain.ControlFramework{ID: v.ID, TenantID: v.TenantID, Name: v.Name, Slug: v.Slug, Version: v.Version, Description: v.Description, Status: v.Status, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}, err
			})
			done <- reply{s, v, err}
		}()
	}
	close(start)
	var results [2]string
	for i := range results {
		select {
		case r := <-done:
			if r.status != 201 || r.err != nil {
				t.Fatal("concurrent install failed", r.status, r.err)
			}
			b, err := json.Marshal(r.value)
			if err != nil {
				t.Fatal(err)
			}
			results[i] = string(b)
		case <-ctx.Done():
			t.Fatal("concurrent installation leaked transaction", ctx.Err())
		}
	}
	assertRetentionHTTPReplay(t, results[0], results[1])
	if got := controlTemplateNativeCounts(t, p); calls.Load() != 1 || got != [6]int{1, len(pack.Controls), 1, 0, 1, 0} {
		t.Fatal("duplicate template installation effects", calls.Load(), got)
	}
}

func TestPostgresControlTemplateCancelledGuardReleasesFence(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	opts := subjectVerificationOptions(t, store, nil)
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"controls:admin"}}
	pack := riskdomain.BuiltinTemplatePacks()[0]
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
	go func() { done <- opts.ControlTemplateCommands.AuthorizeControlTemplateInstallation(ctx, a, pack.Slug) }()
	waitForControlTemplateFence(t, ctx, func(ctx context.Context) (bool, error) {
		var blocked bool
		err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()AND wait_event='advisory'AND $1=ANY(pg_blocking_pids(pid)))`, leaderPID).Scan(&blocked)
		return blocked, err
	}, done)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("template cancellation lost", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled template guard leaked transaction")
	}
	if err := leader.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := opts.ControlTemplateCommands.AuthorizeControlTemplateInstallation(t.Context(), a, pack.Slug); err != nil {
		t.Fatal("cancelled guard left ownership locks", err)
	}
	if got := controlTemplateNativeCounts(t, p); got != [6]int{} {
		t.Fatal("cancelled template guard wrote effects", got)
	}
}
