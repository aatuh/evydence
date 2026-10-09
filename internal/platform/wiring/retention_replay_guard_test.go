package wiring

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestPostgresRetentionReplayGuardsRequireCurrentRootsWithoutEffects(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedProviderReceiptHTTP(t, p)
	provider := &retentionProviderFake{}
	c, err := BuildRetentionCommands(store, store, provider)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"admin", "verify:read"}}
	in := verificationapp.CreateObjectRetentionPolicyInput{Name: "Lock", Mode: "governance", RetentionDays: 30}
	missing := a
	missing.TenantID = "missing"
	if err := c.AuthorizeCreateObjectRetentionPolicy(t.Context(), missing, in); !errors.Is(err, verificationapp.ErrNotFound) {
		t.Fatal("missing tenant authorized replay", err)
	}
	if err := c.AuthorizeCreateObjectRetentionPolicy(t.Context(), a, in); err != nil || retentionHTTPCounts(t, p) != [4]int{} {
		t.Fatal("create guard wrote state", err)
	}
	policy, err := c.CreateObjectRetentionPolicy(t.Context(), a, in)
	if err != nil {
		t.Fatal(err)
	}
	foreign := a
	foreign.TenantID = "other"
	if err := c.AuthorizeVerifyObjectRetentionPolicy(t.Context(), foreign, policy.ID); !errors.Is(err, verificationapp.ErrNotFound) {
		t.Fatal("foreign policy authorized replay", err)
	}
	if err := c.AuthorizeVerifyObjectRetentionPolicy(t.Context(), a, "missing"); !errors.Is(err, verificationapp.ErrNotFound) {
		t.Fatal("missing policy authorized replay", err)
	}
	if _, err := p.Exec(t.Context(), `UPDATE object_retention_policies SET verification_checks='{}', verification_limitations=ARRAY[repeat('private-receipt',700000)] WHERE id=$1`, policy.ID); err != nil {
		t.Fatal(err)
	}
	if err := c.AuthorizeVerifyObjectRetentionPolicy(t.Context(), a, policy.ID); err != nil || provider.calls != 0 || retentionHTTPCounts(t, p) != [4]int{1, 1, 0, 0} {
		t.Fatal("replay guard loaded mutable receipt, called provider, or wrote state", err)
	}
}

func TestPostgresRetentionFencePrecedesTenantAndPolicyLocks(t *testing.T) {
	for _, stage := range []string{"create-guard", "verify-guard", "create", "verify"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedProviderReceiptHTTP(t, p)
			c, err := BuildRetentionCommands(store, store, nil)
			if err != nil {
				t.Fatal(err)
			}
			a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"admin", "verify:read"}}
			in := verificationapp.CreateObjectRetentionPolicyInput{Name: "Lock", Mode: "governance", RetentionDays: 30}
			policy, err := c.CreateObjectRetentionPolicy(t.Context(), a, in)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			leader, err := p.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = leader.Rollback(context.WithoutCancel(ctx)) }()
			if err := coordination.LockWorkerProjection(ctx, leader, a.TenantID); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				var err error
				switch stage {
				case "create-guard":
					err = c.AuthorizeCreateObjectRetentionPolicy(ctx, a, in)
				case "verify-guard":
					err = c.AuthorizeVerifyObjectRetentionPolicy(ctx, a, policy.ID)
				case "create":
					_, err = c.CreateObjectRetentionPolicy(ctx, a, in)
				case "verify":
					_, err = c.VerifyObjectRetentionPolicy(ctx, a, policy.ID)
				}
				done <- err
			}()
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case err := <-done:
					t.Fatal("retention operation bypassed tenant fence", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-ticker.C:
					var blocked bool
					if err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory' AND $1=ANY(pg_blocking_pids(pid)))`, leader.Conn().PgConn().PID()).Scan(&blocked); err != nil {
						t.Fatal(err)
					}
					if !blocked {
						continue
					}
					if _, err := leader.Exec(ctx, `SELECT id FROM tenants WHERE id='tenant' FOR UPDATE NOWAIT`); err != nil {
						t.Fatal("tenant lock preceded fence", err)
					}
					if _, err := leader.Exec(ctx, `SELECT id FROM object_retention_policies WHERE id=$1 FOR UPDATE NOWAIT`, policy.ID); err != nil {
						t.Fatal("policy lock preceded fence", err)
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
						t.Fatal("retention operation did not resume", ctx.Err())
					}
					want := [4]int{1, 1, 0, 0}
					switch stage {
					case "create":
						want = [4]int{2, 2, 0, 0}
					case "verify":
						want[1] = 2
					}
					if retentionHTTPCounts(t, p) != want {
						t.Fatal("fenced operation published wrong effects")
					}
					return
				}
			}
		})
	}
}
