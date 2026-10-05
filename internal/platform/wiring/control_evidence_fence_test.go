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
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func TestPostgresControlEvidenceGuardParentLocksJoinOuterReplay(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedNativeControlEvidence(t, store, p)
	opts := subjectVerificationOptions(t, store, nil)
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"controls:write"}}
	in := riskapp.LinkControlEvidenceInput{EvidenceType: "sbom", SubjectType: "product", SubjectID: "product", Confidence: "high", Notes: "reviewed"}
	calls, guards := 0, 0
	for range 2 {
		_, _, err := opts.DurableCommandExecutor.WithBody(t.Context(), a, "POST", "/v1/controls/control/evidence", "joined", []byte(`{}`), func(ctx context.Context) error {
			if err := opts.ControlEvidenceCommands.AuthorizeControlEvidenceLink(ctx, a, "control", in); err != nil {
				return err
			}
			guards++
			for _, tc := range []struct {
				table   string
				blocked bool
			}{{"tenants", true}, {"control_frameworks", true}, {"security_controls", true}, {"control_evidence", false}, {"sso_sessions", false}} {
				probe, err := p.Begin(ctx)
				if err != nil {
					return err
				}
				_, err = probe.Exec(ctx, "SELECT 1 FROM "+tc.table+" FOR NO KEY UPDATE NOWAIT")
				_ = probe.Rollback(context.WithoutCancel(ctx))
				var pe *pgconn.PgError
				if tc.blocked && (!errors.As(err, &pe) || pe.Code != "55P03") || !tc.blocked && err != nil {
					t.Fatal("link guard lost parent locks or read duplicate metadata", tc, err)
				}
			}
			return nil
		}, func(ctx context.Context) (int, any, error) {
			calls++
			v, err := opts.ControlEvidenceCommands.LinkControlEvidence(ctx, a, "control", in)
			return 201, domain.ControlEvidence{ID: v.ID, TenantID: v.TenantID, ControlID: v.ControlID, SubjectType: v.SubjectType, SubjectID: v.SubjectID}, err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := controlEvidenceNativeCounts(t, p); got != [5]int{1, 1, 0, 1, 0} || calls != 1 || guards != 2 {
		t.Fatal("joined link replay repeated effects", got, calls, guards)
	}
}

func TestPostgresControlEvidenceConcurrentDeliveryLinksOnce(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedNativeControlEvidence(t, store, p)
	opts := subjectVerificationOptions(t, store, nil)
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"controls:write"}}
	in := riskapp.LinkControlEvidenceInput{EvidenceType: "sbom", SubjectType: "product", SubjectID: "product", Confidence: "high", Notes: "reviewed"}
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
			s, v, err := opts.DurableCommandExecutor.WithBody(ctx, a, "POST", "/v1/controls/control/evidence", "concurrent", []byte(`{}`), func(ctx context.Context) error {
				return opts.ControlEvidenceCommands.AuthorizeControlEvidenceLink(ctx, a, "control", in)
			}, func(ctx context.Context) (int, any, error) {
				calls.Add(1)
				v, err := opts.ControlEvidenceCommands.LinkControlEvidence(ctx, a, "control", in)
				return 201, domain.ControlEvidence{ID: v.ID, TenantID: v.TenantID, ControlID: v.ControlID, EvidenceType: v.EvidenceType, SubjectType: v.SubjectType, SubjectID: v.SubjectID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Confidence: v.Confidence, Notes: v.Notes, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}, err
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
				t.Fatal("concurrent link failed", r.status, r.err)
			}
			b, err := json.Marshal(r.value)
			if err != nil {
				t.Fatal(err)
			}
			out[i] = string(b)
		case <-ctx.Done():
			t.Fatal("concurrent link leaked transaction", ctx.Err())
		}
	}
	assertRetentionHTTPReplay(t, out[0], out[1])
	if got := controlEvidenceNativeCounts(t, p); got != [5]int{1, 1, 0, 1, 0} || calls.Load() != 1 {
		t.Fatal("concurrent link repeated effects", got, calls.Load())
	}
}

func TestPostgresControlEvidenceFencePrecedesTenantAndControlLocks(t *testing.T) {
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
		done <- repositories.New(child).Controls.(riskapp.ControlEvidenceReader).LockControlEvidenceTenant(ctx, "tenant")
	}()
	waitForControlTemplateFence(t, ctx, func(ctx context.Context) (bool, error) {
		var blocked bool
		err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event='advisory'AND $2=ANY(pg_blocking_pids(pid)))`, childPID, leaderPID).Scan(&blocked)
		return blocked, err
	}, done)
	if _, err := leader.Exec(ctx, `SELECT 1 FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`); err != nil {
		t.Fatal("link tenant lock preceded fence", err)
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
		t.Fatal("link scope did not release fence")
	}
}

func TestPostgresControlEvidenceCancelledGuardReleasesFence(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedNativeControlEvidence(t, store, p)
	commands, err := BuildControlEvidenceCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"controls:write"}}
	in := riskapp.LinkControlEvidenceInput{EvidenceType: "sbom", SubjectType: "product", SubjectID: "product", Confidence: "high"}
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
	go func() { done <- commands.AuthorizeControlEvidenceLink(ctx, a, "control", in) }()
	waitForControlTemplateFence(t, ctx, func(ctx context.Context) (bool, error) {
		var blocked bool
		err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()AND wait_event='advisory'AND $1=ANY(pg_blocking_pids(pid)))`, leaderPID).Scan(&blocked)
		return blocked, err
	}, done)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("link cancellation lost", err)
		}
	case <-time.After(time.Second):
		t.Fatal("link guard leaked transaction")
	}
	if err := leader.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := commands.AuthorizeControlEvidenceLink(t.Context(), a, "control", in); err != nil {
		t.Fatal("cancelled link guard left locks", err)
	}
	if got := controlEvidenceNativeCounts(t, p); got != [5]int{} {
		t.Fatal("cancelled link guard wrote effects", got)
	}
}
