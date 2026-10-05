package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/domain"
)

func TestPostgresBuildAttestationGuardLocksJoinReplayWithoutEvidenceOrAttestationReads(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedBuildCreationNative(t, p)
	body := attestationNativeBody(t)
	seed := attestationNativeHTTP(t, store, nil, "seed", body, 201)
	var envelope struct {
		Data domain.BuildAttestation `json:"data"`
	}
	if err := json.Unmarshal([]byte(seed), &envelope); err != nil {
		t.Fatal(err)
	}
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"build:write"}}
	calls, guards := 0, 0
	for range 2 {
		_, _, err := o.DurableCommandExecutor.WithBody(t.Context(), a, "POST", "/v1/builds/linked-build/attestations", "locks", []byte(body), func(ctx context.Context) error {
			if err := o.BuildAttestationCommands.AuthorizeBuildAttestationCreation(ctx, a, "linked-build"); err != nil {
				return err
			}
			guards++
			for _, tc := range []struct {
				table, id string
				blocked   bool
			}{{"tenants", "tenant", true}, {"build_runs", "linked-build", true}, {"projects", "project", true}, {"products", "product", true}, {"releases", "release", true}, {"artifacts", "artifact", true}, {"build_attestations", envelope.Data.ID, false}, {"evidence_items", envelope.Data.EvidenceID, false}, {"projects", "other-project", false}, {"artifacts", "foreign-artifact", false}, {"sso_sessions", "operator-session", false}} {
				probe, err := p.Begin(ctx)
				if err != nil {
					return err
				}
				_, err = probe.Exec(ctx, "SELECT 1 FROM "+tc.table+" WHERE id=$1 FOR NO KEY UPDATE NOWAIT", tc.id)
				_ = probe.Rollback(context.WithoutCancel(ctx))
				var pe *pgconn.PgError
				if tc.blocked && (!errors.As(err, &pe) || pe.Code != "55P03") || !tc.blocked && err != nil {
					t.Fatal("guard lost parent lock or locked historical ingestion", tc, err)
				}
			}
			return nil
		}, func(context.Context) (int, any, error) { calls++; return 201, map[string]any{"id": "guard-only"}, nil })
		if err != nil {
			t.Fatal(err)
		}
	}
	// Inline/no-object-store creation has one verification job and no payload
	// finalization job, unlike the managed-storage workflow below.
	if got := attestationNativeCounts(t, p); calls != 1 || guards != 2 || got != [7]int{1, 1, 2, 0, 1, 2, 0} {
		t.Fatal("guard skipped replay authority or repeated effects", calls, guards, got)
	}
}

func TestPostgresBuildAttestationNativeConcurrentReplayStagesAndCreatesOnce(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedBuildCreationNative(t, p)
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	objects := &countedSignatureStager{Store: fs}
	o := subjectVerificationOptions(t, store, objects)
	o.BuildAttestationCommands, err = BuildBuildAttestationCommands(store, objects, true)
	if err != nil {
		t.Fatal(err)
	}
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"build:write"}}
	body := []byte(attestationNativeBody(t))
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
			s, v, err := o.DurableCommandExecutor.WithBody(ctx, a, "POST", "/v1/builds/linked-build/attestations", "concurrent", body, func(ctx context.Context) error {
				return o.BuildAttestationCommands.AuthorizeBuildAttestationCreation(ctx, a, "linked-build")
			}, func(ctx context.Context) (int, any, error) {
				calls.Add(1)
				v, err := o.BuildAttestationCommands.UploadBuildAttestation(ctx, a, "linked-build", body)
				public := domain.BuildAttestation(v)
				public.PayloadRef = ""
				return 201, public, err
			})
			done <- reply{s, v, err}
		}()
	}
	close(start)
	var replies [2]string
	for i := range replies {
		select {
		case r := <-done:
			if r.err != nil || r.status != 201 {
				t.Fatal("concurrent attestation failed", r.status, r.err)
			}
			raw, err := json.Marshal(r.value)
			if err != nil {
				t.Fatal(err)
			}
			replies[i] = string(raw)
		case <-ctx.Done():
			t.Fatal("concurrent attestation leaked transaction", ctx.Err())
		}
	}
	assertRetentionHTTPReplay(t, replies[0], replies[1])
	if got := attestationNativeCounts(t, p); calls.Load() != 1 || objects.stages != 1 || got != [7]int{1, 1, 2, 1, 2, 1, 0} {
		t.Fatal("concurrent attestation duplicated ingestion", calls.Load(), objects.stages, got)
	}
}

func TestPostgresBuildAttestationCancelledGuardReleasesFenceBeforeTenantLocks(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedBuildCreationNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"build:write"}}
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
	go func() { done <- o.BuildAttestationCommands.AuthorizeBuildAttestationCreation(ctx, a, "linked-build") }()
	waitForControlTemplateFence(t, ctx, func(ctx context.Context) (bool, error) {
		var blocked bool
		err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()AND wait_event='advisory'AND $1=ANY(pg_blocking_pids(pid)))`, leaderPID).Scan(&blocked)
		return blocked, err
	}, done)
	if _, err := leader.Exec(t.Context(), `SELECT 1 FROM tenants WHERE id='tenant'FOR UPDATE NOWAIT`); err != nil {
		t.Fatal("attestation tenant lock preceded writer fence", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("guard lost cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled guard leaked transaction")
	}
	if err := leader.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := o.BuildAttestationCommands.AuthorizeBuildAttestationCreation(t.Context(), a, "linked-build"); err != nil {
		t.Fatal("cancelled guard leaked fence", err)
	}
	if got := attestationNativeCounts(t, p); got != [7]int{} {
		t.Fatal("guard wrote ingestion effects", got)
	}
}
