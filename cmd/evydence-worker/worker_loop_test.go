package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/platform/logging"
	"github.com/aatuh/evydence/internal/runtimeinfo"
)

type lifecycleQueue struct {
	claim                                    func(context.Context) ([]postgres.ClaimedJob, error)
	complete                                 func(context.Context) error
	outcome                                  func(postgres.JobFailure)
	claims, completions, failures, deferrals atomic.Int32
}

func TestWorkerLoopSignalProcess(t *testing.T) {
	if mode := os.Getenv("EVYDENCE_WORKER_SIGNAL_TEST"); mode != "" {
		logger, err := logging.New(os.Stderr, "worker", runtimeinfo.Current(), logging.Config{})
		if err != nil {
			t.Fatal(err)
		}
		ctx, stop := signal.NotifyContext(logging.WithLogger(context.Background(), logger), syscall.SIGTERM)
		defer stop()
		q := &lifecycleQueue{claim: func(context.Context) ([]postgres.ClaimedJob, error) {
			return []postgres.ClaimedJob{{ID: "active"}, {ID: "tail"}}, nil
		}}
		p := lifecycleProcessor(func(jobCtx context.Context, _ postgres.ClaimedJob) error {
			fmt.Println("READY")
			<-ctx.Done()
			if mode == "forced" {
				<-jobCtx.Done()
				return jobCtx.Err()
			}
			return nil
		})
		config := shutdownLoopConfig()
		config.ShutdownTimeout = 25 * time.Millisecond
		err = runWorkerLoop(ctx, q, p, config)
		if mode == "graceful" && err == nil && q.completions.Load() == 1 && q.claims.Load() == 1 {
			os.Exit(0)
		}
		if mode == "forced" && errors.Is(err, errWorkerDrainTimeout) && q.completions.Load() == 0 && q.failures.Load() == 0 {
			os.Exit(23)
		}
		os.Exit(24)
	}
	for _, mode := range []string{"graceful", "forced"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(ctx, executable, "-test.run=^TestWorkerLoopSignalProcess$")
			command.Env = append(os.Environ(), "EVYDENCE_WORKER_SIGNAL_TEST="+mode)
			var diagnostics bytes.Buffer
			command.Stderr = &diagnostics
			stdout, err := command.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err = command.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if command.ProcessState == nil {
					_ = command.Process.Kill()
					_ = command.Wait()
				}
			}()
			reader := bufio.NewScanner(stdout)
			if !reader.Scan() || reader.Text() != "READY" {
				t.Fatal("signal helper did not enter job", reader.Err())
			}
			if err = command.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			err = command.Wait()
			if mode == "graceful" && err != nil {
				t.Fatal("SIGTERM did not exit successfully", err, diagnostics.String())
			}
			if mode == "forced" {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 23 {
					t.Fatal("forced SIGTERM did not fail distinctly", err, diagnostics.String())
				}
			}
			if !strings.Contains(diagnostics.String(), `"msg":"drain"`) || !strings.Contains(diagnostics.String(), `"result_code":"started"`) {
				t.Fatal("safe drain status missing", diagnostics.String())
			}
		})
	}
}

func (q *lifecycleQueue) ClaimJobs(ctx context.Context, _ int) ([]postgres.ClaimedJob, error) {
	q.claims.Add(1)
	return q.claim(ctx)
}
func (q *lifecycleQueue) CompleteJob(ctx context.Context, _, _ string) error {
	q.completions.Add(1)
	if q.complete != nil {
		return q.complete(ctx)
	}
	return ctx.Err()
}
func (q *lifecycleQueue) FailJob(ctx context.Context, _, _ string, failure postgres.JobFailure) error {
	q.failures.Add(1)
	if q.outcome != nil {
		q.outcome(failure)
	}
	return ctx.Err()
}
func (q *lifecycleQueue) DeferJob(ctx context.Context, _, _ string, failure postgres.JobFailure) error {
	q.deferrals.Add(1)
	if q.outcome != nil {
		q.outcome(failure)
	}
	return ctx.Err()
}

type lifecycleProcessor func(context.Context, postgres.ClaimedJob) error

func (f lifecycleProcessor) Process(ctx context.Context, job postgres.ClaimedJob) error {
	return f(ctx, job)
}

func shutdownLoopConfig() workerLoopConfig {
	return workerLoopConfig{PollInterval: time.Hour, BatchSize: 2, ShutdownTimeout: time.Second}
}
func awaitWorkerLoop(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("worker loop did not terminate")
		return nil
	}
}

func TestWorkerLoopShutdownIdleIsSuccessfulWithoutClaim(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	q := &lifecycleQueue{claim: func(context.Context) ([]postgres.ClaimedJob, error) { t.Error("claimed after stop"); return nil, nil }}
	err := runWorkerLoop(ctx, q, lifecycleProcessor(func(context.Context, postgres.ClaimedJob) error { return nil }), shutdownLoopConfig())
	if err != nil || q.claims.Load() != 0 {
		t.Fatal("healthy stop was not successful", err, q.claims.Load())
	}
}

func TestWorkerLoopShutdownDuringClaimStopsNormally(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered := make(chan struct{})
	q := &lifecycleQueue{claim: func(ctx context.Context) ([]postgres.ClaimedJob, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	done := make(chan error, 1)
	go func() {
		done <- runWorkerLoop(ctx, q, lifecycleProcessor(func(context.Context, postgres.ClaimedJob) error { t.Error("processed after stop"); return nil }), shutdownLoopConfig())
	}()
	<-entered
	cancel()
	if err := awaitWorkerLoop(t, done); err != nil || q.claims.Load() != 1 {
		t.Fatal("canceled claim was not graceful", err, q.claims.Load())
	}
}

func TestWorkerLoopShutdownDoesNotStartClaimedBatchTail(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	q := &lifecycleQueue{claim: func(context.Context) ([]postgres.ClaimedJob, error) {
		return []postgres.ClaimedJob{{ID: "first", LeaseToken: "lease1"}, {ID: "second", LeaseToken: "lease2"}}, nil
	}}
	var calls atomic.Int32
	p := lifecycleProcessor(func(context.Context, postgres.ClaimedJob) error { calls.Add(1); cancel(); return context.Canceled })
	err := runWorkerLoop(ctx, q, p, shutdownLoopConfig())
	if err != nil || calls.Load() != 1 || q.completions.Load() != 0 || q.failures.Load() != 0 || q.deferrals.Load() != 0 || q.claims.Load() != 1 {
		t.Fatal("shutdown ran batch tail or acknowledged uncertain work", err, calls.Load(), q.completions.Load(), q.failures.Load(), q.deferrals.Load(), q.claims.Load())
	}
}

func TestWorkerLoopShutdownAllowsActiveJobToFinishBeforeCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, finish := make(chan struct{}), make(chan struct{})
	q := &lifecycleQueue{claim: func(context.Context) ([]postgres.ClaimedJob, error) {
		return []postgres.ClaimedJob{{ID: "active"}, {ID: "unstarted"}}, nil
	}}
	var calls atomic.Int32
	p := lifecycleProcessor(func(jobCtx context.Context, _ postgres.ClaimedJob) error {
		calls.Add(1)
		close(entered)
		<-finish
		if jobCtx.Err() != nil {
			t.Error("signal canceled job before its drain budget")
		}
		return nil
	})
	done := make(chan error, 1)
	go func() { done <- runWorkerLoop(ctx, q, p, shutdownLoopConfig()) }()
	<-entered
	cancel()
	close(finish)
	if err := awaitWorkerLoop(t, done); err != nil || calls.Load() != 1 || q.completions.Load() != 1 || q.claims.Load() != 1 {
		t.Fatal("active job failed to drain once", err, calls.Load(), q.completions.Load(), q.claims.Load())
	}
}

func TestWorkerLoopShutdownCancelsActiveJobAtDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, stopped := make(chan struct{}), make(chan struct{})
	q := &lifecycleQueue{claim: func(context.Context) ([]postgres.ClaimedJob, error) {
		return []postgres.ClaimedJob{{ID: "unfinished"}}, nil
	}}
	p := lifecycleProcessor(func(jobCtx context.Context, _ postgres.ClaimedJob) error {
		close(entered)
		<-jobCtx.Done()
		close(stopped)
		return jobCtx.Err()
	})
	config := shutdownLoopConfig()
	config.ShutdownTimeout = 10 * time.Millisecond
	done := make(chan error, 1)
	go func() { done <- runWorkerLoop(ctx, q, p, config) }()
	<-entered
	cancel()
	if err := awaitWorkerLoop(t, done); !errors.Is(err, errWorkerDrainTimeout) {
		t.Fatal("deadline was not a forced failure", err)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("active job context was not canceled")
	}
	if q.completions.Load() != 0 || q.failures.Load() != 0 || q.deferrals.Load() != 0 {
		t.Fatal("unfinished job was acknowledged")
	}
}

func TestWorkerLoopShutdownBoundsCompletionAndReportsUncertainty(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(map[bool]string{false: "failed", true: "blocked"}[blocked], func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			q := &lifecycleQueue{claim: func(context.Context) ([]postgres.ClaimedJob, error) {
				return []postgres.ClaimedJob{{ID: "finished"}}, nil
			}}
			stopped := make(chan struct{})
			q.complete = func(ack context.Context) error {
				defer close(stopped)
				if blocked {
					<-ack.Done()
					return ack.Err()
				}
				return errors.New("provider-secret-DO-NOT-LOG")
			}
			config := shutdownLoopConfig()
			config.ShutdownTimeout = 10 * time.Millisecond
			err := runWorkerLoop(ctx, q, lifecycleProcessor(func(context.Context, postgres.ClaimedJob) error { cancel(); return nil }), config)
			if err == nil || errors.Is(err, context.Canceled) {
				t.Fatal("uncertain acknowledgement was reported successful", err)
			}
			<-stopped
			if q.completions.Load() != 1 || q.failures.Load() != 0 || q.claims.Load() != 1 {
				t.Fatal("duplicate or false acknowledgement")
			}
		})
	}
}

func TestWorkerShutdownTimeoutValidation(t *testing.T) {
	for _, tc := range []struct {
		value   string
		want    time.Duration
		invalid bool
	}{
		{"", 30 * time.Second, false}, {"1", time.Second, false}, {" 300 ", 300 * time.Second, false},
		{"0", 0, true}, {"-1", 0, true}, {"301", 0, true}, {"1s", 0, true}, {"huge-secret-input", 0, true}, {"999999999999999999999999999", 0, true},
	} {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("EVYDENCE_WORKER_SHUTDOWN_TIMEOUT_SECONDS", tc.value)
			got, err := workerShutdownTimeoutFromEnv()
			if (err != nil) != tc.invalid || got != tc.want {
				t.Fatal("invalid budget contract", got, err)
			}
			if tc.invalid {
				t.Setenv("EVYDENCE_DATABASE_URL", "")
				if err := run(); err == nil || err.Error() != "EVYDENCE_WORKER_SHUTDOWN_TIMEOUT_SECONDS must be an integer between 1 and 300" {
					t.Fatal("invalid budget did not fail before storage", err)
				}
			}
		})
	}
}

func TestWorkerInvalidCleanupBudgetFailsBeforeStorage(t *testing.T) {
	t.Setenv("EVYDENCE_DATABASE_URL", "")
	t.Setenv("EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS", "61")
	if err := run(); err == nil || err.Error() != "EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS must be an integer between 1 and 60" {
		t.Fatal("invalid cleanup budget did not fail before storage", err)
	}
}

func TestWorkerShutdownCleanupCannotBlockForcedExit(t *testing.T) {
	for _, err := range []error{nil, errors.New("startup failed"), errWorkerDrainTimeout} {
		called := 0
		closeWorkerAfterStop(err, func() { called++ })
		want := 1
		if errors.Is(err, errWorkerDrainTimeout) {
			want = 0
		}
		if called != want {
			t.Fatal("cleanup did not respect forced-exit boundary", err, called, want)
		}
	}
}

func TestWorkerLoopPreservesFailurePolicyAndContinuesBatch(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		want     postgres.JobFailure
		deferJob bool
	}{
		{"transient", errors.New("private-provider-input"), postgres.JobFailure{Class: postgres.JobFailureTransient, Code: "worker_processing_failed"}, false},
		{"permanent", app.ErrNotFound, postgres.JobFailure{Class: postgres.JobFailurePermanent, Code: "payload_orphaned"}, false},
		{"poisoned", errWorkerBoundedPayloadRejected, postgres.JobFailure{Class: postgres.JobFailurePoisoned, Code: "payload_invariant_failed"}, false},
		{"dependency", errVEXDecisionDependenciesPending, postgres.JobFailure{Class: postgres.JobFailureTransient, Code: "dependency_pending"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			q := &lifecycleQueue{claim: func(context.Context) ([]postgres.ClaimedJob, error) {
				return []postgres.ClaimedJob{{ID: "failed"}, {ID: "next"}}, nil
			}}
			q.outcome = func(got postgres.JobFailure) {
				if got != tc.want {
					t.Error("failure policy changed", got, tc.want)
				}
			}
			var calls int
			p := lifecycleProcessor(func(context.Context, postgres.ClaimedJob) error {
				calls++
				if calls == 1 {
					return tc.err
				}
				cancel()
				return nil
			})
			if err := runWorkerLoop(ctx, q, p, shutdownLoopConfig()); err != nil {
				t.Fatal(err)
			}
			if calls != 2 || q.completions.Load() != 1 || q.failures.Load()+q.deferrals.Load() != 1 {
				t.Fatal("batch failure handling changed", calls)
			}
			if (q.deferrals.Load() == 1) != tc.deferJob {
				t.Fatal("dependency policy changed")
			}
		})
	}
}

func TestWorkerLoopShutdownDuringPollAndAfterClaimReturns(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "claim-error"}[failed], func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			q := &lifecycleQueue{claim: func(context.Context) ([]postgres.ClaimedJob, error) {
				cancel()
				if failed {
					return nil, errors.New("private-db-error")
				}
				return nil, nil
			}}
			if err := runWorkerLoop(ctx, q, lifecycleProcessor(func(context.Context, postgres.ClaimedJob) error { t.Error("unexpected job"); return nil }), shutdownLoopConfig()); err != nil || q.claims.Load() != 1 {
				t.Fatal("poll did not stop normally", err, q.claims.Load())
			}
		})
	}
}

func TestWorkerLoopRejectsInvalidDependenciesAndLimits(t *testing.T) {
	var nilQueue *lifecycleQueue
	var nilProcessor lifecycleProcessor
	q := &lifecycleQueue{}
	p := lifecycleProcessor(func(context.Context, postgres.ClaimedJob) error { return nil })
	for _, tc := range []struct {
		ctx       context.Context
		queue     workerQueue
		processor workerProcessor
		config    workerLoopConfig
	}{
		{nil, q, p, shutdownLoopConfig()}, {t.Context(), nilQueue, p, shutdownLoopConfig()},
		{t.Context(), q, nilProcessor, shutdownLoopConfig()}, {t.Context(), q, p, workerLoopConfig{}},
	} {
		if err := runWorkerLoop(tc.ctx, tc.queue, tc.processor, tc.config); err == nil {
			t.Fatal("invalid worker inputs accepted")
		}
	}
}

func TestWorkerLoopShutdownConfirmsCompletedJobWithLiveBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	q := &lifecycleQueue{claim: func(context.Context) ([]postgres.ClaimedJob, error) {
		return []postgres.ClaimedJob{{ID: "completed", LeaseToken: "lease"}}, nil
	}}
	q.complete = func(ack context.Context) error {
		deadline, ok := ack.Deadline()
		if ack.Err() != nil || !ok || time.Until(deadline) > time.Second {
			t.Error("completion reused canceled root or unbounded context")
		}
		return ack.Err()
	}
	p := lifecycleProcessor(func(context.Context, postgres.ClaimedJob) error { cancel(); return nil })
	if err := runWorkerLoop(ctx, q, p, shutdownLoopConfig()); err != nil || q.completions.Load() != 1 || q.claims.Load() != 1 {
		t.Fatal("committed work was not acknowledged during drain", err, q.completions.Load())
	}
}

func TestWorkerLoopShutdownBoundsUncooperativeProcessor(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer func() { close(release); <-finished }()
	q := &lifecycleQueue{claim: func(context.Context) ([]postgres.ClaimedJob, error) {
		return []postgres.ClaimedJob{{ID: "blocked", LeaseToken: "lease"}}, nil
	}}
	p := lifecycleProcessor(func(context.Context, postgres.ClaimedJob) error {
		close(entered)
		<-release
		close(finished)
		return nil
	})
	config := shutdownLoopConfig()
	config.ShutdownTimeout = 10 * time.Millisecond
	done := make(chan error, 1)
	go func() { done <- runWorkerLoop(ctx, q, p, config) }()
	<-entered
	cancel()
	if err := awaitWorkerLoop(t, done); err == nil || errors.Is(err, context.Canceled) {
		t.Fatal("forced shutdown did not fail distinctly", err)
	}
	if q.completions.Load() != 0 || q.failures.Load() != 0 {
		t.Fatal("forced shutdown acknowledged unfinished work")
	}
}
