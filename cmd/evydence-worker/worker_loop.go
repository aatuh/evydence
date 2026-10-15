package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres"
)

type workerQueue interface {
	ClaimJobs(context.Context, int) ([]postgres.ClaimedJob, error)
	CompleteJob(context.Context, string, string) error
	FailJob(context.Context, string, string, postgres.JobFailure) error
	DeferJob(context.Context, string, string, postgres.JobFailure) error
}
type workerProcessor interface {
	Process(context.Context, postgres.ClaimedJob) error
}
type workerLoopConfig struct {
	PollInterval    time.Duration
	BatchSize       int
	ShutdownTimeout time.Duration
}

var errWorkerDrainTimeout = errors.New("worker shutdown deadline exceeded; unfinished claims await lease expiry")

func closeWorkerAfterStop(err error, closeRuntime func()) {
	// Pool.Close waits for checked-out connections. Once the job deadline has
	// expired, it must not hold the daemon open behind a noncooperative call.
	// main exits nonzero; the OS closes connections and existing leases expire.
	if !errors.Is(err, errWorkerDrainTimeout) {
		closeRuntime()
	}
}

func workerShutdownTimeoutFromEnv() (time.Duration, error) {
	const name = "EVYDENCE_WORKER_SHUTDOWN_TIMEOUT_SECONDS"
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return 30 * time.Second, nil
	}
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds < 1 || seconds > 300 {
		return 0, fmt.Errorf("%s must be an integer between 1 and 300", name)
	}
	return time.Duration(seconds) * time.Second, nil
}

// A signal is a successful stop; an unexpected root deadline is a failure.
func workerStopError(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		log.Print("worker drain completed; unstarted claims await lease expiry")
		return nil
	}
	return ctx.Err()
}

func runWorkerLoop(ctx context.Context, store workerQueue, processor workerProcessor, config workerLoopConfig) error {
	if ctx == nil || missingWorkerPort(store) || missingWorkerPort(processor) || config.PollInterval <= 0 || config.BatchSize <= 0 || config.ShutdownTimeout <= 0 {
		return errors.New("worker loop requires context, queue, processor and positive limits")
	}
	pollInterval, batchSize := config.PollInterval, config.BatchSize
	for {
		if ctx.Err() != nil {
			return workerStopError(ctx)
		}
		jobs, err := store.ClaimJobs(ctx, batchSize)
		if err != nil {
			log.Printf("outbox claim failed")
			if err := waitWorkerPoll(ctx, pollInterval); err != nil {
				return workerStopError(ctx)
			}
			continue
		}
		if len(jobs) == 0 {
			if err := waitWorkerPoll(ctx, pollInterval); err != nil {
				return workerStopError(ctx)
			}
			continue
		}
		prioritizePayloadFinalization(jobs)
		for _, job := range jobs {
			if ctx.Err() != nil {
				return workerStopError(ctx)
			}
			log.Printf("processing outbox job id=%s kind=%s subject_type=%s subject_id=%s attempt=%d", job.ID, job.Kind, job.SubjectType, job.SubjectID, job.Attempts)
			if err := drainableWorkerJob(ctx, store, processor, job, config.ShutdownTimeout); err != nil {
				return err
			}
		}
	}
}

// Only this owner advances from processing to acknowledgement. A processor
// ignoring cancellation may outlive the deadline until process exit, but cannot
// cause a late acknowledgement. Native storage/provider calls receive jobCtx.
func drainableWorkerJob(root context.Context, store workerQueue, processor workerProcessor, job postgres.ClaimedJob, timeout time.Duration) error {
	jobCtx, cancelJob := context.WithCancel(context.WithoutCancel(root))
	defer cancelJob()
	drain := &workerDrain{jobCtx: jobCtx, timeout: timeout}
	defer func() {
		if drain.cancel != nil {
			drain.cancel()
		}
	}()
	err := drain.call(root, func(ctx context.Context) error { return processor.Process(ctx, job) })
	if errors.Is(err, errWorkerDrainTimeout) {
		return err
	}
	if err != nil && root.Err() != nil {
		// Cancellation or a failed attempt during drain is uncertain. Preserve
		// its lease for fenced reclaim instead of recording a false outcome.
		return workerStopError(root)
	}
	if err != nil {
		failure := classifyWorkerFailure(err)
		log.Printf("outbox job failed id=%s kind=%s class=%s code=%s", job.ID, job.Kind, failure.Class, failure.Code)
		err = drain.call(root, func(ctx context.Context) error {
			if failure.Class == postgres.JobFailureTransient && failure.Code == "dependency_pending" {
				return store.DeferJob(ctx, job.ID, job.LeaseToken, failure)
			}
			return store.FailJob(ctx, job.ID, job.LeaseToken, failure)
		})
	} else {
		err = drain.call(root, func(ctx context.Context) error { return store.CompleteJob(ctx, job.ID, job.LeaseToken) })
	}
	if errors.Is(err, errWorkerDrainTimeout) {
		return err
	}
	if err != nil {
		log.Print("record outbox outcome failed; claim awaits lease expiry")
		if root.Err() != nil {
			return errors.New("worker drain could not confirm job outcome")
		}
	}
	return nil
}

type workerDrain struct {
	jobCtx  context.Context
	timeout time.Duration
	ctx     context.Context
	cancel  context.CancelFunc
}

func (d *workerDrain) begin(root context.Context) {
	if d.ctx == nil {
		d.ctx, d.cancel = context.WithTimeout(context.WithoutCancel(root), d.timeout) // #nosec G118 -- drainableWorkerJob defers d.cancel across both phases.
		log.Print("worker drain started; new claims stopped")
	}
}

//nolint:contextcheck // Both stored contexts derive from root; their independent drain lifetime intentionally survives its cancellation.
func (d *workerDrain) call(root context.Context, operation func(context.Context) error) error {
	if root.Err() != nil {
		d.begin(root)
	}
	ctx := d.jobCtx
	if d.ctx != nil {
		ctx = d.ctx
		if ctx.Err() != nil {
			return errWorkerDrainTimeout
		}
	}
	result := make(chan error, 1)
	go func() { result <- operation(ctx) }()
	if d.ctx == nil {
		select {
		case err := <-result:
			return err
		case <-root.Done():
			d.begin(root)
		}
	}
	select {
	case err := <-result:
		if d.ctx.Err() != nil {
			return errWorkerDrainTimeout
		}
		return err
	case <-d.ctx.Done():
		return errWorkerDrainTimeout
	}
}
