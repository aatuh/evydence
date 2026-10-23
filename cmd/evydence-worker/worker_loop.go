package main

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/platform/logging"
	"github.com/aatuh/evydence/internal/platform/telemetry"
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
	// Pool.Close waits for checked-out connections. Once a job or probe drain
	// deadline has expired, it must not wait behind a noncooperative call.
	// main exits nonzero; the OS closes connections and existing leases expire.
	if !errors.Is(err, errWorkerDrainTimeout) && !errors.Is(err, errWorkerProbeDrainTimeout) {
		closeRuntime()
	}
}

// A signal is a successful stop; an unexpected root deadline is a failure.
func workerStopError(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		logging.Emit(ctx, logging.Drain, logging.Fields{Result: logging.Succeeded})
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
		jobs, err := telemetry.Measure(ctx, telemetry.OperationWorkerClaim, func(claimCtx context.Context) ([]postgres.ClaimedJob, error) {
			return store.ClaimJobs(claimCtx, batchSize)
		})
		if err != nil {
			logging.Emit(ctx, logging.Outbox, logging.Fields{OperationID: "claim_jobs", Result: logging.Failed, Retry: logging.Transient})
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
	root = logging.WithCorrelation(root, job.Correlation)
	started := time.Now()
	fields := logging.Fields{TenantID: job.TenantID, ResourceID: job.SubjectID, JobID: job.ID, Attempt: job.Attempts, Result: logging.Started}
	if logging.CorrelationFromContext(root).OperationID == "" {
		fields.OperationID = job.Kind
	}
	logging.Emit(root, logging.Outbox, fields)
	jobCtx, cancelJob := context.WithCancel(context.WithoutCancel(root))
	defer cancelJob()
	drain := &workerDrain{jobCtx: jobCtx, timeout: timeout}
	defer func() {
		if drain.cancel != nil {
			drain.cancel()
		}
	}()
	err := measureWorkerPhase(root, jobCtx, telemetry.OperationWorkerProcess, job.Attempts, func() error {
		return drain.call(root, func(ctx context.Context) error { return processor.Process(ctx, job) })
	})
	if errors.Is(err, errWorkerDrainTimeout) {
		fields.Result = logging.Uncertain
		fields.Retry = logging.Transient
		fields.Duration = time.Since(started)
		logging.Emit(jobCtx, logging.Outbox, fields)
		return err
	}
	if err != nil && root.Err() != nil {
		// Cancellation or a failed attempt during drain is uncertain. Preserve
		// its lease for fenced reclaim instead of recording a false outcome.
		return workerStopError(root)
	}
	if err != nil {
		failure := classifyWorkerFailure(err)
		fields.Duration = time.Since(started)
		fields.Result = logging.Failed
		switch failure.Class {
		case postgres.JobFailureTransient:
			fields.Retry = logging.Transient
		case postgres.JobFailurePermanent:
			fields.Retry = logging.Permanent
		case postgres.JobFailurePoisoned:
			fields.Retry = logging.Poisoned
		}
		logging.Emit(jobCtx, logging.Outbox, fields)
		operation := telemetry.OperationWorkerFail
		if failure.Class == postgres.JobFailureTransient && failure.Code == "dependency_pending" {
			operation = telemetry.OperationWorkerDefer
		}
		err = measureWorkerPhase(root, jobCtx, operation, job.Attempts, func() error {
			return drain.call(root, func(ctx context.Context) error {
				if failure.Class == postgres.JobFailureTransient && failure.Code == "dependency_pending" {
					return store.DeferJob(ctx, job.ID, job.LeaseToken, failure)
				}
				return store.FailJob(ctx, job.ID, job.LeaseToken, failure)
			})
		})
	} else {
		err = measureWorkerPhase(root, jobCtx, telemetry.OperationWorkerComplete, job.Attempts, func() error {
			return drain.call(root, func(ctx context.Context) error { return store.CompleteJob(ctx, job.ID, job.LeaseToken) })
		})
	}
	if errors.Is(err, errWorkerDrainTimeout) {
		fields.Result = logging.Uncertain
		fields.Retry = logging.Transient
		fields.Duration = time.Since(started)
		logging.Emit(jobCtx, logging.Outbox, fields)
		return err
	}
	if err != nil {
		fields.Duration = time.Since(started)
		fields.Result = logging.Uncertain
		logging.Emit(jobCtx, logging.Outbox, fields)
		if root.Err() != nil {
			return errors.New("worker drain could not confirm job outcome")
		}
	}
	if err == nil && fields.Result == logging.Started {
		fields.Result = logging.Succeeded
		fields.Duration = time.Since(started)
		logging.Emit(jobCtx, logging.Outbox, fields)
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
		logging.Emit(root, logging.Drain, logging.Fields{Result: logging.Started})
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
