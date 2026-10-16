package main

import (
	"context"
	"errors"
	"math"

	"github.com/aatuh/evydence/internal/platform/telemetry"
)

func workerMetricAttempt(attempt int) uint32 {
	if attempt <= 0 {
		return 0
	}
	if uint64(attempt) > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(attempt)
}

// Observe the owner-confirmed phase result outside the drain callback. A late
// noncooperative callback cannot publish a second success after timeout. This
// helper does not process, acknowledge, retry or change ownership of a claim.
func measureWorkerPhase(root, jobCtx context.Context, operation telemetry.Operation, attempt int, call func() error) error {
	finish := telemetry.Start(jobCtx, operation)
	number := workerMetricAttempt(attempt)
	defer finish(telemetry.OutcomeUncertain, number)
	err := call()
	outcome := telemetry.OutcomeForError(err)
	if err != nil {
		if root.Err() != nil || errors.Is(err, errWorkerDrainTimeout) || operation == telemetry.OperationWorkerComplete || operation == telemetry.OperationWorkerFail || operation == telemetry.OperationWorkerDefer {
			outcome = telemetry.OutcomeUncertain
		}
	}
	finish(outcome, number)
	return err
}
