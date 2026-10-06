package main

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
)

// The production worker requires scoped reads and claim-fenced writes. Neither
// aggregate loading nor snapshot publication belongs to this dependency surface.
type nativeJobStateStore interface {
	jobFocusedStateLoader
	jobClaimedReleaseLedgerMutationStore
	jobDependencyInspector
	app.ObjectPayloadLifecycleStore
}
type nativeJobObjectStore interface {
	app.PayloadObjectStore
	app.BoundedObjectReader
}
type nativeJobProcessor struct {
	state   nativeJobStateStore
	objects nativeJobObjectStore
}

// Bounded readers reject both size and metadata constraints with ErrConflict;
// do not guess the provider-specific cause or keep retrying an invalid object.
var errWorkerBoundedPayloadRejected = errors.New("outbox payload violates bounded read constraints")

func newNativeJobProcessor(state nativeJobStateStore, objects app.ObjectStore) (*nativeJobProcessor, error) {
	if missingWorkerPort(state) || missingWorkerPort(objects) {
		return nil, errors.New("native worker state and object ports are required")
	}
	bounded, ok := objects.(nativeJobObjectStore)
	if !ok {
		return nil, errors.New("native worker requires bounded payload lifecycle object storage")
	}
	return &nativeJobProcessor{state, bounded}, nil
}
func missingWorkerPort(port any) bool {
	if port == nil {
		return true
	}
	v := reflect.ValueOf(port)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan:
		return v.IsNil()
	default:
		return false
	}
}
func (p *nativeJobProcessor) Process(ctx context.Context, job postgres.ClaimedJob) error {
	if p == nil {
		return errors.New("native worker processor is required")
	}
	return processJobInternal(ctx, p.state, p.objects, job, true)
}
func supportedWorkerJob(kind string) bool {
	switch kind {
	case "finalize_payload", "parse_sbom", "parse_vulnerability_scan", "parse_openapi_contract", "verify_attestation", "parse_vex", "sign_bundle", "verify_subject":
		return true
	default:
		return false
	}
}
func waitWorkerPoll(ctx context.Context, interval time.Duration) error {
	if ctx == nil {
		return errors.New("worker context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

var _ nativeJobStateStore = (*postgres.Store)(nil)
