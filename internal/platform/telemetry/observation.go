// Package telemetry defines bounded operational observations. Core code depends
// on this port; concrete metrics and tracing SDKs belong in adapters.
package telemetry

import (
	"context"
	"time"
)

type Operation string

const (
	OperationUnknown                Operation = "other"
	OperationProviderSign           Operation = "provider_sign"
	OperationProviderOIDCDiscovery  Operation = "provider_oidc_discovery"
	OperationProviderIdentity       Operation = "provider_identity_validation"
	OperationProviderTransparency   Operation = "provider_transparency_fetch"
	OperationProviderCosign         Operation = "provider_cosign_verify"
	OperationWorkerClaim            Operation = "worker_claim"
	OperationWorkerProcess          Operation = "worker_process"
	OperationWorkerComplete         Operation = "worker_complete"
	OperationWorkerFail             Operation = "worker_fail"
	OperationWorkerDefer            Operation = "worker_defer"
	OperationParseSBOM              Operation = "parse_sbom"
	OperationParseVulnerabilityScan Operation = "parse_vulnerability_scan"
	OperationParseOpenAPI           Operation = "parse_openapi_contract"
	OperationParseVEX               Operation = "parse_vex"
	OperationVerifyAttestation      Operation = "verify_attestation"
	OperationSigning                Operation = "signing"
	OperationVerification           Operation = "verification"
	OperationObjectReconciliation   Operation = "object_reconciliation"
	OperationPackageGeneration      Operation = "package_generation"
	OperationObjectRead             Operation = "object_read"
	OperationObjectWrite            Operation = "object_write"
	OperationObjectDelete           Operation = "object_delete"
	OperationObjectList             Operation = "object_list"
	OperationDatabaseAcquire        Operation = "database_acquire"
)

var operationCatalog = [...]Operation{
	OperationUnknown, OperationProviderSign, OperationProviderOIDCDiscovery,
	OperationProviderIdentity, OperationProviderTransparency, OperationProviderCosign,
	OperationWorkerClaim, OperationWorkerProcess, OperationWorkerComplete,
	OperationWorkerFail, OperationWorkerDefer, OperationParseSBOM,
	OperationParseVulnerabilityScan, OperationParseOpenAPI, OperationParseVEX,
	OperationVerifyAttestation, OperationSigning, OperationVerification,
	OperationObjectReconciliation, OperationPackageGeneration, OperationObjectRead,
	OperationObjectWrite, OperationObjectDelete, OperationObjectList,
	OperationDatabaseAcquire,
}

// Canonical discards arbitrary values before they become names or labels.
func (o Operation) Canonical() Operation {
	for _, known := range operationCatalog {
		if o == known {
			return known
		}
	}
	return OperationUnknown
}

func Operations() []Operation { return append([]Operation(nil), operationCatalog[:]...) }

type Outcome string

const (
	OutcomeUnknown   Outcome = "unknown"
	OutcomeSucceeded Outcome = "succeeded"
	OutcomeFailed    Outcome = "failed"
	OutcomeRejected  Outcome = "rejected"
	OutcomeUncertain Outcome = "uncertain"
	OutcomeCanceled  Outcome = "canceled"
)

var outcomeCatalog = [...]Outcome{
	OutcomeUnknown, OutcomeSucceeded, OutcomeFailed, OutcomeRejected,
	OutcomeUncertain, OutcomeCanceled,
}

func (o Outcome) Canonical() Outcome {
	for _, known := range outcomeCatalog {
		if o == known {
			return known
		}
	}
	return OutcomeUnknown
}

func Outcomes() []Outcome { return append([]Outcome(nil), outcomeCatalog[:]...) }

// Event has no free-form attributes, identifiers, errors or payloads. Attempt
// is a numeric measurement, never a label. Events are not durable audit records.
type Event struct {
	Operation Operation
	Outcome   Outcome
	Duration  time.Duration
	Attempt   uint32
}

// Observer implementations must be concurrent-safe and nonblocking, perform no
// synchronous network/storage I/O, and never retain the caller's context. An
// adapter owning asynchronous export also owns its queue bounds and shutdown.
type Observer interface {
	Observe(context.Context, Event)
}

type observerKey struct{}
type observerScope struct{ observer Observer }

// WithObserver preserves the parent cancellation and values. A nil observer
// explicitly disables recording in this child, without changing its parent.
func WithObserver(ctx context.Context, observer Observer) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, observerKey{}, observerScope{observer})
}

// Record delivers a normalized value copy, even after request cancellation.
// A missing or faulty observer cannot change the application's result. Blocking
// observers violate the port contract; Record starts no detached work to hide it.
func Record(ctx context.Context, event Event) {
	if ctx == nil {
		return
	}
	scope, ok := ctx.Value(observerKey{}).(observerScope)
	if !ok || scope.observer == nil {
		return
	}
	event.Operation = event.Operation.Canonical()
	event.Outcome = event.Outcome.Canonical()
	if event.Duration < 0 {
		event.Duration = 0
	}
	defer func() { _ = recover() }()
	scope.observer.Observe(ctx, event)
}
