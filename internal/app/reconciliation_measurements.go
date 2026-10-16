package app

import (
	"context"

	"github.com/aatuh/evydence/internal/platform/telemetry"
)

func ReconcileObjectPayloads(ctx context.Context, lifecycle ObjectPayloadLifecycleStore, metadata ObjectPayloadReconciliationStore, objects objectPayloadGetter, request ObjectReconciliationRequest) (ObjectReconciliationReceipt, error) {
	return telemetry.Measure(ctx, telemetry.OperationObjectReconciliation, func(callCtx context.Context) (ObjectReconciliationReceipt, error) {
		return reconcileObjectPayloads(callCtx, lifecycle, metadata, objects, request)
	})
}
