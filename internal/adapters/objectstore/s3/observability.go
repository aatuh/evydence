package s3

import (
	"context"
	"io"

	"github.com/minio/minio-go/v7"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/platform/telemetry"
)

// Measurement delegates to the existing implementation without wrapping the
// store itself, so optional capabilities and cleanup ownership stay intact.
func (s *Store) Put(ctx context.Context, object app.Object) error {
	return telemetry.MeasureError(ctx, telemetry.OperationObjectWrite, func(c context.Context) error { return s.put(c, object) })
}
func (s *Store) Get(ctx context.Context, key string) (app.Object, error) {
	return telemetry.Measure(ctx, telemetry.OperationObjectRead, func(c context.Context) (app.Object, error) { return s.readObject(c, key) })
}
func (s *Store) GetBounded(ctx context.Context, key string, maximum int64) (app.Object, error) {
	return telemetry.Measure(ctx, telemetry.OperationObjectRead, func(c context.Context) (app.Object, error) { return s.getBounded(c, key, maximum) })
}
func (s *Store) ListObjectInventory(ctx context.Context, tenant string, cursor, limit int) (app.ObjectInventoryPage, error) {
	return telemetry.Measure(ctx, telemetry.OperationObjectList, func(c context.Context) (app.ObjectInventoryPage, error) {
		return s.listObjectInventory(c, tenant, cursor, limit)
	})
}
func (s *Store) StagePayload(ctx context.Context, payload app.ObjectPayload, reader io.Reader) (app.ObjectPayload, error) {
	return telemetry.Measure(ctx, telemetry.OperationObjectStage, func(c context.Context) (app.ObjectPayload, error) { return s.stagePayload(c, payload, reader) })
}
func (s *Store) FinalizePayload(ctx context.Context, payload app.ObjectPayload) (app.Object, error) {
	return telemetry.Measure(ctx, telemetry.OperationObjectFinalize, func(c context.Context) (app.Object, error) { return s.finalizePayload(c, payload) })
}

func (s *Store) VerifyObjectRetention(ctx context.Context, request app.ObjectRetentionRequest) (app.ObjectRetentionResult, error) {
	return telemetry.Measure(ctx, telemetry.OperationObjectRetention, func(c context.Context) (app.ObjectRetentionResult, error) { return s.verifyObjectRetention(c, request) })
}

func (s *Store) removeObject(ctx context.Context, key string) error {
	return telemetry.MeasureError(ctx, telemetry.OperationObjectDelete, func(c context.Context) error {
		return s.client.RemoveObject(c, s.bucket, key, minio.RemoveObjectOptions{})
	})
}
