package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aatuh/evydence/internal/app"
)

// CheckOutboxReadiness detects work that has stopped making progress. An
// eligible queued/retrying job gets the same five-minute grace as a worker
// lease; future scheduled work and historical terminal jobs do not block API
// readiness. Running work must have an unexpired lease. This global process
// dependency returns no tenant facts and never claims or modifies a job.
//
// EXISTS uses the active claim/reclaim indexes, not an aggregate over retained
// job history. The caller supplies the deadline and short-lived result cache.
func (s *Store) CheckOutboxReadiness(ctx context.Context) error {
	if s == nil || s.pool == nil || ctx == nil {
		return app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var stalled bool
	if err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM outbox_jobs
			WHERE status IN ('queued', 'retrying')
			  AND run_after <= now() - $1 * interval '1 second'
		) OR EXISTS (
			SELECT 1 FROM outbox_jobs
			WHERE status = 'running'
			  AND (locked_at IS NULL OR locked_at <= now() - $1 * interval '1 second')
		)
	`, int(outboxLeaseDuration/time.Second)).Scan(&stalled); err != nil {
		return fmt.Errorf("check outbox readiness: %w", err)
	}
	if stalled {
		return errors.New("outbox progress is unavailable")
	}
	return nil
}
