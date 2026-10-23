package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/platform/telemetry"
)

var errRuntimeResourcesUnavailable = errors.New("runtime resource snapshot is unavailable")

// ReadRuntimeResources performs one bounded scalar SELECT through the existing
// read-only pool. It reads no payload/identity columns, loads no Ledger and
// never claims, renews, acknowledges or otherwise changes durable work.
func (s *Store) ReadRuntimeResources(ctx context.Context) (telemetry.RuntimeResources, error) {
	var empty telemetry.RuntimeResources
	if s == nil || s.pool == nil || s.packageReadPool == nil || ctx == nil {
		return empty, app.ErrValidation
	}
	ctx, cancel := context.WithTimeout(ctx, telemetry.RuntimeResourceTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	var result telemetry.RuntimeResources
	var oldest, eligible *time.Time
	err := s.packageReadPool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status = 'queued'),
		       count(*) FILTER (WHERE status = 'retrying'),
		       count(*) FILTER (WHERE status = 'running'),
		       count(*) FILTER (WHERE status = 'succeeded'),
		       count(*) FILTER (WHERE status = 'dead_letter'),
		       COALESCE(SUM(attempts), 0),
		       count(*) FILTER (WHERE status IN ('queued','retrying') AND run_after <= now()),
		       count(*) FILTER (WHERE status IN ('queued','retrying') AND run_after <= now() - $1 * interval '1 second'),
		       count(*) FILTER (WHERE status = 'running' AND (locked_at IS NULL OR locked_at <= now() - $1 * interval '1 second')),
		       min(created_at) FILTER (WHERE status IN ('queued','retrying')),
		       min(created_at) FILTER (WHERE status IN ('queued','retrying') AND run_after <= now())
		FROM outbox_jobs
	`, int(outboxLeaseDuration/time.Second)).Scan(
		&result.Queue.Queued, &result.Queue.Retrying, &result.Queue.Running,
		&result.Queue.Succeeded, &result.Queue.DeadLetter, &result.Queue.Attempts,
		&result.Queue.EligiblePending, &result.Queue.OverduePending, &result.Queue.ExpiredLeases,
		&oldest, &eligible,
	)
	if err != nil {
		if cause := ctx.Err(); cause != nil {
			return empty, cause
		}
		return empty, errRuntimeResourcesUnavailable
	}
	if oldest != nil {
		result.Queue.OldestPendingAt = oldest.UTC()
	}
	if eligible != nil {
		result.Queue.OldestEligibleAt = eligible.UTC()
	}
	result.PrimaryPool = runtimePoolResources(s.pool.Stat())
	result.ReadPool = runtimePoolResources(s.packageReadPool.Stat())
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if !result.Valid() {
		return empty, errRuntimeResourcesUnavailable
	}
	return result, nil
}

func runtimePoolResources(stat *pgxpool.Stat) telemetry.PoolResources {
	return telemetry.PoolResources{
		Acquired: stat.AcquiredConns(), Idle: stat.IdleConns(),
		Constructing: stat.ConstructingConns(), Max: stat.MaxConns(),
		Acquires: stat.AcquireCount(), CanceledAcquires: stat.CanceledAcquireCount(),
		WaitedAcquires:  stat.EmptyAcquireCount(),
		AcquireDuration: stat.AcquireDuration(), AcquireWait: stat.EmptyAcquireWaitTime(),
	}
}

var _ telemetry.ResourceReader = (*Store)(nil)
