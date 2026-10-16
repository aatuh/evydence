package metrics

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/aatuh/evydence/internal/platform/telemetry"
)

func captureRuntimeResources(ctx context.Context, reader telemetry.ResourceReader) (result telemetry.RuntimeResources, err error) {
	defer func() {
		if recover() != nil {
			result = telemetry.RuntimeResources{}
			err = errSnapshot
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, telemetry.RuntimeResourceTimeout)
	defer cancel()
	result, err = reader.ReadRuntimeResources(ctx)
	if cause := ctx.Err(); cause != nil {
		return telemetry.RuntimeResources{}, cause
	}
	if err != nil || !result.Valid() {
		return telemetry.RuntimeResources{}, errSnapshot
	}
	return result, nil
}

type runtimeResourceCollector struct{ metrics []prometheus.Metric }

func (c *runtimeResourceCollector) Describe(out chan<- *prometheus.Desc) {
	for _, metric := range c.metrics {
		out <- metric.Desc()
	}
}
func (c *runtimeResourceCollector) Collect(out chan<- prometheus.Metric) {
	for _, metric := range c.metrics {
		out <- metric
	}
}

func newRuntimeResourceCollector(r telemetry.RuntimeResources, now time.Time) *runtimeResourceCollector {
	c := &runtimeResourceCollector{}
	desc := func(name, help string, labels ...string) *prometheus.Desc {
		return prometheus.NewDesc(name, help, labels, nil)
	}
	add := func(d *prometheus.Desc, kind prometheus.ValueType, value float64, labels ...string) {
		c.metrics = append(c.metrics, prometheus.MustNewConstMetric(d, kind, value, labels...))
	}
	connections := desc("evydence_db_pool_connections", "Current process pool connections by fixed pool and state; maximum is the configured capacity.", "pool", "state")
	acquires := desc("evydence_db_pool_acquires_total", "Successful connection acquires in this process.", "pool")
	canceled := desc("evydence_db_pool_canceled_acquires_total", "Connection acquires canceled while waiting in this process.", "pool")
	waited := desc("evydence_db_pool_waited_acquires_total", "Successful connection acquires which waited for a resource; a subset of successful acquires.", "pool")
	duration := desc("evydence_db_pool_acquire_duration_seconds_total", "Total duration of successful connection acquires in this process.", "pool")
	wait := desc("evydence_db_pool_wait_seconds_total", "Total wait time of successful connection acquires which found the pool empty.", "pool")
	for _, pool := range []struct {
		name  string
		stats telemetry.PoolResources
	}{{"primary", r.PrimaryPool}, {"package_read", r.ReadPool}} {
		p := pool.stats
		for _, state := range []struct {
			name  string
			value int32
		}{{"acquired", p.Acquired}, {"idle", p.Idle}, {"constructing", p.Constructing}, {"maximum", p.Max}} {
			add(connections, prometheus.GaugeValue, float64(state.value), pool.name, state.name)
		}
		add(acquires, prometheus.CounterValue, float64(p.Acquires), pool.name)
		add(canceled, prometheus.CounterValue, float64(p.CanceledAcquires), pool.name)
		add(waited, prometheus.CounterValue, float64(p.WaitedAcquires), pool.name)
		add(duration, prometheus.CounterValue, p.AcquireDuration.Seconds(), pool.name)
		add(wait, prometheus.CounterValue, p.AcquireWait.Seconds(), pool.name)
	}
	q := r.Queue
	jobs := desc("evydence_queue_jobs", "Retained instance-wide jobs by fixed state; repeated across process targets, not additive across targets.", "state")
	for _, state := range []struct {
		name  string
		value int64
	}{{"queued", q.Queued}, {"retrying", q.Retrying}, {"running", q.Running}, {"succeeded", q.Succeeded}, {"dead_letter", q.DeadLetter}} {
		add(jobs, prometheus.GaugeValue, float64(state.value), state.name)
	}
	for _, gauge := range []struct {
		name, help string
		value      float64
	}{
		{"evydence_queue_attempts", "Sum of current attempt numbers on retained jobs; not a durable attempt-event counter.", float64(q.Attempts)},
		{"evydence_queue_eligible_jobs", "Queued or retrying jobs whose run-after time is due.", float64(q.EligiblePending)},
		{"evydence_queue_overdue_jobs", "Eligible queued or retrying jobs at least five minutes past run-after.", float64(q.OverduePending)},
		{"evydence_queue_expired_leases", "Running jobs with a missing or expired five-minute lease.", float64(q.ExpiredLeases)},
		{"evydence_queue_oldest_pending_age_seconds", "Age since creation of the oldest queued or retrying job, including future scheduled work.", runtimeAge(now, q.OldestPendingAt)},
		{"evydence_queue_oldest_eligible_age_seconds", "Age since creation of the oldest currently eligible queued or retrying job.", runtimeAge(now, q.OldestEligibleAt)},
	} {
		add(desc(gauge.name, gauge.help), prometheus.GaugeValue, gauge.value)
	}
	return c
}

func runtimeAge(now, created time.Time) float64 {
	if created.IsZero() {
		return 0
	}
	return max(now.Sub(created).Seconds(), 0)
}
