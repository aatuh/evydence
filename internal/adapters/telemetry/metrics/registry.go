// Package metrics adapts bounded operational observations to a private
// Prometheus registry. Scrape callers must enforce instance authorization.
package metrics

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	toolkitmetrics "github.com/aatuh/api-toolkit/contrib/v3/middleware/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"

	"github.com/aatuh/evydence/internal/platform/telemetry"
)

const (
	MaxRoutes        = 256
	MaxHTTPSeries    = 1024
	maxRouteBytes    = 192
	maxSnapshotBytes = 8 << 20
)

var (
	errInvalidConfig = errors.New("invalid operational metrics configuration")
	errSnapshot      = errors.New("operational metrics snapshot is unavailable")
)

type Config struct {
	Service string
	// Routes must come from code-owned route contracts, never request paths.
	Routes         []string
	ResourceReader telemetry.ResourceReader
}

type httpLabels struct{ method, route, status string }

type Registry struct {
	service      string
	resources    telemetry.ResourceReader
	registry     *prometheus.Registry
	http         *toolkitmetrics.PrometheusRecorder
	operations   *prometheus.CounterVec
	durations    *prometheus.HistogramVec
	attempts     *prometheus.HistogramVec
	httpOutcomes *prometheus.CounterVec
	overflow     prometheus.Counter
	routes       map[string]struct{}
	mu           sync.Mutex
	httpSeries   map[httpLabels]struct{}
}

func New(cfg Config) (*Registry, error) {
	if (cfg.Service != "api" && cfg.Service != "worker") || len(cfg.Routes) > MaxRoutes {
		return nil, errInvalidConfig
	}
	r := &Registry{
		service: cfg.Service, resources: cfg.ResourceReader,
		registry: prometheus.NewRegistry(), routes: make(map[string]struct{}, len(cfg.Routes)),
		httpSeries: make(map[httpLabels]struct{}),
	}
	for _, route := range cfg.Routes {
		if !validRoute(route) {
			return nil, errInvalidConfig
		}
		r.routes[route] = struct{}{}
	}
	registerer := prometheus.WrapRegistererWith(prometheus.Labels{"service": cfg.Service}, r.registry)
	var err error
	r.http, err = toolkitmetrics.NewPrometheusRecorderChecked(registerer, nil)
	if err != nil {
		return nil, errInvalidConfig
	}
	r.operations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "evydence_operations_total", Help: "Completed operational observations by fixed operation and outcome.",
	}, []string{"operation", "outcome"})
	r.durations = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "evydence_operation_duration_seconds", Help: "Operational duration in seconds.",
		Buckets: []float64{0.001, 0.01, 0.1, 0.5, 1, 5, 15, 60},
	}, []string{"operation", "outcome"})
	r.attempts = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "evydence_operation_attempt_number", Help: "Attempt number measured as a value, never as a label.",
		Buckets: []float64{1, 2, 3, 5, 10},
	}, []string{"operation", "outcome"})
	r.httpOutcomes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "evydence_http_outcomes_total", Help: "HTTP outcomes retained independently of the detailed series budget.",
	}, []string{"outcome"})
	r.overflow = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "evydence_telemetry_series_overflow_total", Help: "HTTP observations grouped into the fixed overflow series after the label budget is exhausted.",
	})
	for _, collector := range []prometheus.Collector{r.operations, r.durations, r.attempts, r.httpOutcomes, r.overflow} {
		if registerer.Register(collector) != nil {
			return nil, errInvalidConfig
		}
	}
	return r, nil
}

func validRoute(route string) bool {
	if len(route) == 0 || len(route) > maxRouteBytes || route[0] != '/' {
		return false
	}
	for _, char := range route {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("/-_{}.~", char) {
			continue
		}
		return false
	}
	return true
}

func (r *Registry) canonicalRoute(pattern string) string {
	if len(pattern) > maxRouteBytes+16 {
		return "unknown"
	}
	if method, route, found := strings.Cut(pattern, " "); found {
		if canonicalMethod(method) == "OTHER" || canonicalMethod(method) == "UNKNOWN" {
			return "unknown"
		}
		pattern = route
	}
	if _, known := r.routes[pattern]; known {
		return pattern
	}
	return "unknown"
}

// The toolkit also normalizes methods. This guard bounds the application's
// series-budget keys before those keys reach the toolkit recorder.
func canonicalMethod(method string) string {
	if len(method) > 16 {
		return "OTHER"
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	switch method {
	case "":
		return "UNKNOWN"
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace:
		return method
	default:
		return "OTHER"
	}
}

func (r *Registry) ObserveHTTP(method, route string, status int, duration time.Duration) {
	if r == nil {
		return
	}
	if status < 100 || status > 599 {
		status = 0
	}
	outcome := telemetry.OutcomeSucceeded
	switch {
	case status == 0:
		outcome = telemetry.OutcomeUncertain
	case status >= 500:
		outcome = telemetry.OutcomeFailed
	case status >= 400:
		outcome = telemetry.OutcomeRejected
	}
	r.httpOutcomes.WithLabelValues(string(outcome)).Inc()
	key := httpLabels{canonicalMethod(method), r.canonicalRoute(route), strconv.Itoa(status)}
	r.mu.Lock()
	if _, exists := r.httpSeries[key]; !exists {
		if len(r.httpSeries) < MaxHTTPSeries {
			r.httpSeries[key] = struct{}{}
		} else {
			key = httpLabels{"OTHER", "unknown", "0"}
			r.overflow.Inc()
		}
	}
	r.mu.Unlock()
	labels := toolkitmetrics.Labels{"method": key.method, "route": key.route, "status": key.status}
	r.http.IncCounter("http_requests_total", labels)
	r.http.ObserveHistogram("http_request_duration_seconds", max(duration.Seconds(), 0), labels)
}

func (r *Registry) Observe(_ context.Context, event telemetry.Event) {
	if r == nil {
		return
	}
	operation, outcome := string(event.Operation.Canonical()), string(event.Outcome.Canonical())
	r.operations.WithLabelValues(operation, outcome).Inc()
	r.durations.WithLabelValues(operation, outcome).Observe(max(event.Duration.Seconds(), 0))
	if event.Attempt != 0 {
		r.attempts.WithLabelValues(operation, outcome).Observe(float64(event.Attempt))
	}
}

// Snapshot contains only this registry's bounded families. An optional resource
// reader supplies one deadline-bound scalar projection after authorization by
// the caller. No global default registry or caller context is retained.
func (r *Registry) Snapshot(ctx context.Context) (string, error) {
	if r == nil || ctx == nil {
		return "", errSnapshot
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	families, err := r.registry.Gather()
	if err != nil {
		return "", errSnapshot
	}
	if r.resources != nil {
		resources, err := captureRuntimeResources(ctx, r.resources)
		if err != nil {
			return "", err
		}
		// A per-scrape collector owns a value copy. Shared mutable gauges would
		// let concurrent requests mix samples or retain stale values on failure.
		local := prometheus.NewRegistry()
		registerer := prometheus.WrapRegistererWith(prometheus.Labels{"service": r.service}, local)
		if err := registerer.Register(newRuntimeResourceCollector(resources, time.Now())); err != nil {
			return "", errSnapshot
		}
		sampled, err := local.Gather()
		if err != nil {
			return "", errSnapshot
		}
		families = append(families, sampled...)
	}
	var output boundedExposition
	for _, family := range families {
		if _, err := expfmt.MetricFamilyToText(&output, family); err != nil {
			return "", errSnapshot
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return output.String(), nil
}

type boundedExposition struct{ builder strings.Builder }

func (w *boundedExposition) Write(p []byte) (int, error) {
	if len(p) > maxSnapshotBytes-w.builder.Len() {
		return 0, errSnapshot
	}
	return w.builder.Write(p)
}

func (w *boundedExposition) WriteString(value string) (int, error) {
	if len(value) > maxSnapshotBytes-w.builder.Len() {
		return 0, errSnapshot
	}
	return w.builder.WriteString(value)
}

func (w *boundedExposition) WriteByte(value byte) error {
	if w.builder.Len() >= maxSnapshotBytes {
		return errSnapshot
	}
	return w.builder.WriteByte(value)
}

func (w *boundedExposition) String() string { return w.builder.String() }

var _ telemetry.Observer = (*Registry)(nil)
