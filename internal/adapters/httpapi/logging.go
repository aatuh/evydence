package httpapi

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/aatuh/evydence/internal/platform/logging"
	"github.com/aatuh/evydence/internal/platform/telemetry"
)

type requestLogKey struct{}

// Routes can replace the request/context while authentication still publishes
// only the verified tenant to the outer request observer. Never copy actors,
// credentials, names or input bodies into this carrier.
type requestLogScope struct {
	mu     sync.Mutex
	tenant string
	retry  *logging.RetryClass
}

func recordLogTenant(ctx context.Context, tenant string) {
	if scope, ok := ctx.Value(requestLogKey{}).(*requestLogScope); ok {
		scope.mu.Lock()
		scope.tenant = tenant
		scope.mu.Unlock()
	}
}

func recordLogRetry(ctx context.Context, retryable bool) {
	if scope, ok := ctx.Value(requestLogKey{}).(*requestLogScope); ok {
		retry := logging.NoRetry
		if retryable {
			retry = logging.Transient
		}
		scope.mu.Lock()
		scope.retry = &retry
		scope.mu.Unlock()
	}
}

func (s *Server) observeRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if s.logger != nil {
			ctx = logging.WithLogger(ctx, s.logger)
		}
		if s.operationalMetrics != nil {
			ctx = telemetry.WithObserver(ctx, s.operationalMetrics)
		}
		metricRoute := "unknown"
		// Resolve only bounded paths to a canonical registered operation. Never log
		// the URL, query, headers, IP, path variables or an arbitrary unmatched path.
		if len(r.URL.Path) <= defaultMaxURLBytes {
			_, pattern := s.mux.Handler(r)
			if op := s.logOperations[pattern]; op != "" {
				ctx = logging.WithOperation(ctx, op)
				metricRoute = pattern
			}
		}
		scope := &requestLogScope{}
		ctx = context.WithValue(ctx, requestLogKey{}, scope)
		r = r.WithContext(ctx)
		status := &failureStatusWriter{ResponseWriter: w}
		started := time.Now()
		completed := false
		defer func() {
			fields := logging.Fields{Status: status.status, Duration: time.Since(started), Result: logging.Uncertain, Retry: logging.Transient}
			scope.mu.Lock()
			fields.TenantID = scope.tenant
			retry := scope.retry
			scope.mu.Unlock()
			if completed {
				if fields.Status == 0 {
					fields.Status = http.StatusOK
				}
				switch {
				case fields.Status >= 500:
					fields.Result = logging.Failed
				case fields.Status >= 400:
					fields.Result = logging.Rejected
					fields.Retry = logging.Permanent
					if fields.Status == http.StatusTooManyRequests || fields.Status == http.StatusRequestTimeout || fields.Status == http.StatusTooEarly {
						fields.Retry = logging.Transient
					}
				default:
					fields.Result = logging.Succeeded
					fields.Retry = logging.NoRetry
				}
			}
			if completed && retry != nil {
				fields.Retry = *retry
			}
			logging.Emit(ctx, logging.HTTPRequest, fields)
			metricStatus := fields.Status
			if !completed {
				metricStatus = 0
			}
			recordHTTPMetrics(s.operationalMetrics, r.Method, metricRoute, metricStatus, fields.Duration)
		}()
		next.ServeHTTP(status, r)
		completed = true
	})
}
