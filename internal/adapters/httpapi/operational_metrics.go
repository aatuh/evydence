package httpapi

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/platform/telemetry"
)

// OperationalMetrics records process-wide measurements without arbitrary
// attributes. Snapshot callers must authorize explicit instance authority.
// Implementations must not perform I/O while recording or retain contexts.
type OperationalMetrics interface {
	telemetry.Observer
	ObserveHTTP(method, route string, status int, duration time.Duration)
	Snapshot(context.Context) (string, error)
}

// MetricRoutes returns copied, code-owned route templates for a recorder's
// allowlist. Request paths and path-variable values never populate this list.
func MetricRoutes() []string {
	definitions := (&Server{}).routeDefinitions()
	routes := make([]string, 0, len(definitions))
	for _, definition := range definitions {
		routes = append(routes, definition.path)
	}
	return routes
}

func recordHTTPMetrics(observer OperationalMetrics, method, route string, status int, duration time.Duration) {
	if observer == nil {
		return
	}
	// Recording is diagnostic: a faulty embedded observer must not replace a
	// response or obscure an existing handler panic.
	defer func() { _ = recover() }()
	observer.ObserveHTTP(method, route, status, duration)
}
