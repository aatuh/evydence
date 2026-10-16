package wiring

import (
	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/telemetry/metrics"
)

// BuildOperationalMetrics owns one private recorder per daemon. Core services
// receive only context-scoped neutral observers; no SDK enters those services.
func BuildOperationalMetrics(process Process) (*metrics.Registry, error) {
	config := metrics.Config{Service: string(process)}
	if process == API {
		config.Routes = httpapi.MetricRoutes()
	}
	return metrics.New(config)
}
