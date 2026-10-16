package wiring

import (
	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/telemetry/metrics"
	"github.com/aatuh/evydence/internal/platform/telemetry"
)

// BuildOperationalMetrics owns one private recorder per daemon. Core services
// receive only context-scoped neutral observers; no SDK enters those services.
func BuildOperationalMetrics(process Process, resources telemetry.ResourceReader) (*metrics.Registry, error) {
	config := metrics.Config{Service: string(process), ResourceReader: resources}
	if process == API {
		config.Routes = httpapi.MetricRoutes()
	}
	return metrics.New(config)
}
