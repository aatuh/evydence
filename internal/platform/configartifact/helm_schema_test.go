package configartifact

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/platform/config"
)

// This checks chart declaration drift against runtime metadata. Rendering and
// process-startup behavior require their separate deployment checks.
func TestHelmBoundsMatchRuntimeSchema(t *testing.T) {
	body, err := os.ReadFile("../../../deploy/helm/evydence/values.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	definitions := make(map[string]config.Definition)
	for _, definition := range config.Definitions() {
		definitions[definition.Name] = definition
	}
	for _, binding := range []struct{ field, option string }{
		{"cleanupTimeoutSeconds", "EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS"},
		{"api.readHeaderTimeoutSeconds", "EVYDENCE_HTTP_READ_HEADER_TIMEOUT_SECONDS"},
		{"api.readTimeoutSeconds", "EVYDENCE_HTTP_READ_TIMEOUT_SECONDS"},
		{"api.writeTimeoutSeconds", "EVYDENCE_HTTP_WRITE_TIMEOUT_SECONDS"},
		{"api.idleTimeoutSeconds", "EVYDENCE_HTTP_IDLE_TIMEOUT_SECONDS"},
		{"api.shutdownTimeoutSeconds", "EVYDENCE_HTTP_SHUTDOWN_TIMEOUT_SECONDS"},
		{"api.maxHeaderBytes", "EVYDENCE_HTTP_MAX_HEADER_BYTES"},
		{"api.maxURLBytes", "EVYDENCE_HTTP_MAX_URL_BYTES"},
		{"api.maxInFlightRequests", "EVYDENCE_HTTP_MAX_IN_FLIGHT_REQUESTS"},
		{"api.maxConcurrentUploads", "EVYDENCE_HTTP_MAX_CONCURRENT_UPLOADS"},
		{"api.rateLimitRequestsPerMinute", "EVYDENCE_RATE_LIMIT_REQUESTS_PER_MINUTE"},
		{"api.authenticationFailuresPerMinute", "EVYDENCE_AUTH_FAILURES_PER_MINUTE"},
		{"api.expensiveTenantRequestsPerMinute", "EVYDENCE_EXPENSIVE_TENANT_REQUESTS_PER_MINUTE"},
		{"api.rateLimitBucketCapacity", "EVYDENCE_RATE_LIMIT_BUCKET_CAPACITY"},
		{"worker.shutdownTimeoutSeconds", "EVYDENCE_WORKER_SHUTDOWN_TIMEOUT_SECONDS"},
	} {
		t.Run(binding.field, func(t *testing.T) {
			definition, ok := definitions[binding.option]
			if !ok || (definition.Kind != config.Integer && definition.Kind != config.Seconds) {
				t.Fatal("chart binding lost its integer runtime definition")
			}
			property, err := helmProperty(body, strings.Split(binding.field, "."))
			if err != nil || property.Type != "integer" || property.Minimum == nil || property.Maximum == nil || *property.Minimum != definition.Min || *property.Maximum != definition.Max {
				t.Fatalf("%s must declare integer bounds %d..%d from %s; property=%+v error=%v", binding.field, definition.Min, definition.Max, binding.option, property, err)
			}
		})
	}
}

type helmSchemaProperty struct {
	Type       string                     `json:"type"`
	Minimum    *int64                     `json:"minimum"`
	Maximum    *int64                     `json:"maximum"`
	Properties map[string]json.RawMessage `json:"properties"`
}

func helmProperty(body []byte, fields []string) (helmSchemaProperty, error) {
	var property helmSchemaProperty
	if err := json.Unmarshal(body, &property); err != nil {
		return property, err
	}
	for _, field := range fields {
		child, ok := property.Properties[field]
		if !ok {
			return helmSchemaProperty{}, fmt.Errorf("missing chart property %s", field)
		}
		property = helmSchemaProperty{}
		if err := json.Unmarshal(child, &property); err != nil {
			return property, err
		}
	}
	return property, nil
}
