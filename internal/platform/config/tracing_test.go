package config

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestTracingDefaultsAreDisabledAndProjectBoundedSettings(t *testing.T) {
	for _, role := range []Role{API, Worker} {
		cfg, err := Parse(roleEnvironment(t, role, false), role)
		if err != nil {
			t.Fatal(err)
		}
		settings := cfg.Runtime()
		if settings.TracingEnabled || settings.TracingEndpoint != "" || settings.TracingSamplePerMillion != 10000 || settings.TracingQueueSize != 128 || settings.TracingExportTimeout != 2*time.Second {
			t.Fatal("tracing was enabled implicitly or lost its bounded defaults")
		}
		cfg, err = Parse(roleEnvironment(t, role, true,
			"EVYDENCE_TRACING_ENABLED=true",
			"EVYDENCE_TRACING_ENDPOINT=https://PRIVATE_COLLECTOR.invalid:4318/v1/traces",
			"EVYDENCE_TRACING_SAMPLE_PER_MILLION=250000",
			"EVYDENCE_TRACING_QUEUE_SIZE=64",
			"EVYDENCE_TRACING_EXPORT_TIMEOUT_SECONDS=1"), role)
		if err != nil {
			t.Fatal("pure tracing validation attempted resolution or rejected TLS", err)
		}
		settings = cfg.Runtime()
		if !settings.TracingEnabled || settings.TracingSamplePerMillion != 250000 || settings.TracingQueueSize != 64 || settings.TracingExportTimeout != time.Second {
			t.Fatal("validated tracing settings did not reach the typed projection")
		}
		if strings.Contains(fmt.Sprintf("%v %+v %#v", cfg, settings, settings), "PRIVATE") {
			t.Fatal("tracing diagnostics exposed collector configuration")
		}
	}
}

func TestTracingRejectsUnsafeOrUnboundedConfigurationBeforeStartup(t *testing.T) {
	for _, test := range []struct {
		name  string
		extra []string
		want  error
	}{
		{"missing endpoint", []string{"EVYDENCE_TRACING_ENABLED=true"}, ErrMissingValue},
		{"http", []string{"EVYDENCE_TRACING_ENDPOINT=http://PRIVATE_COLLECTOR.invalid/v1/traces"}, ErrInvalidValue},
		{"loopback http", []string{"EVYDENCE_TRACING_ENDPOINT=http://127.0.0.1:4318/v1/traces"}, ErrInvalidValue},
		{"userinfo", []string{"EVYDENCE_TRACING_ENDPOINT=https://user:PRIVATE_PASSWORD@collector.invalid/v1/traces"}, ErrInvalidValue},
		{"query", []string{"EVYDENCE_TRACING_ENDPOINT=https://collector.invalid/v1/traces?token=PRIVATE_TOKEN"}, ErrInvalidValue},
		{"empty query", []string{"EVYDENCE_TRACING_ENDPOINT=https://collector.invalid/v1/traces?"}, ErrInvalidValue},
		{"fragment", []string{"EVYDENCE_TRACING_ENDPOINT=https://collector.invalid/v1/traces#PRIVATE_FRAGMENT"}, ErrInvalidValue},
		{"excessive sample", []string{"EVYDENCE_TRACING_SAMPLE_PER_MILLION=1000001"}, ErrInvalidValue},
		{"negative sample", []string{"EVYDENCE_TRACING_SAMPLE_PER_MILLION=-1"}, ErrInvalidValue},
		{"small queue", []string{"EVYDENCE_TRACING_QUEUE_SIZE=15"}, ErrInvalidValue},
		{"large queue", []string{"EVYDENCE_TRACING_QUEUE_SIZE=1025"}, ErrInvalidValue},
		{"zero timeout", []string{"EVYDENCE_TRACING_EXPORT_TIMEOUT_SECONDS=0"}, ErrInvalidValue},
		{"large timeout", []string{"EVYDENCE_TRACING_EXPORT_TIMEOUT_SECONDS=6"}, ErrInvalidValue},
		{"invalid switch", []string{"EVYDENCE_TRACING_ENABLED=PRIVATE_SWITCH"}, ErrInvalidValue},
	} {
		for _, role := range []Role{API, Worker} {
			t.Run(fmt.Sprintf("%s/role_%d", test.name, role), func(t *testing.T) {
				cfg, err := Parse(roleEnvironment(t, role, false, test.extra...), role)
				if !errors.Is(err, test.want) || !reflect.DeepEqual(cfg, Configuration{}) {
					t.Fatal("invalid tracing settings returned usable configuration", err)
				}
				if strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
					t.Fatal("tracing rejection disclosed operator input")
				}
			})
		}
	}
}
