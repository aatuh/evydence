package config

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

func TestWorkerProbeScopeIsIndependentOfRuntimeDependencies(t *testing.T) {
	e, err := Capture([]string{
		"ENV=production", "EVYDENCE_WORKER_HEALTH_ADDR=[::1]:8181",
		"EVYDENCE_DATABASE_URL=PRIVATE_INVALID_DSN", "EVYDENCE_DATABASE_URL_FILE=relative/PRIVATE_MISSING",
		"EVYDENCE_RUNTIME_PROFILE=local_memory", "EVYDENCE_OBJECT_STORE=s3",
		"EVYDENCE_S3_SECRET_ACCESS_KEY_FILE=/PRIVATE_MISSING/key", "EVYDENCE_S3_ENDPOINT=PRIVATE_INVALID/endpoint",
		"EVYDENCE_WORKER_METRICS_TOKEN_FILE=/PRIVATE_MISSING/token", "EVYDENCE_WORKER_METRICS_ADDR=PUBLIC_INVALID",
		"EVYDENCE_WORKER_POLL_INTERVAL=PRIVATE_INVALID", "EVYDENCE_WORKER_BATCH_SIZE=0",
		"PGPORT=PRIVATE_INVALID", "HTTPS_PROXY=PRIVATE_INVALID", "SSL_CERT_FILE=   ",
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := Prepare(e, WorkerProbe)
	if err != nil {
		t.Fatal("probe evaluated unused dependency settings", err)
	}
	c, err := Resolve(t.Context(), p, true)
	if err != nil || c.Role() != WorkerProbe || !c.Production() || c.Worker().HealthAddress != netip.MustParseAddrPort("[::1]:8181") || c.Runtime().DatabaseURL.IsSet() || c.Storage().Kind != "" || c.Worker().MetricsAddress.IsValid() || !reflect.DeepEqual(c.native, NativeSettings{}) {
		t.Fatal("probe scope loaded a runtime dependency or lost its address", err)
	}
	if _, enabled := c.WorkerMetricsTokenHash(); enabled {
		t.Fatal("probe resolved daemon metrics credentials")
	}
}

func TestWorkerProbeScopeValidatesApplicableSettings(t *testing.T) {
	for _, tc := range []struct {
		entry string
		want  error
	}{
		{"EVYDENCE_WORKER_HEALTH_ADDR=0.0.0.0:8181", ErrInvalidValue},
		{"EVYDENCE_WORKER_HEALTH_ADDR=127.0.0.1:0", ErrInvalidValue},
		{"EVYDENCE_WORKER_HEALTH_ADDR=PRIVATE_HOST:8181", ErrInvalidValue},
		{"EVYDENCE_WORKER_HEALTH_ADDR=[::1%PRIVATE_ZONE]:8181", ErrInvalidValue},
		{"EVYDENCE_LOG_LEVEL=PRIVATE_INVALID", ErrInvalidValue},
		{"EVYDENCE_LOG_FORMAT=PRIVATE_INVALID", ErrInvalidValue},
		{"EVYDENCE_PRIVATE_UNKNOWN=PRIVATE_VALUE", ErrUnknownOption},
	} {
		e, err := Capture([]string{"ENV=production", tc.entry})
		if err != nil {
			t.Fatal(err)
		}
		c, err := Parse(e, WorkerProbe)
		if !errors.Is(err, tc.want) || !reflect.DeepEqual(c, Configuration{}) {
			t.Fatal("probe accepted invalid settings or returned partial configuration", err)
		}
	}
	e, err := Capture(nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(e, WorkerProbe)
	if err != nil || c.Worker().HealthAddress != netip.MustParseAddrPort("127.0.0.1:8081") || c.Runtime().LogLevel != "info" || c.Runtime().LogFormat != "json" {
		t.Fatal("probe did not use canonical defaults", err)
	}
}
