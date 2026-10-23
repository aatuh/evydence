package config_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/platform/config"
)

func TestParseUsesOnlyCapturedInputAndDoesNotResolveReferences(t *testing.T) {
	for _, role := range []config.Role{config.API, config.Worker, config.Migrate, config.CLI} {
		entries := []string{"ENV=development", "EVYDENCE_RUNTIME_PROFILE=postgres", "EVYDENCE_DATABASE_URL=host=PRIVATE_DATABASE dbname=evidence sslmode=verify-full sslrootcert=/PRIVATE_NONEXISTENT/root.pem", "PGSERVICE=PRIVATE_SERVICE", "PGSERVICEFILE=/PRIVATE_NONEXISTENT/service", "PGPASSFILE=/PRIVATE_NONEXISTENT/pass", "AWS_CONFIG_FILE=/PRIVATE_NONEXISTENT/aws", "GOOGLE_APPLICATION_CREDENTIALS=/PRIVATE_NONEXISTENT/google", "AZURE_FEDERATED_TOKEN_FILE=/PRIVATE_NONEXISTENT/azure", "EVYDENCE_WORKER_METRICS_TOKEN_FILE=/PRIVATE_NONEXISTENT/metrics"}
		environment, err := config.Capture(entries)
		if err != nil {
			t.Fatal(err)
		}
		entries[0] = "ENV=production"
		t.Setenv("ENV", "production")
		t.Setenv("EVYDENCE_RUNTIME_PROFILE", "PRIVATE_BAD_PROFILE")
		t.Setenv("AWS_MAX_ATTEMPTS", "PRIVATE_BAD_NUMBER")
		cfg, err := config.Parse(environment, role)
		if err != nil || cfg.Role() != role || cfg.Production() || cfg.Runtime().LogFormat != "json" {
			t.Fatal("pure parse consulted ambient input or external references", role, err)
		}
		for _, value := range []any{cfg, &cfg, cfg.Native(), cfg.Runtime()} {
			data, err := json.Marshal(value)
			if err != nil || strings.Contains(string(data), "PRIVATE") || strings.Contains(fmt.Sprintf("%v %#v", value, value), "PRIVATE") {
				t.Fatal("public parsed settings disclosed captured input", err)
			}
		}
	}
}

func TestParseReturnsNoConfigurationOnValidationFailure(t *testing.T) {
	for _, tc := range []struct {
		role    config.Role
		entries []string
		want    error
	}{
		{0, nil, config.ErrInvalidRole},
		{config.API, nil, config.ErrMissingValue},
		{config.CLI, []string{"ENV=production", "EVYDENCE_PRIVATE_UNKNOWN=PRIVATE_VALUE"}, config.ErrUnknownOption},
		{config.Worker, []string{"EVYDENCE_RUNTIME_PROFILE=postgres", "EVYDENCE_DATABASE_URL=host=PRIVATE_DATABASE", "EVYDENCE_WORKER_BATCH_SIZE=PRIVATE_NUMBER"}, config.ErrInvalidValue},
		{config.API, []string{"EVYDENCE_RUNTIME_PROFILE=postgres", "EVYDENCE_DATABASE_URL=host=PRIVATE_DATABASE", "AWS_MAX_ATTEMPTS=PRIVATE_NUMBER"}, config.ErrInvalidValue},
		{config.API, []string{"EVYDENCE_RUNTIME_PROFILE=postgres", "EVYDENCE_DATABASE_URL=host=PRIVATE_DATABASE", "EVYDENCE_AWS_REGION=PRIVATE_FIRST", "AWS_REGION=PRIVATE_SECOND"}, config.ErrConflictingAliases},
	} {
		environment, err := config.Capture(tc.entries)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Parse(environment, tc.role)
		if !errors.Is(err, tc.want) || !reflect.DeepEqual(cfg, config.Configuration{}) || strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
			t.Fatal("failed pure parse returned partial settings or an unsafe diagnostic", err)
		}
	}
}
