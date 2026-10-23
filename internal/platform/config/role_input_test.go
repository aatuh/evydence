package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func roleEnvironment(t *testing.T, role Role, production bool, extra ...string) Environment {
	t.Helper()
	values := map[string]string{"ENV": "development"}
	if production {
		values["ENV"] = "production"
		if role == API {
			values["EVYDENCE_API_KEY_PEPPER"] = "PRIVATE_PEPPER"
			values["EVYDENCE_SIGNING_KEY_MODE"] = "aws-kms"
			values["EVYDENCE_AWS_REGION"] = "eu-test-1"
			values["EVYDENCE_AWS_KMS_KEY_ID"] = "PRIVATE_TEST_KEY"
		}
	}
	if role != CLI {
		values["EVYDENCE_DATABASE_URL"] = "host=PRIVATE_DATABASE dbname=evydence"
	}
	if role == API || role == Worker {
		values["EVYDENCE_RUNTIME_PROFILE"] = "postgres"
	}
	for _, entry := range extra {
		name, value, _ := strings.Cut(entry, "=")
		values[name] = value
	}
	entries := make([]string, 0, len(values))
	for name, value := range values {
		entries = append(entries, name+"="+value)
	}
	e, err := Capture(entries)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestRoleInputResolvesSchemaDefaultsAndTypedValues(t *testing.T) {
	for _, production := range []bool{false, true} {
		for _, role := range []Role{API, Worker, Migrate, CLI} {
			t.Run(fmt.Sprintf("%d/%t", role, production), func(t *testing.T) {
				input, err := parseRoleInput(roleEnvironment(t, role, production), role)
				if err != nil || input.role != role || input.production != production {
					t.Fatal("valid role input was rejected", err)
				}
				if input.values["EVYDENCE_LOG_FORMAT"].text != "json" {
					t.Fatal("schema default was not applied")
				}
				if role == API && input.values["EVYDENCE_HTTP_READ_HEADER_TIMEOUT_SECONDS"].duration != 5*time.Second {
					t.Fatal("API timeout was not typed")
				}
				if role == API || role == Worker {
					want := "snapshot_preferred"
					if production {
						want = "relational_only"
					}
					if input.values["EVYDENCE_POSTGRES_LOAD_MODE"].text != want {
						t.Fatal("conditional load-mode default was lost")
					}
				}
				if role == Worker && input.values["EVYDENCE_WORKER_METRICS_ADDR"].text != "" {
					t.Fatal("disabled metrics listener acquired an address")
				}
				if role == CLI && !input.values["EVYDENCE_BUILD_STARTED_AT"].timestamp.IsZero() {
					t.Fatal("pure input parsing consulted the command clock")
				}
			})
		}
	}
	input, err := parseRoleInput(roleEnvironment(t, Worker, false, "EVYDENCE_WORKER_METRICS_TOKEN_FILE=/PRIVATE_NONEXISTENT/token"), Worker)
	if err != nil || input.values["EVYDENCE_WORKER_METRICS_ADDR"].text != "127.0.0.1:9091" {
		t.Fatal("credential-dependent listener default was lost or file was opened", err)
	}
}

func TestRoleInputRejectsMissingMalformedAndUnsafeProductionInput(t *testing.T) {
	for _, tc := range []struct {
		name       string
		role       Role
		production bool
		extra      []string
		want       error
	}{
		{"profile-required", API, false, []string{"EVYDENCE_RUNTIME_PROFILE="}, ErrMissingValue},
		{"database-required", Worker, false, []string{"EVYDENCE_DATABASE_URL= "}, ErrMissingValue},
		{"pepper-required", API, true, []string{"EVYDENCE_API_KEY_PEPPER="}, ErrMissingValue},
		{"inactive-provider-type", API, false, []string{"EVYDENCE_AWS_KMS_TIMEOUT_SECONDS=PRIVATE_VALUE"}, ErrInvalidValue},
		{"unknown-production-name", API, true, []string{"EVYDENCE_PRIVATE_CANARY=PRIVATE_VALUE"}, ErrUnknownOption},
		{"local-override", API, true, []string{"EVYDENCE_OIDC_USERINFO_ALLOW_INSECURE_LOCALHOST=true"}, ErrUnsafeProduction},
		{"bootstrap-secret", API, true, []string{"EVYDENCE_PRINT_BOOTSTRAP_SECRET=true"}, ErrUnsafeProduction},
		{"snapshot-fallback", Worker, true, []string{"EVYDENCE_POSTGRES_LOAD_MODE=snapshot_preferred"}, ErrUnsafeProduction},
		{"malformed-environment", CLI, false, []string{"ENV=PRIVATE_ENVIRONMENT"}, ErrInvalidValue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input, err := parseRoleInput(roleEnvironment(t, tc.role, tc.production, tc.extra...), tc.role)
			if !errors.Is(err, tc.want) || !reflect.DeepEqual(input, parsedInput{}) {
				t.Fatal("invalid input returned a complete or partially resolved configuration", err)
			}
			encoded, marshalErr := json.Marshal(err)
			if marshalErr != nil || strings.Contains(fmt.Sprintf("%v %#v %s", err, err, encoded), "PRIVATE") {
				t.Fatal("configuration diagnostic exposed supplied names, values or causes")
			}
		})
	}
	for _, role := range []Role{0, API | Worker, AllRoles, Role(128)} {
		if input, err := parseRoleInput(Environment{}, role); !errors.Is(err, ErrInvalidRole) || !reflect.DeepEqual(input, parsedInput{}) {
			t.Fatal("ambiguous process role was accepted", err)
		}
	}
}

func TestRoleInputAliasesConflictWithoutEnvironmentOrderDependence(t *testing.T) {
	for _, extra := range [][]string{
		{"AWS_REGION=eu-test-1"},
		{"EVYDENCE_AWS_REGION=eu-test-1", "AWS_REGION=eu-test-1"},
		{"EVYDENCE_AWS_REGION=", "AWS_REGION=eu-test-1"},
	} {
		input, err := parseRoleInput(roleEnvironment(t, API, false, extra...), API)
		if err != nil || input.values["EVYDENCE_AWS_REGION"].text != "eu-test-1" {
			t.Fatal("compatible region alias was lost", err)
		}
	}
	input, err := parseRoleInput(roleEnvironment(t, API, false, "EVYDENCE_AWS_REGION=PRIVATE_REGION_A", "AWS_REGION=PRIVATE_REGION_B"), API)
	if !errors.Is(err, ErrConflictingAliases) || !reflect.DeepEqual(input, parsedInput{}) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("conflicting aliases were not rejected safely", err)
	}
}

func TestRoleInputScopesAndRedactsAllValues(t *testing.T) {
	// An unused API setting must not impose API dependencies on migration/CLI.
	input, err := parseRoleInput(roleEnvironment(t, Migrate, true, "EVYDENCE_HTTP_MAX_HEADER_BYTES=PRIVATE_UNUSED"), Migrate)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := input.values["EVYDENCE_HTTP_MAX_HEADER_BYTES"]; ok {
		t.Fatal("another role's configuration escaped the role boundary")
	}
	for _, value := range []any{input, &input, []parsedInput{input}} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, value), "PRIVATE") {
				t.Fatal("resolved input formatting exposed values")
			}
		}
		encoded, err := json.Marshal(value)
		if err != nil || strings.Contains(string(encoded), "PRIVATE") {
			t.Fatal("resolved input JSON exposed values", err)
		}
	}
	// SDK inputs are captured but remain outside project-owned scalar parsing.
	if _, err := parseRoleInput(roleEnvironment(t, API, true, "AWS_SECRET_ACCESS_KEY=PRIVATE_SDK_KEY", "ENV= Production "), API); err != nil {
		t.Fatal("native SDK input or canonical production selector was rejected", err)
	}
}

func TestRoleInputFailureOrderIsIndependentOfSourceOrder(t *testing.T) {
	entries := []string{
		"ENV=production", "EVYDENCE_DATABASE_URL= ",
		"EVYDENCE_RUNTIME_PROFILE=postgres", "EVYDENCE_API_KEY_PEPPER=PRIVATE_PEPPER",
		"EVYDENCE_LOG_LEVEL=PRIVATE_INVALID_LEVEL",
	}
	for range 2 {
		e, err := Capture(entries)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseRoleInput(e, API); !errors.Is(err, ErrMissingValue) {
			t.Fatal("validation failure changed with source order", err)
		}
		for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
			entries[i], entries[j] = entries[j], entries[i]
		}
	}
}
