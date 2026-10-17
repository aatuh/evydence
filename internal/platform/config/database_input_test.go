package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func nativeDatabaseFixture(t *testing.T, entries ...string) nativeInputs {
	t.Helper()
	environment, err := Capture(entries)
	if err != nil {
		t.Fatal(err)
	}
	input, err := parseNativeInputs(environment, API)
	if err != nil {
		t.Fatal(err)
	}
	return input
}

func TestDatabaseInputMergesOwnedSuppliedLayersWithoutAmbientReads(t *testing.T) {
	t.Setenv("PGHOST", "PRIVATE_AMBIENT")
	t.Setenv("PGSERVICEFILE", "/PRIVATE_AMBIENT/service")
	native := nativeDatabaseFixture(t,
		"PGHOST=PRIVATE_NATIVE_HOST", "PGPORT=5433", "PGUSER=PRIVATE_NATIVE_USER",
		"PGPASSWORD= PRIVATE_NATIVE_PASSWORD ", "PGSSLKEY=/PRIVATE_KEY",
	)
	input, err := parseDatabaseInput("host=PRIVATE_DSN_HOST password='' user='' sslcert=/PRIVATE_CERT", native)
	if err != nil || input.needsService {
		t.Fatal("mixed-source input failed or consulted ambient service configuration", err)
	}
	want := map[string]string{
		"host": "PRIVATE_DSN_HOST", "port": "5433", "user": "PRIVATE_NATIVE_USER",
		"password": "", "sslcert": "/PRIVATE_CERT", "sslkey": "/PRIVATE_KEY",
	}
	if !reflect.DeepEqual(input.candidate.values, want) || input.native.values["host"] != "PRIVATE_NATIVE_HOST" || input.explicit.values["host"] != "PRIVATE_DSN_HOST" {
		t.Fatal("DSN precedence, empty-password clearing or empty-user compatibility changed")
	}
	native.values["PGPASSWORD"] = nativeValue{raw: "PRIVATE_MUTATION"}
	input.candidate.values["host"] = "PRIVATE_CANDIDATE_MUTATION"
	if input.native.values["password"] != " PRIVATE_NATIVE_PASSWORD " || input.native.values["host"] != "PRIVATE_NATIVE_HOST" || input.explicit.values["host"] != "PRIVATE_DSN_HOST" {
		t.Fatal("database input layers share mutable maps")
	}
	for _, value := range []any{input, &input, input.native, input.explicit, input.candidate, struct{ Database databaseInput }{input}} {
		encoded, err := json.Marshal(value)
		if err != nil || strings.Contains(string(encoded), "PRIVATE") || strings.Contains(fmt.Sprintf("%v %#v", value, value), "PRIVATE") {
			t.Fatal("layered database input exposed supplied values", err)
		}
	}
}

func TestDatabaseRoleChecksMergedRelationshipsInEveryRuntimeRole(t *testing.T) {
	for _, role := range []Role{API, Worker, Migrate} {
		for _, extra := range [][]string{
			{"EVYDENCE_DATABASE_URL=host=db sslcert=/PRIVATE_CERT", "PGSSLKEY=/PRIVATE_KEY"},
			{"EVYDENCE_DATABASE_URL=host=db sslkey=/PRIVATE_KEY", "PGSSLCERT=/PRIVATE_CERT"},
			{"EVYDENCE_DATABASE_URL=host=db min_protocol_version=3.0", "PGMINPROTOCOLVERSION=3.2", "PGMAXPROTOCOLVERSION=3.0"},
			{"EVYDENCE_DATABASE_URL=host=db sslcert='' sslkey=''", "PGSSLCERT=/PRIVATE_CERT"},
		} {
			input, err := parseRoleInput(roleEnvironment(t, role, false, extra...), role)
			if err != nil || input.database.candidate.values["host"] != "db" || input.database.needsService {
				t.Fatal("runtime rejected valid relationships supplied across DSN/native layers", role, err)
			}
		}
		for _, extra := range [][]string{
			{"PGSSLCERT=/PRIVATE_CERT"},
			{"PGMINPROTOCOLVERSION=3.2", "PGMAXPROTOCOLVERSION=3.0"},
			{"EVYDENCE_DATABASE_URL=host=db max_protocol_version=3.0", "PGMINPROTOCOLVERSION=3.2"},
			{"EVYDENCE_DATABASE_URL=host=db sslkey=''", "PGSSLCERT=/PRIVATE_CERT", "PGSSLKEY=/PRIVATE_KEY"},
		} {
			input, err := parseRoleInput(roleEnvironment(t, role, false, extra...), role)
			if !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(input, parsedInput{}) {
				t.Fatal("runtime accepted invalid merged database relationships or returned partial input", role, err)
			}
		}
	}
	input, err := parseRoleInput(roleEnvironment(t, CLI, false, "EVYDENCE_DATABASE_URL=PRIVATE_UNUSED", "PGSSLCERT=/PRIVATE_UNUSED_CERT"), CLI)
	if err != nil || !reflect.DeepEqual(input.database, databaseInput{}) {
		t.Fatal("CLI acquired runtime database requirements", err)
	}
}

func TestDatabaseServiceInputDefersOnlyUnknownRelationships(t *testing.T) {
	for _, tc := range []struct {
		dsn    string
		native []string
	}{
		{"host=db sslcert=/PRIVATE_CERT", []string{"PGSERVICE=PRIVATE_SERVICE", "PGSERVICEFILE=/PRIVATE_MISSING/service"}},
		{"host=db service=PRIVATE_SERVICE servicefile=/PRIVATE_MISSING/service", []string{"PGMINPROTOCOLVERSION=3.2", "PGMAXPROTOCOLVERSION=3.0"}},
		{"host=db service=PRIVATE_SERVICE", []string{"PGSERVICE=PRIVATE_OTHER_SERVICE"}},
	} {
		input, err := parseDatabaseInput(tc.dsn, nativeDatabaseFixture(t, tc.native...))
		if err != nil || !input.needsService || input.candidate.values["service"] != "PRIVATE_SERVICE" {
			t.Fatal("service input was prematurely treated as resolved, rejected or opened", err)
		}
	}
	for _, dsn := range []string{
		"service=PRIVATE_SERVICE sslcert=/PRIVATE_CERT sslkey=''",
		"service=PRIVATE_SERVICE min_protocol_version=3.2 max_protocol_version=3.0",
		"service=PRIVATE_SERVICE pool_max_conns=2 pool_min_conns=3",
		"service=PRIVATE_SERVICE pool_health_check_period=PRIVATE_INVALID",
	} {
		input, err := parseDatabaseInput(dsn, nativeInputs{})
		if !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(input, databaseInput{}) || strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
			t.Fatal("service reference bypassed known explicit contradictions or leaked input", err)
		}
	}
}

func TestDatabaseInputBoundsMergedParameterCount(t *testing.T) {
	var dsn strings.Builder
	for n := range 128 {
		_, _ = fmt.Fprintf(&dsn, "custom_%d=value ", n)
	}
	input, err := parseDatabaseInput(dsn.String(), nativeDatabaseFixture(t, "PGHOST=PRIVATE_HOST"))
	if !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(input, databaseInput{}) {
		t.Fatal("merged database parameters exceeded their bound", err)
	}
}

func TestDatabaseExplicitNumbersRejectNativeInvalidWhitespace(t *testing.T) {
	for _, raw := range []string{
		"host=db connect_timeout=' 5 '",
		"host=db pool_max_conns=' 2'",
		"host=db pool_max_conn_lifetime='1s '",
	} {
		if input, err := parseDatabaseInput(raw, nativeInputs{}); !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(input, databaseInput{}) {
			t.Fatal("supplied database input accepted native-invalid numeric whitespace", err)
		}
		if dsn, err := parseDatabaseDSN(raw); !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(dsn, databaseSettings{}) {
			t.Fatal("standalone DSN accepted native-invalid numeric whitespace", err)
		}
	}
}
