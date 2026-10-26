package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestDatabaseDSNPreservesDriverGrammarWithoutAmbientOrFileReads(t *testing.T) {
	t.Setenv("PGHOST", "PRIVATE_AMBIENT_HOST")
	t.Setenv("PGPASSWORD", "PRIVATE_AMBIENT_PASSWORD")
	t.Setenv("PGSERVICEFILE", "/PRIVATE_NONEXISTENT/service")
	for index, tc := range []struct {
		raw  string
		want map[string]string
	}{
		{"host=/PRIVATE_SOCKET dbname=evydence", map[string]string{"host": "/PRIVATE_SOCKET", "database": "evydence"}},
		{" host = localhost user = 'a b' password='PRIVATE\\'PASSWORD' ", map[string]string{"host": "localhost", "user": "a b", "password": "PRIVATE'PASSWORD"}},
		{`host=localhost password='PRIVATE\\PASSWORD'`, map[string]string{"host": "localhost", "password": `PRIVATE\PASSWORD`}},
		{"postgres://user:PRIVATE_PASSWORD@host:5432/evydence?sslmode=disable", map[string]string{"host": "host", "port": "5432", "user": "user", "password": "PRIVATE_PASSWORD", "database": "evydence", "sslmode": "disable"}},
		{"postgresql://first:5432,other:6432/evydence", map[string]string{"host": "first,other", "port": "5432,6432", "database": "evydence"}},
		{"postgresql://[::1]:5432/evydence", map[string]string{"host": "::1", "port": "5432", "database": "evydence"}},
		{"postgres:///evydence?host=%2FPRIVATE_SOCKET", map[string]string{"host": "/PRIVATE_SOCKET", "database": "evydence"}},
		{"postgres://host/old?dbname=new&user=another", map[string]string{"host": "host", "database": "new", "user": "another"}},
		{"service=PRIVATE_SERVICE servicefile=/PRIVATE_NONEXISTENT/service passfile=/PRIVATE_NONEXISTENT/pass sslcert=/PRIVATE_NONEXISTENT/cert sslkey=/PRIVATE_NONEXISTENT/key", map[string]string{"service": "PRIVATE_SERVICE", "servicefile": "/PRIVATE_NONEXISTENT/service", "passfile": "/PRIVATE_NONEXISTENT/pass", "sslcert": "/PRIVATE_NONEXISTENT/cert", "sslkey": "/PRIVATE_NONEXISTENT/key"}},
		{"host=localhost host=localhost dbname=db database=db", map[string]string{"host": "localhost", "database": "db"}},
	} {
		parsed, err := parseDatabaseDSN(tc.raw)
		if err != nil || !reflect.DeepEqual(parsed.values, tc.want) {
			t.Fatalf("database grammar case %d changed, consulted ambient input or opened a file: %v", index, err)
		}
		for _, value := range []any{parsed, &parsed, struct{ Database databaseSettings }{parsed}} {
			if strings.Contains(fmt.Sprintf("%v %#v", value, value), "PRIVATE") {
				t.Fatal("parsed database settings formatting exposed values")
			}
			encoded, err := json.Marshal(value)
			if err != nil || strings.Contains(string(encoded), "PRIVATE") {
				t.Fatal("parsed database settings JSON exposed values", err)
			}
		}
	}
}

func TestDatabaseDSNRejectsMalformedAmbiguousOrUnboundedInput(t *testing.T) {
	for _, raw := range []string{
		"", "PRIVATE_INVALID", "host=localhost PRIVATE_INVALID", "=PRIVATE_VALUE",
		"host=localhost password='PRIVATE_UNTERMINATED", "host=localhost password='PRIVATE_TRAILING\\",
		"host=localhost password=PRIVATE_TRAILING\\", "host=first host=PRIVATE_CONFLICT",
		"dbname=first database=PRIVATE_CONFLICT", "postgres://host/db?password=first&password=PRIVATE_CONFLICT",
		"postgres://host/db?dbname=first&database=PRIVATE_CONFLICT", "postgres://host/db?password=%ZZ",
		"postgres://user:PRIVATE_PASSWORD@host/db#fragment", "postgres://host/db?password=%00",
		"postgresql://[::1]:5432,other:6432/evydence",
		"postgres://host/db?password=%FF", "https://host/PRIVATE_DATABASE", "postgres://host:65536/db",
		"host=localhost port=0", "host=localhost port=65536", "host=localhost port=5432,",
		"connect_timeout=-1", "connect_timeout=9223372037", "pool_max_conns=0", "pool_max_conns=2147483648",
		"pool_min_conns=-1", "pool_max_conns=2 pool_min_conns=3", "pool_health_check_period=0s",
		"pool_max_conn_lifetime=PRIVATE_DURATION", "pool_max_conn_idle_time=-1s",
		"statement_cache_capacity=-1", "description_cache_capacity=2147483648",
		"sslmode=PRIVATE_MODE", "sslnegotiation=PRIVATE_MODE", "sslsni=PRIVATE_BOOL",
		"target_session_attrs=PRIVATE_ROLE", "channel_binding=PRIVATE_POLICY",
		"default_query_exec_mode=PRIVATE_MODE", "min_protocol_version=3.2 max_protocol_version=3.0",
		"sslcert=/PRIVATE_CERT", "pool_PRIVATE_UNKNOWN=1", "ssl_PRIVATE_UNKNOWN=1",
		"host=" + strings.Repeat("host,", 16) + "host",
		strings.Repeat("application_name=same ", 129),
		"password=" + strings.Repeat("x", 8<<20),
	} {
		parsed, err := parseDatabaseDSN(raw)
		if !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(parsed, databaseSettings{}) {
			t.Fatal("malformed DSN returned usable or partial settings", err)
		}
		if strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
			t.Fatal("database parser exposed input or a native parser cause")
		}
	}
}

func TestDatabaseDSNChecksAllRuntimeRolesBeforeProjection(t *testing.T) {
	for _, role := range []Role{API, Worker, Migrate} {
		input, err := parseRoleInput(roleEnvironment(t, role, false, "EVYDENCE_DATABASE_URL=postgres://user:PRIVATE_PASSWORD@host/db?pool_max_conns=bad"), role)
		if !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(input, parsedInput{}) {
			t.Fatal("runtime accepted malformed database settings", err)
		}
	}
	if _, err := parseRoleInput(roleEnvironment(t, CLI, false, "EVYDENCE_DATABASE_URL=PRIVATE_UNUSED"), CLI); err != nil {
		t.Fatal("CLI acquired an unused database dependency", err)
	}
}

func FuzzDatabaseDSNNeverPanicsOrReturnsPartialSettings(f *testing.F) {
	for _, seed := range []string{
		"host=localhost dbname=evydence", "postgres://user:PRIVATE_PASSWORD@host/db?sslmode=disable",
		"password='PRIVATE_TRAILING\\", "password=PRIVATE_TRAILING\\", "password='PRIVATE\\'VALUE'",
		"postgres://[::1]:5432,other:6432/db", "postgres://host/db?password=%00", string([]byte{255}),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > maxEnvironmentBytes {
			return
		}
		parsed, err := parseDatabaseDSN(raw)
		if err != nil {
			if !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(parsed, databaseSettings{}) {
				t.Fatal("database parsing failure returned partial settings or an unsafe cause")
			}
			return
		}
		if parsed.values == nil || len(parsed.values) > 128 {
			t.Fatal("successful database parse lacks bounded owned settings")
		}
	})
}
