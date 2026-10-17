package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestScalarParsingUsesSchemaTypesAndBounds(t *testing.T) {
	defs := schemaByName(t)
	for _, tc := range []struct {
		name, raw string
		check     func(scalarValue) bool
	}{
		{"EVYDENCE_SKIP_MIGRATIONS", " TRUE ", func(v scalarValue) bool { return v.boolean }},
		{"EVYDENCE_SKIP_MIGRATIONS", "false", func(v scalarValue) bool { return !v.boolean }},
		{"EVYDENCE_RATE_LIMIT_REQUESTS_PER_MINUTE", "0", func(v scalarValue) bool { return v.integer == 0 }},
		{"EVYDENCE_HTTP_MAX_HEADER_BYTES", " 1048576 ", func(v scalarValue) bool { return v.integer == 1048576 }},
		{"EVYDENCE_HTTP_READ_HEADER_TIMEOUT_SECONDS", "60", func(v scalarValue) bool { return v.duration == time.Minute }},
		{"EVYDENCE_WORKER_POLL_INTERVAL", "1500ms", func(v scalarValue) bool { return v.duration == 1500*time.Millisecond }},
		{"EVYDENCE_LOG_FORMAT", " TEXT ", func(v scalarValue) bool { return v.text == "text" }},
		{"EVYDENCE_AWS_KMS_SIGNING_ALGORITHM", "ecdsa_sha_256", func(v scalarValue) bool { return v.text == "ECDSA_SHA_256" }},
		{"EVYDENCE_BOOTSTRAP_TENANT", "  Tenant  ", func(v scalarValue) bool { return v.text == "  Tenant  " }},
		{"EVYDENCE_TRUSTED_PROXY_CIDRS", "10.0.0.1/8, 2001:db8::/32", func(v scalarValue) bool {
			return len(v.prefixes) == 2 && v.prefixes[0].String() == "10.0.0.0/8" && v.prefixes[1].String() == "2001:db8::/32"
		}},
		{"EVYDENCE_SIGSTORE_TRUST_ROOT_JSON_BASE64", "e30=", func(v scalarValue) bool { return string(v.bytes) == "{}" }},
		{"EVYDENCE_BUILD_STARTED_AT", "2026-10-16T12:34:56+02:00", func(v scalarValue) bool {
			return v.timestamp.Equal(time.Date(2026, 10, 16, 10, 34, 56, 0, time.UTC)) && v.timestamp.Location() == time.UTC
		}},
	} {
		t.Run(tc.name+"/"+tc.raw, func(t *testing.T) {
			v, err := parseScalar(defs[tc.name], tc.raw)
			if err != nil || !tc.check(v) {
				t.Fatal("schema value was not parsed to the expected type", err)
			}
		})
	}
}

func TestScalarParsingRejectsMalformedInputWithoutPartialValues(t *testing.T) {
	defs := schemaByName(t)
	for _, tc := range []struct{ name, raw string }{
		{"EVYDENCE_SKIP_MIGRATIONS", "yes"},
		{"EVYDENCE_SKIP_MIGRATIONS", "1"},
		{"EVYDENCE_SKIP_MIGRATIONS", ""},
		{"EVYDENCE_HTTP_MAX_HEADER_BYTES", "1023"},
		{"EVYDENCE_HTTP_MAX_HEADER_BYTES", "1048577"},
		{"EVYDENCE_HTTP_MAX_HEADER_BYTES", "1.5"},
		{"EVYDENCE_RATE_LIMIT_REQUESTS_PER_MINUTE", "-1"},
		{"EVYDENCE_WORKER_BATCH_SIZE", "9223372036854775808"},
		{"EVYDENCE_HTTP_READ_HEADER_TIMEOUT_SECONDS", "0"},
		{"EVYDENCE_HTTP_READ_HEADER_TIMEOUT_SECONDS", "61"},
		{"EVYDENCE_AWS_KMS_TIMEOUT_SECONDS", "9223372037"},
		{"EVYDENCE_WORKER_POLL_INTERVAL", "0s"},
		{"EVYDENCE_WORKER_POLL_INTERVAL", "-1s"},
		{"EVYDENCE_WORKER_POLL_INTERVAL", "9223372036854775808ns"},
		{"EVYDENCE_LOG_FORMAT", "PRIVATE_INVALID_VALUE"},
		{"EVYDENCE_TRUSTED_PROXY_CIDRS", "10.0.0.0/8,PRIVATE_INVALID_VALUE"},
		{"EVYDENCE_TRUSTED_PROXY_CIDRS", "10.0.0.0/8,"},
		{"EVYDENCE_TRUSTED_PROXY_CIDRS", "fe80::1%eth0/64"},
		{"EVYDENCE_TRUSTED_PROXY_CIDRS", strings.Repeat("10.0.0.0/8,", 256) + "10.0.0.0/8"},
		{"EVYDENCE_SIGSTORE_TRUST_ROOT_JSON_BASE64", "PRIVATE_INVALID_VALUE"},
		{"EVYDENCE_SIGSTORE_TRUST_ROOT_JSON_BASE64", "AB=="},
		{"EVYDENCE_BUILD_STARTED_AT", "PRIVATE_INVALID_VALUE"},
		{"EVYDENCE_BOOTSTRAP_TENANT", "PRIVATE\x00VALUE"},
		{"EVYDENCE_BOOTSTRAP_TENANT", string([]byte{255})},
	} {
		t.Run(tc.name+"/invalid", func(t *testing.T) {
			v, err := parseScalar(defs[tc.name], tc.raw)
			if !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(v, scalarValue{}) {
				t.Fatal("malformed scalar returned a usable or partially parsed value", err)
			}
			if err.Error() != "invalid runtime configuration value" {
				t.Fatal("scalar diagnostic contains input or a parser cause")
			}
		})
	}
}

func TestScalarParsingHonorsDecodedAndRawByteBounds(t *testing.T) {
	defs := schemaByName(t)
	for _, name := range []string{"EVYDENCE_SIGSTORE_TRUST_ROOT_JSON_BASE64", "EVYDENCE_SIGSTORE_TRUSTED_PUBLIC_KEY_PEM_BASE64"} {
		d := defs[name]
		if d.MaxBytes != 1<<20 {
			t.Fatal("existing Sigstore decoded-size limit is absent from schema")
		}
		encoded := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 1<<20)))
		v, err := parseScalar(d, encoded)
		if err != nil || len(v.bytes) != 1<<20 {
			t.Fatal("exact decoded byte limit was rejected", err)
		}
		encoded = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", (1<<20)+1)))
		if v, err = parseScalar(d, encoded); !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(v, scalarValue{}) {
			t.Fatal("oversized decoded value returned data", err)
		}
	}
	d := defs["EVYDENCE_BOOTSTRAP_TENANT"]
	if d.MaxBytes != 65536 {
		t.Fatal("existing tenant-name raw byte limit is absent from schema")
	}
	if _, err := parseScalar(d, strings.Repeat("x", 65536)); err != nil {
		t.Fatal("exact raw byte limit was rejected", err)
	}
	if _, err := parseScalar(d, strings.Repeat("x", 65537)); !errors.Is(err, ErrInvalidValue) {
		t.Fatal("oversized text was accepted", err)
	}
}

func TestScalarParsingBoundsCIDRAllocationAndSecondsMultiplication(t *testing.T) {
	d := schemaByName(t)["EVYDENCE_TRUSTED_PROXY_CIDRS"]
	if d.MaxItems != 256 {
		t.Fatal("CIDR item bound is absent from the schema")
	}
	if v, err := parseScalar(d, strings.Repeat("10.0.0.0/8,", 255)+"10.0.0.0/8"); err != nil || len(v.prefixes) != 256 {
		t.Fatal("exact CIDR item bound was rejected", err)
	}
	// Keep the multiplication safe independently of today's catalogue ranges.
	d = Definition{Kind: Seconds, Min: math.MinInt64, Max: math.MaxInt64}
	for _, raw := range []string{"9223372037", "-9223372037"} {
		if v, err := parseScalar(d, raw); !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(v, scalarValue{}) {
			t.Fatal("whole-second conversion overflow returned a duration", err)
		}
	}
	for _, raw := range []string{"9223372036", "-9223372036"} {
		if _, err := parseScalar(d, raw); err != nil {
			t.Fatal("representable whole-second duration was rejected", err)
		}
	}
}

func TestScalarParsingPreservesStringInputsForDedicatedValidation(t *testing.T) {
	defs := schemaByName(t)
	// Database DSNs, S3 host:port endpoints and paths need different validators.
	// Scalar parsing must not impose an HTTP URL grammar or open these resources.
	for name, raw := range map[string]string{
		"EVYDENCE_DATABASE_URL":   "host=/PRIVATE_SOCKET dbname=PRIVATE_DATABASE",
		"EVYDENCE_S3_ENDPOINT":    "localhost:9000",
		"EVYDENCE_MIGRATIONS_DIR": "/PRIVATE_NONEXISTENT/migrations",
	} {
		v, err := parseScalar(defs[name], raw)
		if err != nil || v.text != raw {
			t.Fatal("scalar parsing changed an input requiring dedicated validation", name, err)
		}
	}
	for _, kind := range []Kind{Text, URL, Path, CIDRs, Base64, Timestamp} {
		if v, err := parseScalar(Definition{Kind: kind}, ""); err != nil || !reflect.DeepEqual(v, scalarValue{}) {
			t.Fatal("optional absent scalar acquired a value", kind, err)
		}
	}
}

func TestScalarFormattingAndJSONHideAllInput(t *testing.T) {
	defs := schemaByName(t)
	v, err := parseScalar(defs["EVYDENCE_DATABASE_URL"], "host=localhost password=PRIVATE_PASSWORD")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{v, &v, struct{ Value scalarValue }{v}, []scalarValue{v}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if strings.Contains(fmt.Sprintf(format, value), "PRIVATE") {
				t.Fatal("formatting disclosed a configuration value")
			}
		}
		encoded, err := json.Marshal(value)
		if err != nil || strings.Contains(string(encoded), "PRIVATE") {
			t.Fatal("JSON disclosed a configuration value", err)
		}
	}
}

func TestEveryLiteralSchemaDefaultParses(t *testing.T) {
	for _, d := range Definitions() {
		if d.Default == "" {
			continue
		}
		if _, err := parseScalar(d, d.Default); err != nil {
			t.Fatal("code-owned schema default is invalid", d.Name, err)
		}
	}
	if _, err := parseScalar(Definition{Kind: Kind("unknown")}, "PRIVATE_VALUE"); !errors.Is(err, ErrInvalidValue) {
		t.Fatal("unknown scalar kind was accepted", err)
	}
}
