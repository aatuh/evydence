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

func nativeDefinitionByName(t *testing.T, name string) NativeDefinition {
	t.Helper()
	for _, d := range NativeDefinitions() {
		if d.Name == name {
			return d
		}
	}
	t.Fatal("native definition is absent", name)
	return NativeDefinition{}
}

func TestNativeScalarPreservesNativeTypesAndGrammar(t *testing.T) {
	for _, tc := range []struct {
		name, raw, text string
		boolean         bool
		integer         int64
		duration        time.Duration
	}{
		{name: "AWS_USE_FIPS_ENDPOINT", raw: "TRUE", boolean: true},
		{name: "AWS_MAX_ATTEMPTS", raw: "+05", integer: 5},
		{name: "PGCONNECT_TIMEOUT", raw: "30", duration: 30 * time.Second},
		{name: "PGSSLMODE", raw: "verify-full", text: "verify-full"},
		{name: "AWS_RETRY_MODE", raw: "ADAPTIVE", text: "adaptive"},
		{name: "AZURE_TOKEN_CREDENTIALS", raw: "prod", text: "prod"},
		{name: "AZURE_TOKEN_CREDENTIALS", raw: "environmentcredential", text: "EnvironmentCredential"},
		{name: "AZURE_CLIENT_SEND_CERTIFICATE_CHAIN", raw: "1", text: "1"},
		{name: "AWS_SECRET_ACCESS_KEY", raw: " PRIVATE_SECRET\n", text: " PRIVATE_SECRET\n"},
		{name: "AWS_CONTAINER_AUTHORIZATION_TOKEN", raw: "Bearer PRIVATE_TOKEN", text: "Bearer PRIVATE_TOKEN"},
		{name: "GOOGLE_APPLICATION_CREDENTIALS", raw: "/PRIVATE_NONEXISTENT/credentials.json", text: "/PRIVATE_NONEXISTENT/credentials.json"},
		{name: "PGCONNECT_TIMEOUT", raw: ""},
	} {
		t.Run(tc.name+"/"+fmt.Sprint(tc.boolean, tc.integer, tc.duration), func(t *testing.T) {
			value, err := parseNativeScalar(nativeDefinitionByName(t, tc.name), tc.raw)
			if err != nil || value.raw != tc.raw || value.scalar.text != tc.text || value.scalar.boolean != tc.boolean || value.scalar.integer != tc.integer || value.scalar.duration != tc.duration {
				t.Fatal("native primitive changed raw input, grammar or typed output", err)
			}
		})
	}
}

func TestNativeScalarRejectsMalformedInputWithoutPartialValues(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"AWS_USE_FIPS_ENDPOINT", "1"},
		{"AWS_USE_FIPS_ENDPOINT", " true "},
		{"AWS_MAX_ATTEMPTS", "-1"},
		{"AWS_MAX_ATTEMPTS", " 5"},
		{"AWS_REQUEST_MIN_COMPRESSION_SIZE_BYTES", "10485761"},
		{"PGCONNECT_TIMEOUT", "9223372037"},
		{"PGSSLMODE", "VERIFY-FULL"},
		{"PGSSLMODE", "verify-full "},
		{"AWS_ACCOUNT_ID_ENDPOINT_MODE", "PREFERRED"},
		{"AZURE_TOKEN_CREDENTIALS", ""},
		{"AZURE_TOKEN_CREDENTIALS", "PROD"},
		{"AZURE_CLIENT_SEND_CERTIFICATE_CHAIN", "PRIVATE_INVALID_FLAG"},
		{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "true"},
		{"GOOGLE_APPLICATION_CREDENTIALS", " "},
		{"GOOGLE_APPLICATION_CREDENTIALS", "/PRIVATE_\nFILE"},
		{"GOOGLE_APPLICATION_CREDENTIALS", "/" + strings.Repeat("x", 4096)},
		{"AWS_CONTAINER_AUTHORIZATION_TOKEN", "PRIVATE_TOKEN\r\nInjected: value"},
		{"MSI_SECRET", "PRIVATE_SECRET\n"},
		{"AWS_SECRET_ACCESS_KEY", "PRIVATE\x00SECRET"},
		{"AWS_SECRET_ACCESS_KEY", "PRIVATE" + string([]byte{255})},
	} {
		value, err := parseNativeScalar(nativeDefinitionByName(t, tc.name), tc.raw)
		if !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(value, nativeValue{}) || strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
			t.Fatal("invalid native primitive returned partial output or unsafe diagnostics", tc.name, err)
		}
	}
}

func TestNativeParsingOwnsPresenceFallbacksAndRoleScope(t *testing.T) {
	entries := []string{
		"AWS_MAX_ATTEMPTS=3", "AWS_SECRET_ACCESS_KEY= PRIVATE_SECRET ",
		"AWS_REGION=PRIVATE_PRIMARY", "AWS_DEFAULT_REGION=PRIVATE_FALLBACK",
		"HTTP_PROXY=", "http_proxy=http://PRIVATE_PROXY:3128",
		"GOOGLE_APPLICATION_CREDENTIALS=/PRIVATE_NONEXISTENT/credentials.json",
	}
	environment, err := Capture(entries)
	if err != nil {
		t.Fatal(err)
	}
	input, err := parseNativeInputs(environment, API)
	if err != nil || input.values["AWS_MAX_ATTEMPTS"].scalar.integer != 3 || input.values["AWS_SECRET_ACCESS_KEY"].scalar.text != " PRIVATE_SECRET " {
		t.Fatal("native input lost typed or raw credential values", err)
	}
	if value, exists := input.values["HTTP_PROXY"]; !exists || value.raw != "" {
		t.Fatal("explicit empty primary input lost its presence")
	}
	if value, exists := input.selected(nativeDefinitionByName(t, "AWS_REGION")); !exists || value.raw != "PRIVATE_PRIMARY" {
		t.Fatal("native primary precedence changed")
	}
	if value, exists := input.selected(nativeDefinitionByName(t, "HTTP_PROXY")); !exists || value.raw != "http://PRIVATE_PROXY:3128" {
		t.Fatal("native first nonempty fallback precedence changed")
	}
	cli, err := parseNativeInputs(environment, CLI)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := cli.values["AWS_MAX_ATTEMPTS"]; exists {
		t.Fatal("CLI acquired API-only native input")
	}
	entries[1] = "AWS_SECRET_ACCESS_KEY=PRIVATE_MUTATION"
	if input.values["AWS_SECRET_ACCESS_KEY"].raw != " PRIVATE_SECRET " {
		t.Fatal("native input retained a mutable caller slice")
	}
	for _, value := range []any{input, &input, input.values["AWS_SECRET_ACCESS_KEY"], struct{ Input nativeInputs }{input}} {
		encoded, err := json.Marshal(value)
		if err != nil || strings.Contains(string(encoded), "PRIVATE") || strings.Contains(fmt.Sprintf("%v %#v", value, value), "PRIVATE") {
			t.Fatal("native typed state leaked through formatting or JSON", err)
		}
	}
}

func TestNativeParsingAndRoleInputFailAtomically(t *testing.T) {
	e := roleEnvironment(t, API, false, "AWS_SECRET_ACCESS_KEY=PRIVATE_SECRET", "AWS_MAX_ATTEMPTS=PRIVATE_INVALID")
	input, err := parseNativeInputs(e, API)
	if !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(input, nativeInputs{}) {
		t.Fatal("native failure returned partial data", err)
	}
	role, err := parseRoleInput(e, API)
	if !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(role, parsedInput{}) {
		t.Fatal("role evaluator accepted malformed native primitives", err)
	}
	for _, role := range []Role{0, API | CLI, AllRoles} {
		input, err := parseNativeInputs(Environment{}, role)
		if !errors.Is(err, ErrInvalidRole) || !reflect.DeepEqual(input, nativeInputs{}) {
			t.Fatal("ambiguous native role was accepted", err)
		}
	}
}

func TestNativeScalarUsesDeclaredPolicyAfterNameChanges(t *testing.T) {
	// Native rules belong to metadata rather than duplicated option-name checks
	// in the parser. Renaming an option must preserve its declared grammar.
	for _, tc := range []struct{ name, raw string }{
		{"AWS_ACCOUNT_ID_ENDPOINT_MODE", "PREFERRED"},
		{"AZURE_TOKEN_CREDENTIALS", ""},
		{"AZURE_TOKEN_CREDENTIALS", "PROD"},
		{"MSI_SECRET", "PRIVATE_HEADER\n"},
	} {
		d := nativeDefinitionByName(t, tc.name)
		d.Name = "RENAMED_NATIVE_OPTION"
		if value, err := parseNativeScalar(d, tc.raw); !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(value, nativeValue{}) {
			t.Fatal("native parser lost schema policy after option rename", tc.name, err)
		}
	}
}
