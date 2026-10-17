package config

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestNativeAzureCoreInputsAreTypedAndRedacted(t *testing.T) {
	cfg := typedConfiguration(t, API, "AZURE_SDK_GO_LOGGING=all", "OS=PRIVATE_OS")
	if !cfg.Native().Azure().SDKLogging.HasValue() || cfg.Native().Azure().SDKLogging.Value() != "all" || cfg.Native().Host().OperatingSystem.Value() != "PRIVATE_OS" {
		t.Fatal("Azure core environment inputs are missing from typed capture")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", cfg.Native(), cfg.Native()), "PRIVATE") {
		t.Fatal("native telemetry input leaked through default formatting")
	}
}

func TestProductionRejectsRawAzureSDKLoggingBeforeStartup(t *testing.T) {
	input, err := parseRoleInput(roleEnvironment(t, API, true, "AZURE_SDK_GO_LOGGING=all"), API)
	if !errors.Is(err, ErrUnsafeProduction) || !reflect.DeepEqual(input, parsedInput{}) || strings.Contains(fmt.Sprintf("%v %#v", err, err), "all") {
		t.Fatal("production admitted raw SDK request/response logging or returned partial settings", err)
	}
	for _, raw := range []string{"", "off"} {
		if _, err := parseRoleInput(roleEnvironment(t, API, true, "AZURE_SDK_GO_LOGGING="+raw), API); err != nil {
			t.Fatal("disabled native logging acquired a new requirement", err)
		}
	}
	for _, role := range []Role{Worker, Migrate, CLI} {
		if _, err := parseRoleInput(roleEnvironment(t, role, true, "AZURE_SDK_GO_LOGGING=all"), role); err != nil {
			t.Fatal("unused API SDK imposed another process's production dependency", role, err)
		}
	}
}

func TestNativeAzureCoreGrammarAndPolicyMetadataAreOwned(t *testing.T) {
	for _, entry := range []string{"AZURE_SDK_GO_LOGGING=ALL", "AZURE_SDK_GO_LOGGING=PRIVATE_INVALID", "OS=PRIVATE\nHEADER", "OS=" + strings.Repeat("x", 257)} {
		input, err := parseRoleInput(roleEnvironment(t, API, false, entry), API)
		if !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(input, parsedInput{}) || strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
			t.Fatal("invalid native logging/telemetry input was admitted", err)
		}
	}
	for _, d := range NativeDefinitions() {
		if d.Name == "AZURE_SDK_GO_LOGGING" {
			if len(d.ProductionAllowed) == 0 {
				t.Fatal("native production policy is missing from schema metadata")
			}
			d.ProductionAllowed[0] = "all"
		}
	}
	if _, err := parseRoleInput(roleEnvironment(t, API, true, "AZURE_SDK_GO_LOGGING=all"), API); !errors.Is(err, ErrUnsafeProduction) {
		t.Fatal("returned native schema metadata weakened production policy", err)
	}
}
