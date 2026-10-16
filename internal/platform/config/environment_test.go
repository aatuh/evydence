package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestCaptureOwnsSelectedInputWithoutReadingAmbientEnvironment(t *testing.T) {
	t.Setenv("EVYDENCE_AMBIENT_ONLY", "PRIVATE_AMBIENT_SECRET")
	input := []string{
		"ENV=production", "EVYDENCE_DATABASE_URL= PRIVATE_DATABASE_SECRET ",
		"EVYDENCE_EMPTY=", "AWS_REGION=eu-test-1", "GOOGLE_APPLICATION_CREDENTIALS=/PRIVATE_GOOGLE",
		"AZURE_TENANT_ID=PRIVATE_AZURE", "GITHUB_TOKEN=PRIVATE_GITHUB", "CI=true", "PATH=PRIVATE_PATH",
	}
	e, err := Capture(input)
	if err != nil {
		t.Fatal(err)
	}
	input[1] = "EVYDENCE_DATABASE_URL=PRIVATE_REPLACEMENT"
	if value, ok := e.lookup("EVYDENCE_DATABASE_URL"); !ok || value != " PRIVATE_DATABASE_SECRET " {
		t.Fatal("capture changed raw bytes or retained the caller's slice")
	}
	if value, ok := e.lookup("EVYDENCE_EMPTY"); !ok || value != "" {
		t.Fatal("explicit empty input lost its presence")
	}
	for _, name := range []string{"PATH", "EVYDENCE_AMBIENT_ONLY", "EVYDENCE_UNSET"} {
		if _, ok := e.lookup(name); ok {
			t.Fatal("capture read ambient or unrelated input")
		}
	}
	for _, name := range []string{"ENV", "AWS_REGION", "GOOGLE_APPLICATION_CREDENTIALS", "AZURE_TENANT_ID", "GITHUB_TOKEN", "CI"} {
		if _, ok := e.lookup(name); !ok {
			t.Fatal("supported process/SDK/CI namespace was lost", name)
		}
	}
}

func TestCaptureRejectsMalformedOrUnboundedInputWithoutReturningValues(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []string
	}{
		{"duplicate", []string{"EVYDENCE_KEY=PRIVATE_FIRST", "EVYDENCE_KEY=PRIVATE_SECOND"}},
		{"missing-equals", []string{"EVYDENCE_PRIVATE_SECRET"}},
		{"invalid-name", []string{"EVYDENCE_PRIVATE SECRET=value"}},
		{"long-name", []string{"EVYDENCE_" + strings.Repeat("X", 256) + "=PRIVATE_VALUE"}},
		{"nul-value", []string{"EVYDENCE_KEY=PRIVATE\x00SECRET"}},
		{"invalid-utf8", []string{"EVYDENCE_KEY=PRIVATE" + string([]byte{255})}},
		{"entry-count", make([]string, 4097)},
		{"byte-bound", []string{"EVYDENCE_KEY=" + strings.Repeat("P", 8<<20)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := Capture(tc.entries)
			if !errors.Is(err, ErrInvalidEnvironment) || !reflect.DeepEqual(e, Environment{}) {
				t.Fatal("invalid input returned usable or partially captured configuration", err)
			}
			if strings.Contains(fmt.Sprintf("%+v %#v", err, err), "PRIVATE") {
				t.Fatal("validation diagnostic exposed supplied input")
			}
		})
	}
}

func TestCaptureBoundsCombinedBytesAndSelectedSettings(t *testing.T) {
	// Every individual entry is below the byte bound; the combined input is not.
	if _, err := Capture([]string{"EVYDENCE_A=" + strings.Repeat("a", 4<<20), "EVYDENCE_B=" + strings.Repeat("b", 4<<20)}); !errors.Is(err, ErrInvalidEnvironment) {
		t.Fatal("combined source size was unbounded", err)
	}
	entries := make([]string, 1025)
	for i := range entries {
		entries[i] = fmt.Sprintf("EVYDENCE_OPTION_%d=value", i)
	}
	if _, err := Capture(entries); !errors.Is(err, ErrInvalidEnvironment) {
		t.Fatal("selected-setting count was unbounded", err)
	}
}

func TestEnvironmentFormattingAndJSONNeverExposeCapturedInput(t *testing.T) {
	e, err := Capture([]string{"EVYDENCE_PRIVATE_NAME=PRIVATE_DATABASE_PASSWORD", "AWS_SECRET_ACCESS_KEY=PRIVATE_AWS_SECRET"})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{e, &e, struct{ Input Environment }{e}, map[string]Environment{"input": e}} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, value), "PRIVATE") {
				t.Fatal("configuration formatting exposed names or values")
			}
		}
		raw, err := json.Marshal(value)
		if err != nil || strings.Contains(string(raw), "PRIVATE") {
			t.Fatal("configuration JSON exposed names or values", err)
		}
	}
	raw, err := json.Marshal(e)
	if err != nil || string(raw) != `{"redacted":true}` {
		t.Fatal("safe configuration JSON contract changed", err)
	}
}

func TestEnvironmentFingerprintAndNamesAreStableOwnedValues(t *testing.T) {
	first, err := Capture([]string{"EVYDENCE_B=two=parts", "ENV=production", "EVYDENCE_A=one", "PATH=first"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Capture([]string{"PATH=second", "EVYDENCE_A=one", "EVYDENCE_B=two=parts", "ENV=production"})
	if err != nil || first.fingerprint != second.fingerprint {
		t.Fatal("input ordering or unrelated environment changed the fingerprint", err)
	}
	changed, err := Capture([]string{"EVYDENCE_A=changed", "EVYDENCE_B=two=parts", "ENV=production"})
	if err != nil || changed.fingerprint == first.fingerprint {
		t.Fatal("changed selected values retained their old fingerprint", err)
	}
	names := first.names()
	if !reflect.DeepEqual(names, []string{"ENV", "EVYDENCE_A", "EVYDENCE_B"}) {
		t.Fatal("setting order is nondeterministic")
	}
	names[0] = "PRIVATE_MUTATION"
	if first.names()[0] != "ENV" {
		t.Fatal("caller changed captured metadata")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				if value, ok := first.lookup("EVYDENCE_B"); !ok || value != "two=parts" {
					t.Error("concurrent configuration read changed")
				}
			}
		})
	}
	wg.Wait()
}
