package config_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/platform/config"
)

func TestConfigurationMatchesOnlyItsCapturedSource(t *testing.T) {
	entries := []string{"EVYDENCE_RUNTIME_PROFILE=postgres", "EVYDENCE_DATABASE_URL=host=PRIVATE_DB", "PGUSER=PRIVATE_USER", "UNRELATED=first"}
	input, err := config.Capture(entries)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := config.Parse(input, config.Worker)
	if err != nil {
		t.Fatal(err)
	}
	identity := settings.SourceIdentity()
	for _, tc := range []struct {
		entries []string
		match   bool
	}{
		{[]string{"UNRELATED=changed", "PGUSER=PRIVATE_USER", "EVYDENCE_DATABASE_URL=host=PRIVATE_DB", "EVYDENCE_RUNTIME_PROFILE=postgres"}, true},
		{[]string{"PGUSER=PRIVATE_CHANGED", "EVYDENCE_DATABASE_URL=host=PRIVATE_DB", "EVYDENCE_RUNTIME_PROFILE=postgres"}, false},
		{[]string{"PGUSER=PRIVATE_USER", "EVYDENCE_DATABASE_URL= host=PRIVATE_DB ", "EVYDENCE_RUNTIME_PROFILE=postgres"}, false},
		{[]string{"PGUSER=PRIVATE_USER", "EVYDENCE_DATABASE_URL=host=PRIVATE_DB", "EVYDENCE_RUNTIME_PROFILE=postgres", "EVYDENCE_API_KEY="}, false},
	} {
		current, err := config.Capture(tc.entries)
		if err != nil || identity.MatchesSource(current) != tc.match {
			t.Fatal("configuration source comparison changed raw ownership or selection", err)
		}
	}
	if (config.Configuration{}).SourceIdentity().MatchesSource(input) || identity.MatchesSource(config.Environment{}) {
		t.Fatal("zero values authorized a source match")
	}
}

func TestSourceIdentityRetainsNoInputReferencesAndRedactsFingerprint(t *testing.T) {
	var inspect func(reflect.Type)
	inspect = func(kind reflect.Type) {
		switch kind.Kind() {
		case reflect.String, reflect.Map, reflect.Slice, reflect.Pointer, reflect.Interface, reflect.Func, reflect.Chan, reflect.UnsafePointer:
			t.Fatal("source identity can retain configuration values", kind)
		case reflect.Array:
			inspect(kind.Elem())
		case reflect.Struct:
			for i := range kind.NumField() {
				inspect(kind.Field(i).Type)
			}
		}
	}
	input, err := config.Capture([]string{"EVYDENCE_API_KEY=PRIVATE_TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	settings, err := config.Parse(input, config.CLI)
	if err != nil {
		t.Fatal(err)
	}
	identity := settings.SourceIdentity()
	settings = config.Configuration{}
	if settings.Role() != 0 || !identity.MatchesSource(input) {
		t.Fatal("source identity depends on its settings object's lifetime")
	}
	inspect(reflect.TypeOf(identity))
	encoded, err := json.Marshal(identity)
	if err != nil || string(encoded) != `{"redacted":true}` || fmt.Sprintf("%v", identity) != "config.Value{redacted}" || fmt.Sprintf("%#v", identity) != "config.Value{redacted}" {
		t.Fatal("source identity exposes its fingerprint", err)
	}
}
