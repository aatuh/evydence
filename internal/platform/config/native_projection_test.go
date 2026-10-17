package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func nativeGroups(s NativeSettings) []any {
	return []any{s.Postgres(), s.AWS(), s.Google(), s.Azure(), s.Host()}
}

func TestEveryNativeDefinitionHasOneTypedField(t *testing.T) {
	defs := make(map[string]NativeDefinition)
	for _, d := range NativeDefinitions() {
		defs[d.Name] = d
	}
	seen := make(map[string]bool)
	for _, group := range nativeGroups(NativeSettings{}) {
		typeOf := reflect.TypeOf(group)
		for i := range typeOf.NumField() {
			field := typeOf.Field(i)
			if field.Anonymous {
				continue
			}
			name := field.Tag.Get("env")
			d, ok := defs[name]
			if !ok || seen[name] {
				t.Fatal("native typed field has no unique schema owner", typeOf.Name(), field.Name)
			}
			var want reflect.Type
			switch {
			case d.Syntax == NativePostgresPorts:
				want = reflect.TypeFor[NativeOption[[]uint16]]()
			case d.Syntax == NativePostgresHosts || d.Syntax == NativePathList || d.Syntax == NativeCertDirectories || d.Syntax == NativeNoProxy || d.Syntax == NativeAuthSchemes || d.Syntax == NativeTenants || d.Syntax == NativeWindowsExtensions:
				want = reflect.TypeFor[NativeOption[[]string]]()
			case d.Kind == URL || d.Syntax == NativeMetadataHost || d.Syntax == NativeRelativeCredential:
				want = reflect.TypeFor[NativeOption[NativeURL]]()
			case d.Secret:
				want = reflect.TypeFor[NativeOption[Secret]]()
			case d.Kind == Boolean:
				want = reflect.TypeFor[NativeOption[bool]]()
			case d.Kind == Integer:
				want = reflect.TypeFor[NativeOption[int64]]()
			case d.Kind == Seconds || d.Kind == Duration:
				want = reflect.TypeFor[NativeOption[time.Duration]]()
			default:
				want = reflect.TypeFor[NativeOption[string]]()
			}
			if field.Type != want {
				t.Fatal("native field disagrees with schema type/secret classification", name)
			}
			seen[name] = true
		}
	}
	if len(seen) != len(defs) {
		t.Fatal("native schema options lack typed projections")
	}
}

func TestNativeTypedSettingsPreservePresenceAndFallbackSemantics(t *testing.T) {
	cfg := typedConfiguration(t, API,
		"AWS_ACCESS_KEY_ID=", "AWS_ACCESS_KEY=PRIVATE_LEGACY_KEY", "AWS_SECRET_ACCESS_KEY= PRIVATE_SECRET ",
		"AWS_PROFILE=", "AWS_DEFAULT_PROFILE=", "AWS_MAX_ATTEMPTS=0", "AWS_USE_FIPS_ENDPOINT=false",
		"HTTP_PROXY=", "http_proxy=http://user:PRIVATE_PROXY_PASSWORD@proxy.test:3128",
		"PGHOST=PRIVATE_NATIVE_HOST", "PGPORT=5433", "PGCONNECT_TIMEOUT=7",
	)
	a := cfg.Native().AWS()
	if !a.AccessKeyID.Present() || !a.AccessKeyID.HasValue() || a.AccessKeyID.Value().Reveal() != "PRIVATE_LEGACY_KEY" || a.SecretAccessKey.Value().Reveal() != " PRIVATE_SECRET " {
		t.Fatal("native credential fallback or exact bytes changed")
	}
	if !a.Profile.Present() || a.Profile.HasValue() || a.Profile.Value() != "" || a.SessionToken.Present() || a.SessionToken.HasValue() {
		t.Fatal("explicit empty and absent native inputs became indistinguishable")
	}
	if !a.MaxAttempts.HasValue() || a.MaxAttempts.Value() != 0 || !a.UseFIPSEndpoint.HasValue() || a.UseFIPSEndpoint.Value() {
		t.Fatal("explicit zero/false native values lost their presence")
	}
	p := cfg.Native().Postgres()
	if !slices.Equal(p.Hosts.Value(), []string{"PRIVATE_NATIVE_HOST"}) || !slices.Equal(p.Ports.Value(), []uint16{5433}) || p.ConnectTimeout.Value() != 7*time.Second {
		t.Fatal("native PostgreSQL types were not projected")
	}
	proxy := cfg.Native().Host().HTTPProxy.Value()
	if !cfg.Native().Host().HTTPProxy.HasValue() || proxy.URL().Host != "proxy.test:3128" {
		t.Fatal("native proxy fallback was not projected as a parsed URL")
	}
	for _, value := range []any{cfg.Native(), &a, p, cfg.Native().Host(), a.AccessKeyID, a.SecretAccessKey.Value(), proxy, a.Profile, struct{ Config Configuration }{cfg}} {
		encoded, err := json.Marshal(value)
		if err != nil || strings.Contains(string(encoded), "PRIVATE") || strings.Contains(fmt.Sprintf("%v %#v", value, value), "PRIVATE") {
			t.Fatal("typed native state disclosed operator input", err)
		}
	}
}

func TestNativeTypedSettingsOwnTheirMutableDataAndDatabaseLayers(t *testing.T) {
	input, err := parseRoleInput(roleEnvironment(t, API, false,
		"PGHOST=PRIVATE_HOST", "PGPORT=5433", "NO_PROXY=private.test,localhost",
		"AWS_AUTH_SCHEME_PREFERENCE=sigv4,sigv4a", "HTTPS_PROXY=https://user:PRIVATE_PASSWORD@proxy.test:3128",
	), API)
	if err != nil {
		t.Fatal(err)
	}
	cfg := projectInput(input)
	input.native.values["PGHOST"].items[0] = "PRIVATE_INPUT_MUTATION"
	input.native.values["PGPORT"].ports[0] = 1
	input.native.values["AWS_AUTH_SCHEME_PREFERENCE"].items[0] = "PRIVATE_INPUT_MUTATION"
	input.database.candidate.values["host"] = "PRIVATE_INPUT_MUTATION"
	hosts := cfg.Native().Postgres().Hosts.Value()
	ports := cfg.Native().Postgres().Ports.Value()
	noProxy := cfg.Native().Host().NoProxy.Value()
	hosts[0], ports[0], noProxy[0] = "PRIVATE_CALLER_MUTATION", 2, "PRIVATE_CALLER_MUTATION"
	u := cfg.Native().Host().HTTPSProxy.Value().URL()
	u.Host, u.User = "PRIVATE_CALLER_MUTATION", url.UserPassword("changed", "PRIVATE_CHANGED")
	if cfg.Native().Postgres().Hosts.Value()[0] != "PRIVATE_HOST" || cfg.Native().Postgres().Ports.Value()[0] != 5433 || cfg.Native().Host().NoProxy.Value()[0] != "private.test" || cfg.Native().AWS().AuthSchemePreference.Value()[0] != "sigv4" || cfg.Native().Host().HTTPSProxy.Value().URL().Host != "proxy.test:3128" || cfg.database.candidate.values["host"] != "PRIVATE_DATABASE" {
		t.Fatal("native projection or returned data shares caller-owned state")
	}
}

func TestEveryNativeTypedFieldReadsItsDeclaredSource(t *testing.T) {
	for _, d := range NativeDefinitions() {
		t.Run(d.Name, func(t *testing.T) {
			value := nativeValue{
				raw:      "PRIVATE_RAW_" + d.Name,
				scalar:   scalarValue{text: "PRIVATE_TEXT_" + d.Name, boolean: true, integer: 71, duration: 7 * time.Second},
				endpoint: url.URL{Scheme: "https", Host: "PRIVATE_HOST", Path: "/" + d.Name},
				items:    []string{"PRIVATE_ITEM_" + d.Name}, ports: []uint16{5433},
			}
			native := projectNative(nativeInputs{values: map[string]nativeValue{d.Name: value}})
			for _, group := range nativeGroups(native) {
				r := reflect.ValueOf(group)
				for i := range r.NumField() {
					if r.Type().Field(i).Tag.Get("env") != d.Name {
						continue
					}
					field := r.Field(i)
					if !field.MethodByName("Present").Call(nil)[0].Bool() || !field.MethodByName("HasValue").Call(nil)[0].Bool() {
						t.Fatal("native typed field dropped supplied presence")
					}
					got := field.MethodByName("Value").Call(nil)[0].Interface()
					ok := false
					switch actual := got.(type) {
					case string:
						ok = actual == value.scalar.text
					case Secret:
						ok = actual.Reveal() == value.raw
					case bool:
						ok = actual
					case int64:
						ok = actual == 71
					case time.Duration:
						ok = actual == 7*time.Second
					case NativeURL:
						ok = actual.URL().Path == "/"+d.Name
					case []string:
						ok = slices.Equal(actual, value.items)
					case []uint16:
						ok = slices.Equal(actual, value.ports)
					}
					if !ok {
						t.Fatal("native typed field read a different source or primitive")
					}
					return
				}
			}
			t.Fatal("native source has no typed field")
		})
	}
}
