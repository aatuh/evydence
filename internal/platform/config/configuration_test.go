package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func typedConfiguration(t *testing.T, role Role, extra ...string) Configuration {
	t.Helper()
	input, err := parseRoleInput(roleEnvironment(t, role, false, extra...), role)
	if err != nil {
		t.Fatal(err)
	}
	return projectInput(input)
}

func TestConfigurationProjectsTypedRoleSettings(t *testing.T) {
	cfg := typedConfiguration(t, API, "EVYDENCE_HTTP_READ_HEADER_TIMEOUT_SECONDS=7", "EVYDENCE_HTTP_MAX_HEADER_BYTES=32768", "EVYDENCE_BOOTSTRAP_TENANT=  Tenant  ", "EVYDENCE_DATABASE_URL= host=PRIVATE_DATABASE dbname=evydence ", "EVYDENCE_API_KEY_PEPPER= PRIVATE_PEPPER ", "EVYDENCE_WORKER_OWNED_PARSER_SIDE_EFFECTS=true")
	if cfg.Role() != API || cfg.Production() || cfg.Runtime().Profile != "postgres" || cfg.Runtime().PostgresLoadMode != "snapshot_preferred" || cfg.Runtime().LogFormat != "json" || cfg.Runtime().DatabaseURL.Reveal() != "host=PRIVATE_DATABASE dbname=evydence" {
		t.Fatal("runtime settings were not projected")
	}
	a := cfg.API()
	if a.HTTPReadHeaderTimeout != 7*time.Second || a.HTTPMaxHeaderBytes != 32768 || a.BootstrapTenant != "  Tenant  " || a.KeyPepper.Reveal() != "PRIVATE_PEPPER" || !a.WorkerOwnedParserSideEffects {
		t.Fatal("API types or whitespace contracts changed")
	}
	if cfg.Providers().AWSKMSTimeout != 10*time.Second || cfg.Storage().Kind != "filesystem" || cfg.Storage().Directory != "tmp/objects" {
		t.Fatal("provider/storage defaults were not projected")
	}
	w := typedConfiguration(t, Worker, "EVYDENCE_WORKER_POLL_INTERVAL=250ms", "EVYDENCE_WORKER_METRICS_TOKEN_FILE=/PRIVATE_NONEXISTENT/token").Worker()
	if w.PollInterval != 250*time.Millisecond || w.BatchSize != 10 || w.MaxPayloadBytes != 20971520 || w.HealthAddress != netip.MustParseAddrPort("127.0.0.1:8081") || w.MetricsAddress != netip.MustParseAddrPort("127.0.0.1:9091") {
		t.Fatal("worker settings were not projected to typed values")
	}
	c := typedConfiguration(t, CLI, "CI=true", "EVYDENCE_API_KEY= PRIVATE_CLI_KEY ", "EVYDENCE_BUILD_STARTED_AT=2026-10-16T12:00:00Z", "GITHUB_SHA=PRIVATE_SHA").CLI()
	if !c.CI || c.APIKey.Reveal() != "PRIVATE_CLI_KEY" || c.BuildStartedAt != time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC) || !c.BuildFinishedAt.IsZero() || c.GitHubSHA != "PRIVATE_SHA" {
		t.Fatal("CLI types or captured CI identity changed")
	}
	if cfg.Worker().HealthAddress.IsValid() || cfg.CLI().APIKey.IsSet() || typedConfiguration(t, Migrate).Runtime().Profile != "" {
		t.Fatal("a role acquired another role's settings")
	}
}

func TestConfigurationReturnedSettingsAndSlicesAreOwned(t *testing.T) {
	cfg := typedConfiguration(t, API,
		"EVYDENCE_TRUSTED_PROXY_CIDRS=10.0.0.0/8",
		"EVYDENCE_SIGNING_EXECUTOR_PUBLIC_KEY_BASE64=eHl6",
		"EVYDENCE_SIGSTORE_TRUST_ROOT_JSON_BASE64=e30=",
		"EVYDENCE_SIGSTORE_TRUSTED_PUBLIC_KEY_PEM_BASE64=YWJj",
	)
	runtime := cfg.Runtime()
	runtime.LogFormat = "PRIVATE_MUTATION"
	a := cfg.API()
	a.BootstrapTenant = "PRIVATE_MUTATION"
	prefixes := a.TrustedProxyCIDRs()
	prefixes[0] = netip.MustParsePrefix("192.0.2.0/24")
	p := cfg.Providers()
	for _, bytes := range [][]byte{p.SigningExecutorPublicKey(), p.SigstoreTrustRootJSON(), p.SigstoreTrustedPublicKeyPEM()} {
		bytes[0] = 0
	}
	if cfg.Runtime().LogFormat != "json" || cfg.API().BootstrapTenant != "Local Tenant" || cfg.API().TrustedProxyCIDRs()[0].String() != "10.0.0.0/8" || string(cfg.Providers().SigningExecutorPublicKey()) != "xyz" || string(cfg.Providers().SigstoreTrustRootJSON()) != "{}" || string(cfg.Providers().SigstoreTrustedPublicKeyPEM()) != "abc" {
		t.Fatal("returned settings or slices changed owned configuration")
	}
	// Independently projected configurations also own their decoded slices.
	input, err := parseRoleInput(roleEnvironment(t, API, false, "EVYDENCE_SIGSTORE_TRUST_ROOT_JSON_BASE64=e30="), API)
	if err != nil {
		t.Fatal(err)
	}
	projected := projectInput(input)
	input.values["EVYDENCE_SIGSTORE_TRUST_ROOT_JSON_BASE64"].bytes[0] = 0
	if string(projected.Providers().SigstoreTrustRootJSON()) != "{}" {
		t.Fatal("typed projection retained a mutable parser slice")
	}
}

func TestConfigurationAndSecretFormattingAreRedacted(t *testing.T) {
	cfg := typedConfiguration(t, API, "EVYDENCE_API_KEY_PEPPER=PRIVATE_PEPPER", "EVYDENCE_BOOTSTRAP_TENANT=PRIVATE_TENANT", "EVYDENCE_AWS_KMS_KEY_ID=PRIVATE_PROVIDER_KEY", "EVYDENCE_S3_ENDPOINT=PRIVATE_STORAGE", "EVYDENCE_S3_SECRET_ACCESS_KEY=PRIVATE_S3_KEY")
	worker := typedConfiguration(t, Worker, "EVYDENCE_WORKER_METRICS_TOKEN_FILE=/PRIVATE_NONEXISTENT/token")
	cli := typedConfiguration(t, CLI, "EVYDENCE_API_KEY=PRIVATE_CLI_KEY", "GITHUB_ACTOR=PRIVATE_ACTOR")
	for _, value := range []any{cfg, &cfg, cfg.Runtime(), cfg.API(), worker.Worker(), cfg.Storage(), cfg.Providers(), cli.CLI(), cfg.Runtime().DatabaseURL, cfg.API().KeyPepper, struct{ Config Configuration }{cfg}, map[string]Secret{"credential": cli.CLI().APIKey}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if strings.Contains(fmt.Sprintf(format, value), "PRIVATE") {
				t.Fatal("configuration formatting leaked input")
			}
		}
		encoded, err := json.Marshal(value)
		if err != nil || strings.Contains(string(encoded), "PRIVATE") {
			t.Fatal("configuration JSON leaked input", err)
		}
	}
	if !cfg.API().KeyPepper.IsSet() || (Secret{}).IsSet() || (Secret{}).Reveal() != "" {
		t.Fatal("secret presence or explicit access contract changed")
	}
}

func TestEverySchemaOptionHasExactlyOneTypedProjection(t *testing.T) {
	defs := schemaByName(t)
	seen := make(map[string]bool)
	for _, settings := range []any{RuntimeSettings{}, APISettings{}, WorkerSettings{}, StorageSettings{}, ProviderSettings{}, CLISettings{}} {
		typeOf := reflect.TypeOf(settings)
		for i := range typeOf.NumField() {
			field := typeOf.Field(i)
			name := field.Tag.Get("env")
			if name == "" {
				if !field.Anonymous {
					t.Fatal("configuration field has no schema owner", typeOf.Name(), field.Name)
				}
				continue
			}
			d, ok := defs[name]
			if !ok || seen[name] {
				t.Fatal("projection is absent from the schema or duplicated", name)
			}
			if d.Secret != (field.Type == reflect.TypeFor[Secret]()) {
				t.Fatal("typed projection disagrees with secret classification", name)
			}
			seen[name] = true
		}
	}
	if len(seen) != len(defs) {
		for name := range defs {
			if !seen[name] {
				t.Error("schema option has no typed projection", name)
			}
		}
	}
}

func TestEveryTypedProjectionReadsItsDeclaredSource(t *testing.T) {
	// Set one source at a time. Wrong names or scalar members cannot hide behind
	// matching defaults, identical booleans or another populated setting.
	for _, d := range Definitions() {
		t.Run(d.Name, func(t *testing.T) {
			v := scalarValue{text: "PRIVATE_SOURCE_" + d.Name, boolean: true, integer: 71, duration: 7 * time.Second, timestamp: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC), bytes: []byte("PRIVATE_BYTES"), prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
			if d.Name == "EVYDENCE_WORKER_HEALTH_ADDR" || d.Name == "EVYDENCE_WORKER_METRICS_ADDR" {
				v.text = "127.0.0.1:9091"
			}
			cfg := projectInput(parsedInput{values: map[string]scalarValue{d.Name: v}})
			for _, settings := range []any{cfg.Runtime(), cfg.API(), cfg.Worker(), cfg.Storage(), cfg.Providers(), cfg.CLI()} {
				r := reflect.ValueOf(settings)
				for i := range r.NumField() {
					field := r.Type().Field(i)
					if field.Tag.Get("env") != d.Name {
						continue
					}
					actual := r.Field(i)
					ok := false
					switch field.Type {
					case reflect.TypeFor[Secret]():
						ok = actual.Interface().(Secret).Reveal() == v.text
					case reflect.TypeFor[string]():
						ok = actual.String() == v.text
					case reflect.TypeFor[bool]():
						ok = actual.Bool()
					case reflect.TypeFor[int64]():
						ok = actual.Int() == v.integer
					case reflect.TypeFor[time.Duration]():
						ok = actual.Int() == int64(v.duration)
					case reflect.TypeFor[time.Time]():
						ok = actual.Interface().(time.Time).Equal(v.timestamp)
					case reflect.TypeFor[netip.AddrPort]():
						ok = actual.Interface().(netip.AddrPort).String() == v.text
					case reflect.TypeFor[[]byte]():
						ok = string(actual.Bytes()) == string(v.bytes)
					case reflect.TypeFor[[]netip.Prefix]():
						prefixes := cfg.API().TrustedProxyCIDRs()
						ok = len(prefixes) == 1 && prefixes[0] == v.prefixes[0]
					}
					if !ok {
						t.Fatal("typed field did not read its declared source and kind", field.Name)
					}
					return
				}
			}
			t.Fatal("schema source has no typed field")
		})
	}
}
