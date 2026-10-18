package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func schemaByName(t *testing.T) map[string]Definition {
	t.Helper()
	result := map[string]Definition{}
	for _, d := range Definitions() {
		if result[d.Name].Name != "" || !validEnvironmentName(d.Name) || d.Roles == 0 || d.Roles&^AllRoles != 0 || d.Description == "" {
			t.Fatal("invalid or duplicate schema definition", d.Name)
		}
		result[d.Name] = d
	}
	return result
}

func TestSchemaCapturesExistingIngressAndLifecycleContracts(t *testing.T) {
	defs := schemaByName(t)
	for _, tc := range []struct {
		name, fallback string
		kind           Kind
		min, max       int64
	}{
		{"EVYDENCE_HTTP_READ_HEADER_TIMEOUT_SECONDS", "5", Seconds, 1, 60},
		{"EVYDENCE_HTTP_READ_TIMEOUT_SECONDS", "30", Seconds, 1, 900},
		{"EVYDENCE_HTTP_WRITE_TIMEOUT_SECONDS", "60", Seconds, 1, 900},
		{"EVYDENCE_HTTP_IDLE_TIMEOUT_SECONDS", "120", Seconds, 1, 3600},
		{"EVYDENCE_HTTP_SHUTDOWN_TIMEOUT_SECONDS", "30", Seconds, 1, 300},
		{"EVYDENCE_HTTP_MAX_HEADER_BYTES", "16384", Integer, 1024, 1048576},
		{"EVYDENCE_HTTP_MAX_URL_BYTES", "8192", Integer, 1024, 65536},
		{"EVYDENCE_HTTP_MAX_IN_FLIGHT_REQUESTS", "256", Integer, 1, 100000},
		{"EVYDENCE_HTTP_MAX_CONCURRENT_UPLOADS", "8", Integer, 1, 10000},
		{"EVYDENCE_RATE_LIMIT_REQUESTS_PER_MINUTE", "120", Integer, 0, 60000},
		{"EVYDENCE_AUTH_FAILURES_PER_MINUTE", "20", Integer, 1, 60000},
		{"EVYDENCE_EXPENSIVE_TENANT_REQUESTS_PER_MINUTE", "30", Integer, 0, 60000},
		{"EVYDENCE_RATE_LIMIT_BUCKET_CAPACITY", "10000", Integer, 1, 1000000},
		{"EVYDENCE_WORKER_SHUTDOWN_TIMEOUT_SECONDS", "30", Seconds, 1, 300},
		{"EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS", "5", Seconds, 1, 60},
		{"EVYDENCE_SSO_SESSION_MAX_LIFETIME_SECONDS", "43200", Seconds, 60, 43200},
		{"EVYDENCE_SSO_SESSION_IDLE_TIMEOUT_SECONDS", "1800", Seconds, 60, 43200},
	} {
		d, ok := defs[tc.name]
		if !ok || d.Default != tc.fallback || d.Kind != tc.kind || d.Min != tc.min || d.Max != tc.max {
			t.Fatal("existing validated configuration contract changed", tc.name)
		}
	}
	if defs["EVYDENCE_WORKER_HEALTH_ADDR"].Default != "127.0.0.1:8081" || defs["EVYDENCE_WORKER_POLL_INTERVAL"].Default != "1s" || defs["EVYDENCE_WORKER_BATCH_SIZE"].Default != "10" || defs["EVYDENCE_WORKER_MAX_PAYLOAD_BYTES"].Default != "20971520" {
		t.Fatal("worker defaults changed")
	}
	if defs["EVYDENCE_DATABASE_URL"].Required != API|Worker|Migrate|WorkerReplay|WorkerReconcile || defs["EVYDENCE_API_KEY_PEPPER"].ProductionRequired != API {
		t.Fatal("process-specific requirements changed")
	}
}

func TestSchemaPreservesExplicitRuntimeProfileSelection(t *testing.T) {
	d := schemaByName(t)["EVYDENCE_RUNTIME_PROFILE"]
	if d.Default != "" || d.Required != API|Worker|WorkerReplay|WorkerReconcile || !slices.Equal(d.Allowed, []string{"postgres"}) {
		t.Fatal("schema silently supplied a runtime profile that existing startup requires explicitly")
	}
}

func TestSchemaPreservesConditionalLoadModeDefaultAndProductionRestriction(t *testing.T) {
	d := schemaByName(t)["EVYDENCE_POSTGRES_LOAD_MODE"]
	if d.Default != "" || d.DefaultPolicy == "" || !slices.Contains(d.Allowed, "snapshot_preferred") || !slices.Contains(d.Allowed, "relational_only") || !slices.Contains(d.ProductionAllowed, "relational_only") || slices.Contains(d.ProductionAllowed, "snapshot_preferred") {
		t.Fatal("load-mode compatibility or production isolation was flattened")
	}
}

func TestSchemaClassifiesSecretAndConditionalConfiguration(t *testing.T) {
	defs := schemaByName(t)
	for _, name := range []string{"EVYDENCE_DATABASE_URL", "EVYDENCE_API_KEY", "EVYDENCE_API_KEY_PEPPER", "EVYDENCE_S3_ACCESS_KEY_ID", "EVYDENCE_S3_SECRET_ACCESS_KEY", "EVYDENCE_SIGNING_EXECUTOR_TOKEN", "EVYDENCE_PROVIDER_VALIDATION_GATEWAY_TOKEN", "EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_TOKEN"} {
		d, ok := defs[name]
		if !ok || !d.Secret || d.Default != "" {
			t.Fatal("secret is absent, public or has a generated default", name)
		}
	}
	for _, name := range []string{"EVYDENCE_PRINT_BOOTSTRAP_SECRET", "EVYDENCE_OIDC_DISCOVERY_ALLOW_INSECURE_LOCALHOST", "EVYDENCE_OIDC_USERINFO_ALLOW_INSECURE_LOCALHOST", "EVYDENCE_SIGNING_EXECUTOR_ALLOW_INSECURE_LOCALHOST", "EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_ALLOW_INSECURE_LOCALHOST", "EVYDENCE_PROVIDER_VALIDATION_GATEWAY_ALLOW_INSECURE_LOCALHOST", "EVYDENCE_TRANSPARENCY_FETCH_ALLOW_INSECURE_LOCALHOST"} {
		d := defs[name]
		if d.Kind != Boolean || !d.ForbiddenInProduction {
			t.Fatal("local-only option lost its production constraint", name)
		}
	}
	if !slices.Contains(defs["EVYDENCE_AWS_REGION"].Aliases, "AWS_REGION") || defs["EVYDENCE_WORKER_METRICS_ADDR"].DefaultPolicy == "" || defs["EVYDENCE_BUILD_STARTED_AT"].DefaultPolicy == "" {
		t.Fatal("alias or conditional/dynamic default was flattened into a literal")
	}
}

func TestSchemaDefaultsCannotPublishSecretsOrInvalidConditionalValues(t *testing.T) {
	defs := schemaByName(t)
	for _, d := range defs {
		for _, raw := range []string{d.Default, d.ProductionDefault, d.NonProductionDefault, d.ConditionalDefault, d.ProductionExample} {
			if raw == "" {
				continue
			}
			if d.Secret {
				t.Fatal("secret default could reach generated configuration", d.Name)
			}
			if _, err := parseScalar(d, raw); err != nil {
				t.Fatal("conditional schema default is invalid", d.Name, err)
			}
		}
		if d.DefaultWhenSet != "" {
			dependency, ok := defs[d.DefaultWhenSet]
			if !ok || d.ConditionalDefault == "" || dependency.Roles&d.Roles != d.Roles {
				t.Fatal("conditional default references an unavailable role input", d.Name)
			}
		}
	}
}

func TestSchemaOwnsHTTPPoliciesAndLocalOverrides(t *testing.T) {
	defs := schemaByName(t)
	for _, d := range defs {
		if d.Kind == URL && d.Name != "EVYDENCE_DATABASE_URL" && d.Name != "EVYDENCE_S3_ENDPOINT" && d.EndpointPolicy == "" {
			t.Fatal("HTTP option lacks a schema-owned endpoint policy", d.Name)
		}
		if d.LocalhostOverride != "" {
			override, ok := defs[d.LocalhostOverride]
			if !ok || override.Kind != Boolean || !override.ForbiddenInProduction || override.Roles&d.Roles != d.Roles {
				t.Fatal("endpoint references an unsafe or unavailable localhost override", d.Name)
			}
		}
	}
}

func TestSchemaMetadataIsSortedAndOwned(t *testing.T) {
	first := Definitions()
	if len(first) == 0 || !slices.IsSortedFunc(first, func(a, b Definition) int { return strings.Compare(a.Name, b.Name) }) {
		t.Fatal("schema order is unstable")
	}
	for i := range first {
		if len(first[i].Allowed) > 0 {
			first[i].Allowed[0] = "PRIVATE_ALLOWED_MUTATION"
		}
		if len(first[i].Aliases) > 0 {
			first[i].Aliases[0] = "PRIVATE_ALIAS_MUTATION"
		}
		if len(first[i].ProductionAllowed) > 0 {
			first[i].ProductionAllowed[0] = "PRIVATE_PRODUCTION_MUTATION"
		}
		first[i].Name = "PRIVATE_NAME_MUTATION"
	}
	for _, d := range Definitions() {
		if strings.Contains(d.Name, "PRIVATE") || slices.Contains(d.Allowed, "PRIVATE_ALLOWED_MUTATION") || slices.Contains(d.Aliases, "PRIVATE_ALIAS_MUTATION") || slices.Contains(d.ProductionAllowed, "PRIVATE_PRODUCTION_MUTATION") {
			t.Fatal("caller mutated schema metadata")
		}
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for _, d := range Definitions() {
				if len(d.Allowed) > 0 {
					d.Allowed[0] = "PRIVATE_CONCURRENT_MUTATION"
				}
			}
		})
	}
	wg.Wait()
	for _, d := range Definitions() {
		if slices.Contains(d.Allowed, "PRIVATE_CONCURRENT_MUTATION") {
			t.Fatal("concurrent caller changed shared metadata")
		}
	}
}

func TestSchemaCoversCurrentProductionSourceEnvironmentNames(t *testing.T) {
	known := map[string]bool{}
	for _, d := range Definitions() {
		known[d.Name] = true
	}
	for _, d := range Definitions() {
		for _, alias := range d.Aliases {
			if known[alias] {
				t.Fatal("schema alias collides with another option", alias)
			}
			known[alias] = true
		}
	}
	root := filepath.Clean("../../..")
	for _, base := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, base), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if path == filepath.Join(root, "internal/platform/config") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(node ast.Node) bool {
				literal, ok := node.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					return true
				}
				name, err := strconv.Unquote(literal.Value)
				if err == nil && selectedEnvironmentName(name) && validEnvironmentName(name) && !strings.HasSuffix(name, "_") && !known[name] {
					t.Error("source environment name is absent from schema:", filepath.ToSlash(path), name)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
