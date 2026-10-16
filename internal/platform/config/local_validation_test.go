package config

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestRoleInputRejectsInvalidLocalCombinations(t *testing.T) {
	for _, tc := range []struct {
		name       string
		role       Role
		production bool
		extra      []string
		want       error
	}{
		{"session-idle-exceeds-maximum", API, false, []string{"EVYDENCE_SSO_SESSION_MAX_LIFETIME_SECONDS=600", "EVYDENCE_SSO_SESSION_IDLE_TIMEOUT_SECONDS=601"}, ErrInvalidValue},
		{"blank-bootstrap-name", API, false, []string{"EVYDENCE_BOOTSTRAP_TENANT=  "}, ErrInvalidValue},
		{"multiple-production-writers", API, true, []string{"EVYDENCE_API_WRITER_REPLICAS=2"}, ErrUnsafeProduction},
		{"development-production-pepper", API, true, []string{"EVYDENCE_API_KEY_PEPPER=local-dev-pepper-change-me"}, ErrUnsafeProduction},
		{"api-missing-port", API, false, []string{"EVYDENCE_ADDR=PRIVATE_HOST"}, ErrInvalidValue},
		{"api-service-port", API, false, []string{"EVYDENCE_ADDR=127.0.0.1:http"}, ErrInvalidValue},
		{"api-port-overflow", API, false, []string{"EVYDENCE_ADDR=:65536"}, ErrInvalidValue},
		{"api-host-whitespace", API, false, []string{"EVYDENCE_ADDR=PRIVATE HOST:8080"}, ErrInvalidValue},
		{"unpaired-revision", Worker, false, []string{"EVYDENCE_CONFIGURATION_REVISION=" + strings.Repeat("a", 64)}, ErrInvalidValue},
		{"unpaired-revision-file", API, false, []string{"EVYDENCE_CONFIGURATION_REVISION_FILE=/PRIVATE_NONEXISTENT/revision"}, ErrInvalidValue},
		{"invalid-revision", Worker, false, []string{"EVYDENCE_CONFIGURATION_REVISION=" + strings.Repeat("A", 64), "EVYDENCE_CONFIGURATION_REVISION_FILE=/PRIVATE_NONEXISTENT/revision"}, ErrInvalidValue},
		{"relative-revision-file", Worker, false, []string{"EVYDENCE_CONFIGURATION_REVISION=" + strings.Repeat("a", 64), "EVYDENCE_CONFIGURATION_REVISION_FILE=PRIVATE_RELATIVE/revision"}, ErrInvalidValue},
		{"public-worker-health", Worker, false, []string{"EVYDENCE_WORKER_HEALTH_ADDR=192.0.2.1:8081"}, ErrInvalidValue},
		{"wildcard-worker-health", Worker, false, []string{"EVYDENCE_WORKER_HEALTH_ADDR=0.0.0.0:8081"}, ErrInvalidValue},
		{"hostname-worker-health", Worker, false, []string{"EVYDENCE_WORKER_HEALTH_ADDR=localhost:8081"}, ErrInvalidValue},
		{"zone-worker-health", Worker, false, []string{"EVYDENCE_WORKER_HEALTH_ADDR=[::1%lo]:8081"}, ErrInvalidValue},
		{"zero-worker-health-port", Worker, false, []string{"EVYDENCE_WORKER_HEALTH_ADDR=127.0.0.1:0"}, ErrInvalidValue},
		{"metrics-without-token", Worker, false, []string{"EVYDENCE_WORKER_METRICS_ADDR=127.0.0.1:9091"}, ErrInvalidValue},
		{"public-metrics", Worker, false, []string{"EVYDENCE_WORKER_METRICS_ADDR=192.0.2.1:9091", "EVYDENCE_WORKER_METRICS_TOKEN_FILE=/PRIVATE_NONEXISTENT/token"}, ErrInvalidValue},
		{"relative-metrics-file", Worker, false, []string{"EVYDENCE_WORKER_METRICS_TOKEN_FILE=PRIVATE_RELATIVE/token"}, ErrInvalidValue},
		{"padded-metrics-file", Worker, false, []string{"EVYDENCE_WORKER_METRICS_TOKEN_FILE=/PRIVATE_NONEXISTENT/token "}, ErrInvalidValue},
		{"padded-metrics-address", Worker, false, []string{"EVYDENCE_WORKER_METRICS_ADDR= 127.0.0.1:9091", "EVYDENCE_WORKER_METRICS_TOKEN_FILE=/PRIVATE_NONEXISTENT/token"}, ErrInvalidValue},
		{"metrics-health-collision", Worker, false, []string{"EVYDENCE_WORKER_METRICS_ADDR=127.0.0.1:8081", "EVYDENCE_WORKER_METRICS_TOKEN_FILE=/PRIVATE_NONEXISTENT/token"}, ErrInvalidValue},
		{"mapped-metrics-health-collision", Worker, false, []string{"EVYDENCE_WORKER_METRICS_ADDR=[::ffff:127.0.0.1]:8081", "EVYDENCE_WORKER_METRICS_TOKEN_FILE=/PRIVATE_NONEXISTENT/token"}, ErrInvalidValue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input, err := parseRoleInput(roleEnvironment(t, tc.role, tc.production, tc.extra...), tc.role)
			if !errors.Is(err, tc.want) || !reflect.DeepEqual(input, parsedInput{}) {
				t.Fatal("invalid local configuration returned usable or partial input", err)
			}
		})
	}
}

func TestProductionRejectsCurrentIdentityDevelopmentPepper(t *testing.T) {
	// Keep the transitional validator tied to the existing identity-owned
	// compatibility value without importing application code into configuration.
	file, err := parser.ParseFile(token.NewFileSet(), "../../identity/app/authentication_credentials.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var developmentPepper string
	ast.Inspect(file, func(node ast.Node) bool {
		declaration, ok := node.(*ast.ValueSpec)
		if !ok || len(declaration.Names) != 1 || declaration.Names[0].Name != "LocalDevelopmentPepper" || len(declaration.Values) != 1 {
			return true
		}
		literal, ok := declaration.Values[0].(*ast.BasicLit)
		if ok && literal.Kind == token.STRING {
			developmentPepper, err = strconv.Unquote(literal.Value)
		}
		return false
	})
	if err != nil || developmentPepper == "" {
		t.Fatal("identity compatibility value changed; reconcile configuration ownership", err)
	}
	if _, err := parseRoleInput(roleEnvironment(t, API, true, "EVYDENCE_API_KEY_PEPPER="+developmentPepper), API); !errors.Is(err, ErrUnsafeProduction) {
		t.Fatal("production accepted the current identity development default", err)
	}
}

func TestRoleInputAcceptsLocalConfigurationWithoutOpeningResources(t *testing.T) {
	for _, tc := range []struct {
		role  Role
		extra []string
	}{
		{API, []string{"EVYDENCE_ADDR=:0", "EVYDENCE_SSO_SESSION_MAX_LIFETIME_SECONDS=600", "EVYDENCE_SSO_SESSION_IDLE_TIMEOUT_SECONDS=600", "EVYDENCE_BOOTSTRAP_TENANT=  Tenant  "}},
		{API, []string{"EVYDENCE_ADDR=PRIVATE_HOST:8080"}},
		{API, []string{"EVYDENCE_CONFIGURATION_REVISION=" + strings.Repeat("a", 64), "EVYDENCE_CONFIGURATION_REVISION_FILE=/PRIVATE_NONEXISTENT/revision"}},
		{Worker, []string{"EVYDENCE_WORKER_HEALTH_ADDR=[::1]:8081", "EVYDENCE_WORKER_METRICS_ADDR=[fd00::1]:9091", "EVYDENCE_WORKER_METRICS_TOKEN_FILE=/PRIVATE_NONEXISTENT/token"}},
		{Worker, []string{"EVYDENCE_WORKER_HEALTH_ADDR=127.0.0.2:8081", "EVYDENCE_WORKER_METRICS_ADDR=127.0.0.1:8081", "EVYDENCE_WORKER_METRICS_TOKEN_FILE=/PRIVATE_NONEXISTENT/token"}},
		{Worker, nil},
		{Migrate, nil},
		{CLI, nil},
	} {
		if _, err := parseRoleInput(roleEnvironment(t, tc.role, false, tc.extra...), tc.role); err != nil {
			t.Fatal("local validation opened a resource or rejected a valid value", err)
		}
	}
}
