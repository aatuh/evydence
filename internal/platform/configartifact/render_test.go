package configartifact

import (
	"bytes"
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/platform/config"
)

var ownedPaths = []string{
	".production.env.example",
	"docs/reference/configuration.md",
	"docs/kubernetes.md",
}

func TestRenderPropagatesSchemaChangesToEveryOwnedArtifact(t *testing.T) {
	definitions := []config.Definition{{
		Name: "EVYDENCE_SAMPLE_SECONDS", Kind: config.Seconds,
		Roles: config.API | config.Worker, Default: "11", Min: 1, Max: 30,
		Description: "Original setting description.",
	}}
	first, err := Render(definitions, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(first[ownedPaths[0]], []byte("EVYDENCE_SAMPLE_SECONDS=11\n")) {
		t.Fatal("environment example lost its schema default")
	}
	definitions[0].Default = "23"
	definitions[0].Max = 90
	definitions[0].Description = "Changed setting description."
	changed, err := Render(definitions, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(changed[ownedPaths[0]], []byte("EVYDENCE_SAMPLE_SECONDS=23\n")) {
		t.Fatal("schema default change did not reach the environment example")
	}
	for _, path := range ownedPaths {
		if bytes.Equal(first[path], changed[path]) || !bytes.Contains(changed[path], []byte("Changed setting description.")) || !bytes.Contains(changed[path], []byte("1..90")) {
			t.Fatalf("schema description or bounds drifted in %s", path)
		}
	}
}

func TestRenderIsDeterministicAndDoesNotMutateSchema(t *testing.T) {
	definitions := []config.Definition{
		{Name: "EVYDENCE_ZULU", Kind: config.Text, Roles: config.API, Default: "last", Description: "Last setting."},
		{Name: "EVYDENCE_ALPHA", Kind: config.Boolean, Roles: config.Worker, Default: "false", Description: "First setting."},
	}
	before, err := json.Marshal(definitions)
	if err != nil {
		t.Fatal(err)
	}
	first, err := Render(definitions, nil)
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(definitions)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("renderer mutated caller-owned schema metadata")
	}
	second, err := Render([]config.Definition{definitions[1], definitions[0]}, nil)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatal("artifact output depends on input order")
	}
	for _, path := range ownedPaths {
		body := first[path]
		alpha := bytes.Index(body, []byte("EVYDENCE_ALPHA"))
		zulu := bytes.Index(body, []byte("EVYDENCE_ZULU"))
		if alpha < 0 || zulu < 0 || alpha >= zulu {
			t.Fatalf("missing or unstable generated settings in %s", path)
		}
	}
}

func TestRenderUsesOnlyMetadataAndKeepsSecretsEmpty(t *testing.T) {
	t.Setenv("ENV", "PRIVATE_ENVIRONMENT_CANARY")
	t.Setenv("EVYDENCE_DATABASE_URL", "PRIVATE_DATABASE_CANARY")
	t.Setenv("EVYDENCE_API_KEY_PEPPER", "PRIVATE_PEPPER_CANARY")
	t.Setenv("PGPASSWORD", "PRIVATE_NATIVE_CANARY")
	definitions := []config.Definition{{
		Name: "EVYDENCE_DATABASE_URL", Kind: config.PostgresDSN,
		Roles:  config.API | config.Worker | config.Migrate,
		Secret: true, FileOption: "EVYDENCE_DATABASE_URL_FILE",
		Description: "Durable database connection.",
	}}
	native := []config.NativeDefinition{{
		Definition: config.Definition{Name: "PGPASSWORD", Kind: config.Text, Roles: config.API, Secret: true, Description: "Native credential input."},
		Boundary:   config.NativePostgres, Parameter: "password", Source: "pinned-driver/config.go",
	}}
	artifacts, err := Render(definitions, native)
	if err != nil {
		t.Fatal(err)
	}
	environment := artifacts[ownedPaths[0]]
	if !bytes.Contains(environment, []byte("EVYDENCE_DATABASE_URL=\n")) || bytes.Contains(environment, []byte("\nPGPASSWORD=")) {
		t.Fatal("example lost its empty project secret or activated native credentials")
	}
	for path, body := range artifacts {
		if bytes.Contains(body, []byte("PRIVATE_")) || !bytes.Contains(body, []byte("EVYDENCE_DATABASE_URL_FILE")) {
			t.Fatalf("ambient secret leaked or project file alternative disappeared in %s", path)
		}
	}
	for _, path := range ownedPaths[1:] {
		if !bytes.Contains(artifacts[path], []byte("PGPASSWORD")) || !bytes.Contains(artifacts[path], []byte("pinned-driver/config.go")) {
			t.Fatalf("native input lost its declared resolution owner in %s", path)
		}
	}
}

func TestRenderRejectsSecretDefaultsWithoutPublishingThem(t *testing.T) {
	for _, field := range []string{"default", "production", "nonproduction", "conditional", "example"} {
		t.Run(field, func(t *testing.T) {
			d := config.Definition{Name: "EVYDENCE_SECRET", Kind: config.Text, Roles: config.API, Secret: true, Description: "Secret input."}
			switch field {
			case "default":
				d.Default = "PRIVATE_SCHEMA_SECRET"
			case "production":
				d.ProductionDefault = "PRIVATE_SCHEMA_SECRET"
			case "nonproduction":
				d.NonProductionDefault = "PRIVATE_SCHEMA_SECRET"
			case "conditional":
				d.ConditionalDefault = "PRIVATE_SCHEMA_SECRET"
			case "example":
				d.ProductionExample = "PRIVATE_SCHEMA_SECRET"
			}
			artifacts, err := Render([]config.Definition{d}, nil)
			if err == nil || len(artifacts) != 0 || strings.Contains(err.Error(), "PRIVATE_") {
				t.Fatal("unsafe schema secret reached an artifact or diagnostic")
			}
			d.Name = "PGPASSWORD"
			native := []config.NativeDefinition{{Definition: d, Boundary: config.NativePostgres, Source: "pinned-driver/config.go"}}
			artifacts, err = Render(nil, native)
			if err == nil || len(artifacts) != 0 || strings.Contains(err.Error(), "PRIVATE_") {
				t.Fatal("unsafe native schema secret reached an artifact or diagnostic")
			}
		})
	}
}

func TestRenderDistinguishesProductionSelectionsFromRuntimeDefaults(t *testing.T) {
	definitions := []config.Definition{{
		Name: "EVYDENCE_OBJECT_STORE", Kind: config.Choice, Roles: config.API | config.Worker,
		Default: "filesystem", ProductionExample: "s3", Allowed: []string{"filesystem", "s3", "minio"}, Description: "Object backend.",
	}}
	artifacts, err := Render(definitions, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(artifacts[ownedPaths[0]], []byte("EVYDENCE_OBJECT_STORE=s3\n")) {
		t.Fatal("production selection was replaced with the development default")
	}
	for _, path := range ownedPaths[1:] {
		body := artifacts[path]
		if !bytes.Contains(body, []byte("`filesystem`")) || !bytes.Contains(body, []byte("Production example: `s3`")) {
			t.Fatalf("production selection was presented as a runtime default in %s", path)
		}
	}
}

func TestRenderRejectsUnsafeActiveExampleValues(t *testing.T) {
	for _, value := range []string{"$(PRIVATE_COMMAND)", "`PRIVATE_COMMAND`", "line\nEVYDENCE_OTHER=value", "private\x00value"} {
		definitions := []config.Definition{{Name: "EVYDENCE_SAMPLE", Kind: config.Text, Roles: config.API, Default: value, Description: "Sample setting."}}
		artifacts, err := Render(definitions, nil)
		if err == nil || len(artifacts) != 0 || strings.Contains(err.Error(), "PRIVATE_") || strings.Contains(err.Error(), value) {
			t.Fatal("unsafe active example value reached output or diagnostics")
		}
	}
}

func TestRenderPreservesEnvironmentAndMarkdownFormats(t *testing.T) {
	definitions := []config.Definition{{
		Name: "EVYDENCE_SAMPLE", Kind: config.Integer, Roles: config.API,
		Default: "3", Min: 1, Max: 5, Description: "First | note.\nSecond note.",
	}}
	artifacts, err := Render(definitions, nil)
	if err != nil {
		t.Fatal(err)
	}
	assignment := regexp.MustCompile(`^[A-Z_][A-Z0-9_]*=`)
	for _, line := range strings.Split(string(artifacts[ownedPaths[0]]), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !assignment.MatchString(line) {
			t.Fatal("environment example contains non-configuration output")
		}
	}
	for _, path := range ownedPaths[1:] {
		body := string(artifacts[path])
		if !strings.Contains(body, "| Variable |") || !strings.Contains(body, "Default") || !strings.Contains(body, `First \| note. Second note.`) || strings.Contains(body, "\nSecond note.") {
			t.Fatalf("generated reference loses its table structure or setting description in %s", path)
		}
	}
}

func TestRenderCoversTheCurrentSchemaWithoutResolvingIt(t *testing.T) {
	definitions, native := config.Definitions(), config.NativeDefinitions()
	artifacts, err := Render(definitions, native)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range definitions {
		if !bytes.Contains(artifacts[ownedPaths[1]], []byte("`"+d.Name+"`")) {
			t.Fatal("canonical reference omits a declared setting", d.Name)
		}
	}
	for _, d := range native {
		if !bytes.Contains(artifacts[ownedPaths[1]], []byte("`"+d.Name+"`")) {
			t.Fatal("canonical reference omits a declared native input", d.Name)
		}
	}
	for _, line := range []string{"ENV=production\n", "EVYDENCE_RUNTIME_PROFILE=postgres\n", "EVYDENCE_OBJECT_STORE=s3\n", "EVYDENCE_S3_USE_SSL=true\n", "EVYDENCE_SIGNING_KEY_MODE=external\n", "EVYDENCE_DATABASE_URL=\n", "EVYDENCE_API_KEY_PEPPER=\n"} {
		if !bytes.Contains(artifacts[ownedPaths[0]], []byte(line)) {
			t.Fatal("production profile selection or empty secret is missing")
		}
	}
}

func TestRenderRebasesCanonicalDescriptionLinksForHelm(t *testing.T) {
	definitions := []config.Definition{{Name: "EVYDENCE_SAMPLE", Kind: config.Text, Roles: config.API, Description: "See [worker](observability.md#worker), [limits](#limits), and [provider](https://example.test/provider)."}}
	artifacts, err := Render(definitions, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range []string{"(reference/observability.md#worker)", "(reference/configuration.md#limits)", "(https://example.test/provider)"} {
		if !bytes.Contains(artifacts[ownedPaths[2]], []byte(link)) {
			t.Fatal("generated Helm description points outside its canonical documentation context")
		}
	}
	if !bytes.Contains(artifacts[ownedPaths[1]], []byte("(observability.md#worker)")) {
		t.Fatal("canonical reference link was unnecessarily rebased")
	}
}

func TestRenderPreservesLiteralDefaultAndSelectionBytes(t *testing.T) {
	for _, tc := range []struct {
		name, value, want string
		example           bool
	}{
		{"default-double-space", "double  gap", "`double  gap`", false},
		{"selection-double-space", "double  gap", "Production example: `double  gap`", true},
		{"default-edge-space", " edge ", "`\" edge \"`", false},
		{"selection-markdown-literal", "[literal](observability.md#value)", "Production example: `[literal](observability.md#value)`", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := config.Definition{Name: "EVYDENCE_SAMPLE", Kind: config.Text, Roles: config.API, Description: "A literal setting value."}
			if tc.example {
				d.ProductionExample = tc.value
			} else {
				d.Default = tc.value
			}
			artifacts, err := Render([]config.Definition{d}, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range ownedPaths[1:] {
				if !bytes.Contains(artifacts[path], []byte(tc.want)) {
					t.Fatalf("literal setting bytes changed in %s", path)
				}
			}
		})
	}
}
