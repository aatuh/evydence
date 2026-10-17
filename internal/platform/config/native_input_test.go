package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
)

// This mapping is the parseEnvSettings contract in pgx/v5 v5.9.2,
// pgconn/config.go. The corresponding source pin is recorded in the catalogue.
var expectedPostgresEnvironment = map[string]string{
	"PGHOST": "host", "PGPORT": "port", "PGDATABASE": "database", "PGUSER": "user",
	"PGPASSWORD": "password", "PGPASSFILE": "passfile", "PGAPPNAME": "application_name",
	"PGCONNECT_TIMEOUT": "connect_timeout", "PGSSLMODE": "sslmode", "PGSSLKEY": "sslkey",
	"PGSSLCERT": "sslcert", "PGSSLSNI": "sslsni", "PGSSLROOTCERT": "sslrootcert",
	"PGSSLPASSWORD": "sslpassword", "PGSSLNEGOTIATION": "sslnegotiation",
	"PGTARGETSESSIONATTRS": "target_session_attrs", "PGSERVICE": "service",
	"PGSERVICEFILE": "servicefile", "PGTZ": "timezone", "PGOPTIONS": "options",
	"PGMINPROTOCOLVERSION": "min_protocol_version", "PGMAXPROTOCOLVERSION": "max_protocol_version",
}

func TestNativePostgresSchemaPreservesDriverBoundary(t *testing.T) {
	seen := make(map[string]string)
	definitions := NativeDefinitions()
	for _, d := range definitions {
		if d.Boundary != NativePostgres {
			continue
		}
		if d.Source != "github.com/jackc/pgx/v5@v5.9.2/pgconn/config.go:parseEnvSettings" || d.Roles != API|Worker|Migrate|WorkerReplay|WorkerReconcile || d.Required != 0 || d.ProductionRequired != 0 || d.Default != "" || d.DefaultPolicy == "" || d.Description == "" || d.MaxBytes <= 0 {
			t.Fatal("native input acquired invented requirements/defaults or lost its source", d.Name)
		}
		if _, duplicate := seen[d.Name]; duplicate {
			t.Fatal("duplicate native input", d.Name)
		}
		seen[d.Name] = d.Parameter
		if d.Secret != (d.Name == "PGPASSWORD" || d.Name == "PGSSLPASSWORD") {
			t.Fatal("native credential classification is incorrect", d.Name)
		}
		if !selectedEnvironmentName(d.Name) {
			t.Fatal("declared native input is omitted from capture", d.Name)
		}
	}
	if !reflect.DeepEqual(seen, expectedPostgresEnvironment) {
		t.Fatal("native schema differs from the pinned driver environment contract")
	}
}

func TestNativePostgresSchemaUsesPinnedSourceAndExplicitBounds(t *testing.T) {
	data, err := os.ReadFile("../../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	module, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		t.Fatal(err)
	}
	pin := ""
	for _, dependency := range module.Require {
		if dependency.Mod.Path == "github.com/jackc/pgx/v5" {
			pin = dependency.Mod.Path + "@" + dependency.Mod.Version + "/"
		}
	}
	if pin == "" {
		t.Fatal("native driver dependency is absent")
	}
	defs := make(map[string]NativeDefinition)
	for _, d := range NativeDefinitions() {
		if d.Boundary == NativePostgres {
			if !strings.HasPrefix(d.Source, pin) {
				t.Fatal("native source inventory is stale against the pinned driver")
			}
			defs[d.Name] = d
		}
	}
	for _, name := range []string{"PGPASSFILE", "PGSSLKEY", "PGSSLCERT", "PGSSLROOTCERT", "PGSERVICEFILE"} {
		if defs[name].Kind != Path || defs[name].MaxBytes != 4096 {
			t.Fatal("native file reference lacks its explicit path bound", name)
		}
	}
	if defs["PGCONNECT_TIMEOUT"].Kind != Seconds || defs["PGCONNECT_TIMEOUT"].Min != 0 || defs["PGCONNECT_TIMEOUT"].Max <= 0 || defs["PGHOST"].MaxItems != 16 || defs["PGPORT"].MaxItems != 16 {
		t.Fatal("native timeout or multi-host bounds are missing")
	}
	if defs["PGSSLMODE"].Kind != Choice || !slices.Contains(defs["PGSSLMODE"].Allowed, "verify-full") || slices.Contains(defs["PGSSLMODE"].Allowed, "VERIFY-FULL") {
		t.Fatal("native TLS mode grammar was weakened")
	}
}

func TestCaptureOwnsDeclaredPostgresInputsWithoutReadingAmbient(t *testing.T) {
	t.Setenv("PGPASSWORD", "PRIVATE_AMBIENT_PASSWORD")
	entries := []string{"PGUNRELATED=PRIVATE_UNRELATED", "EDITOR=PRIVATE_UNRELATED_EDITOR"}
	for name := range expectedPostgresEnvironment {
		entries = append(entries, name+"= PRIVATE_"+name+" ")
	}
	e, err := Capture(entries)
	if err != nil {
		t.Fatal(err)
	}
	for name := range expectedPostgresEnvironment {
		if value, ok := e.lookup(name); !ok || value != " PRIVATE_"+name+" " {
			t.Fatal("native input was dropped, changed or read from the ambient process", name)
		}
	}
	for _, name := range []string{"PGUNRELATED", "EDITOR"} {
		if _, ok := e.lookup(name); ok {
			t.Fatal("capture broadened to undeclared host inputs", name)
		}
	}
	for _, value := range []any{e, &e, struct{ Environment Environment }{e}} {
		encoded, err := json.Marshal(value)
		if err != nil || strings.Contains(string(encoded), "PRIVATE") || strings.Contains(fmt.Sprintf("%v %#v", value, value), "PRIVATE") {
			t.Fatal("native inputs leaked through formatting or JSON", err)
		}
	}
	first, err := Capture([]string{"PGPASSWORD=PRIVATE_FIRST"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Capture([]string{"PGPASSWORD=PRIVATE_SECOND"})
	if err != nil || first.fingerprint == second.fingerprint {
		t.Fatal("native credential changes did not change the owned fingerprint", err)
	}
}

func TestCaptureRejectsMalformedNativeInputsAtomically(t *testing.T) {
	for _, entries := range [][]string{
		{"PGPASSWORD=PRIVATE_FIRST", "PGPASSWORD=PRIVATE_SECOND"},
		{"PGPASSWORD"},
		{"PGPASSWORD=PRIVATE\x00PASSWORD"},
		{"PGPASSWORD=PRIVATE" + string([]byte{255})},
	} {
		e, err := Capture(entries)
		if !errors.Is(err, ErrInvalidEnvironment) || !reflect.DeepEqual(e, Environment{}) || strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
			t.Fatal("invalid native input returned partial configuration or unsafe diagnostics", err)
		}
	}
}

func TestNativeSchemaMetadataIsSortedAndOwned(t *testing.T) {
	first := NativeDefinitions()
	if len(first) == 0 || !slices.IsSortedFunc(first, func(a, b NativeDefinition) int { return strings.Compare(a.Name, b.Name) }) {
		t.Fatal("native schema order is unstable")
	}
	for i := range first {
		first[i].Name = "PRIVATE_MUTATION"
		first[i].Parameter = "PRIVATE_PARAMETER"
		for j := range first[i].Allowed {
			first[i].Allowed[j] = "PRIVATE_ALLOWED"
		}
	}
	for _, d := range NativeDefinitions() {
		if strings.Contains(d.Name, "PRIVATE") || strings.Contains(d.Parameter, "PRIVATE") || slices.Contains(d.Allowed, "PRIVATE_ALLOWED") {
			t.Fatal("caller changed shared native schema metadata")
		}
	}
}
