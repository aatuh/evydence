package config

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestProjectPathSchemaHasExplicitBounds(t *testing.T) {
	for _, d := range Definitions() {
		if d.Kind == Path && (d.MaxBytes <= 0 || d.MaxBytes > 4096) {
			t.Fatal("project path lacks an explicit filesystem input bound", d.Name)
		}
	}
}

func TestProjectPathScalarRejectsControlsAndBlankWithoutDisclosure(t *testing.T) {
	for _, d := range Definitions() {
		if d.Kind != Path {
			continue
		}
		for _, raw := range []string{"  ", "/PRIVATE/file\n", "/PRIVATE/\tfile", "/PRIVATE/\x7ffile", "/PRIVATE/\u0085file", strings.Repeat("x", 4097)} {
			value, err := parseScalar(d, raw)
			if !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(value, scalarValue{}) || strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
				t.Fatal("invalid project path returned partial data or unsafe diagnostics", d.Name, err)
			}
		}
		for _, raw := range []string{"", "/PRIVATE_NONEXISTENT/file with spaces", "relative migration dir", strings.Repeat("x", 4096)} {
			value, err := parseScalar(d, raw)
			if err != nil || value.text != raw {
				t.Fatal("path grammar accessed files or changed supported path bytes", d.Name, err)
			}
		}
	}
}

func TestRoleInputRejectsPathControlsBeforeExternalResolution(t *testing.T) {
	for _, role := range []Role{API, Worker, Migrate} {
		for _, entry := range []string{"EVYDENCE_MIGRATIONS_DIR=/PRIVATE_NONEXISTENT/\nfile", "EVYDENCE_MIGRATIONS_DIR=" + strings.Repeat("x", 4097)} {
			input, err := parseRoleInput(roleEnvironment(t, role, false, entry), role)
			if !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(input, parsedInput{}) || strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
				t.Fatal("role preflight admitted an invalid migration path", role, err)
			}
		}
	}
	if _, err := parseRoleInput(roleEnvironment(t, CLI, false, "EVYDENCE_MIGRATIONS_DIR=/PRIVATE_UNUSED/\nfile"), CLI); err != nil {
		t.Fatal("offline CLI acquired another role's filesystem dependency", err)
	}
}
