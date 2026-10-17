package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretReferenceSchemaDeclaresUnambiguousFileOptions(t *testing.T) {
	activation := map[string]SecretFileActivation{
		"EVYDENCE_API_KEY": SecretFileAlways, "EVYDENCE_API_KEY_PEPPER": SecretFileAlways, "EVYDENCE_DATABASE_URL": SecretFileAlways,
		"EVYDENCE_S3_ACCESS_KEY_ID": SecretFileObjectStore, "EVYDENCE_S3_SECRET_ACCESS_KEY": SecretFileObjectStore,
		"EVYDENCE_SIGNING_EXECUTOR_TOKEN": SecretFileSigningGateway, "EVYDENCE_PROVIDER_VALIDATION_GATEWAY_TOKEN": SecretFileProviderGateway, "EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_TOKEN": SecretFileTransparencyGateway,
	}
	known := map[string]bool{}
	for _, d := range Definitions() {
		known[d.Name] = true
		for _, alias := range d.Aliases {
			known[alias] = true
		}
	}
	count := 0
	for _, d := range Definitions() {
		if !d.Secret {
			if d.FileOption != "" || d.FileActivation != SecretFileAlways {
				t.Fatal("nonsecret option acquired implicit file resolution", d.Name)
			}
			continue
		}
		if d.FileOption != d.Name+"_FILE" || !validEnvironmentName(d.FileOption) || known[d.FileOption] {
			t.Fatal("secret file option is missing or collides with schema ownership", d.Name)
		}
		known[d.FileOption] = true
		if want, ok := activation[d.Name]; !ok || d.FileActivation != want {
			t.Fatal("secret file activation ownership needs explicit review", d.Name)
		}
		count++
	}
	if count != 8 {
		t.Fatal("review the explicit project-secret reference scope", count)
	}
}

func TestSecretReferencePlanIsPureOwnedAndRedacted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "PRIVATE_NONEXISTENT", "secret")
	entries := []string{"EVYDENCE_API_KEY_PEPPER=", "EVYDENCE_API_KEY_PEPPER_FILE=" + path, "EVYDENCE_S3_SECRET_ACCESS_KEY_FILE=" + path}
	e, err := Capture(entries)
	if err != nil {
		t.Fatal(err)
	}
	refs, err := parseSecretReferences(e, API)
	if err != nil || len(refs) != 2 || refs[0].target != "EVYDENCE_API_KEY_PEPPER" || refs[0].fileOption != "EVYDENCE_API_KEY_PEPPER_FILE" || refs[0].path != path || refs[0].maxBytes != maxEnvironmentBytes {
		t.Fatal("pure secret reference planning changed scope or attempted file resolution", err)
	}
	entries[1] = "EVYDENCE_API_KEY_PEPPER_FILE=PRIVATE_MUTATION"
	refs[0].path = "PRIVATE_CALLER_MUTATION"
	other, err := parseSecretReferences(e, API)
	if err != nil || other[0].path != path {
		t.Fatal("reference planning retained caller-owned state", err)
	}
	for _, value := range []any{other, other[0], &other[0]} {
		data, err := json.Marshal(value)
		if err != nil || strings.Contains(string(data), "PRIVATE") || strings.Contains(fmt.Sprintf("%v %#v", value, value), "PRIVATE") {
			t.Fatal("secret reference plan disclosed operator input", err)
		}
	}
	for _, d := range Definitions() {
		if d.FileOption != "" {
			d.FileOption = "PRIVATE_METADATA_MUTATION"
		}
	}
	if fresh, err := parseSecretReferences(e, API); err != nil || fresh[0].fileOption != "EVYDENCE_API_KEY_PEPPER_FILE" {
		t.Fatal("public schema metadata mutation changed reference planning", err)
	}
}

func TestSecretReferencePlanRejectsConflictsAndUnsupportedPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "PRIVATE_MISSING")
	for _, raw := range []string{"PRIVATE_VALUE", " "} {
		e, err := Capture([]string{"EVYDENCE_API_KEY_PEPPER=" + raw, "EVYDENCE_API_KEY_PEPPER_FILE=" + path})
		if err != nil {
			t.Fatal(err)
		}
		refs, err := parseSecretReferences(e, API)
		if !errors.Is(err, ErrConflictingSecretSources) || len(refs) != 0 || strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
			t.Fatal("conflicting inline/file sources returned references or leaked input", err)
		}
	}
	for _, path := range []string{"PRIVATE_RELATIVE", "file:///PRIVATE_SECRET", "https://PRIVATE_PROVIDER/secret", path + string(filepath.Separator), filepath.Dir(path) + string(filepath.Separator) + ".." + string(filepath.Separator) + "PRIVATE_SECRET", " " + path, path + "\n", string(filepath.Separator) + strings.Repeat("x", 4096)} {
		e, err := Capture([]string{"EVYDENCE_API_KEY_PEPPER_FILE=" + path})
		if err != nil {
			t.Fatal(err)
		}
		refs, err := parseSecretReferences(e, API)
		if !errors.Is(err, ErrInvalidSecretReference) || len(refs) != 0 || strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
			t.Fatal("unsupported secret reference returned a plan or unsafe diagnostics", err)
		}
	}
}

func TestSecretReferencePlanPreservesInactiveAndEmptySources(t *testing.T) {
	for _, tc := range []struct {
		role Role
		name string
	}{
		{Worker, "EVYDENCE_API_KEY_PEPPER_FILE"}, {Migrate, "EVYDENCE_S3_SECRET_ACCESS_KEY_FILE"}, {CLI, "EVYDENCE_DATABASE_URL_FILE"},
	} {
		e, err := Capture([]string{tc.name + "=PRIVATE_UNUSED_RELATIVE"})
		if err != nil {
			t.Fatal(err)
		}
		if refs, err := parseSecretReferences(e, tc.role); err != nil || len(refs) != 0 {
			t.Fatal("another role's file source imposed a dependency", err)
		}
	}
	e, err := Capture([]string{"EVYDENCE_API_KEY_PEPPER=PRIVATE_INLINE", "EVYDENCE_API_KEY_PEPPER_FILE="})
	if err != nil {
		t.Fatal(err)
	}
	if refs, err := parseSecretReferences(e, API); err != nil || len(refs) != 0 {
		t.Fatal("an unset file option conflicted with inline input", err)
	}
	if refs, err := parseSecretReferences(e, AllRoles); !errors.Is(err, ErrInvalidRole) || len(refs) != 0 {
		t.Fatal("reference planning accepted an ambiguous process role", err)
	}
}
