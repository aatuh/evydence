package config

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestWindowsCaptureCanonicalizesCaseWithoutChangingValues(t *testing.T) {
	entries := []string{"env=production", "evydence_api_key= PRIVATE_KEY ", "Path=C:\\PRIVATE_BIN", "http_proxy=", "aws_default_region=eu-test-1", "nodefaultcurrentdirectoryinexepath="}
	e, err := captureEntries(entries, true)
	if err != nil {
		t.Fatal("Windows input capture failed", err)
	}
	for name, want := range map[string]string{"ENV": "production", "EVYDENCE_API_KEY": " PRIVATE_KEY ", "PATH": "C:\\PRIVATE_BIN", "HTTP_PROXY": "", "AWS_DEFAULT_REGION": "eu-test-1", "NoDefaultCurrentDirectoryInExePath": ""} {
		if got, ok := e.lookup(name); !ok || got != want {
			t.Fatal("Windows name canonicalization changed bytes or presence", name)
		}
	}
	canonical, err := captureEntries([]string{"ENV=production", "EVYDENCE_API_KEY= PRIVATE_KEY ", "PATH=C:\\PRIVATE_BIN", "HTTP_PROXY=", "AWS_DEFAULT_REGION=eu-test-1", "NoDefaultCurrentDirectoryInExePath="}, true)
	if err != nil || e.fingerprint != canonical.fingerprint {
		t.Fatal("case-only changes altered effective Windows input")
	}
	linux, err := captureEntries([]string{"Path=/PRIVATE_IGNORED", "env=production", "HTTP_PROXY=first", "http_proxy=second"}, false)
	if err != nil || len(linux.values) != 2 {
		t.Fatal("Windows case policy leaked into case-sensitive capture", err)
	}
}

func TestWindowsCaptureRejectsCaseCollisionsWithoutPartialInput(t *testing.T) {
	for _, entries := range [][]string{{"Path=PRIVATE_FIRST", "PATH=PRIVATE_SECOND"}, {"EVYDENCE_API_KEY=PRIVATE_FIRST", "evydence_api_key=PRIVATE_SECOND"}, {"HTTP_PROXY=", "http_proxy=PRIVATE_SECOND"}} {
		e, err := captureEntries(entries, true)
		if !errors.Is(err, ErrInvalidEnvironment) || !reflect.DeepEqual(e, Environment{}) || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("ambiguous Windows input returned partial state or an unsafe diagnostic", err)
		}
	}
}

func TestWindowsExecutableLookupInputsAreBoundedTypedAndPresenceAware(t *testing.T) {
	cfg := typedConfiguration(t, API, "PATHEXT=EXE;.CMD;;.tar.gz", "NoDefaultCurrentDirectoryInExePath=")
	host := cfg.Native().Host()
	if !slices.Equal(host.PathExtensions.Value(), []string{".exe", ".cmd", ".tar.gz"}) || !host.NoDefaultCurrentDirectoryInExePath.Present() || host.NoDefaultCurrentDirectoryInExePath.HasValue() {
		t.Fatal("Windows native lookup semantics changed")
	}
	extensions := host.PathExtensions.Value()
	extensions[0] = ".PRIVATE_MUTATION"
	if host.PathExtensions.Value()[0] != ".exe" {
		t.Fatal("Windows extension list shares caller-owned state")
	}
	for _, raw := range []string{`.exe;..\PRIVATE.exe`, `.exe;C:PRIVATE`, ".exe; \tPRIVATE", strings.Repeat(".exe;", 256) + ".cmd", "."} {
		if _, err := parseRoleInput(roleEnvironment(t, API, false, "PATHEXT="+raw), API); !errors.Is(err, ErrInvalidValue) {
			t.Fatal("invalid Windows lookup extension was admitted", err)
		}
	}
	for _, raw := range []string{"", ";;"} {
		cfg := typedConfiguration(t, API, "PATHEXT="+raw)
		if !cfg.Native().Host().PathExtensions.Present() || cfg.Native().Host().PathExtensions.HasValue() != (raw != "") || len(cfg.Native().Host().PathExtensions.Value()) != 0 {
			t.Fatal("native defaults were applied during pure projection")
		}
	}
}
