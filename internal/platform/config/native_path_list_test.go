package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestNativePathListsMatchHostStandardLibrary(t *testing.T) {
	for _, name := range []string{"PATH", "SSL_CERT_DIR"} {
		for _, raw := range []string{"", ";", ":", `C:\PRIVATE;D:\PRIVATE`, `"C:\PRIVATE;roots";D:\PRIVATE`, `/PRIVATE/one:/PRIVATE/two`, `"/PRIVATE/one:/PRIVATE/two"`} {
			got, err := parseNativeValue(nativeDefinitionByName(t, name), raw)
			if err != nil || got.raw != raw || !slices.Equal(got.items, filepath.SplitList(raw)) {
				t.Fatal("native path-list projection diverged from host filepath.SplitList", name, os.PathListSeparator, err)
			}
		}
	}
}

func TestNativePathListsUseTargetPlatformGrammar(t *testing.T) {
	for _, name := range []string{"PATH", "SSL_CERT_DIR"} {
		for _, tc := range []struct {
			name, raw string
			separator byte
			want      []string
		}{
			{"unix", "/PRIVATE/one:/PRIVATE/two::/PRIVATE;literal", ':', []string{"/PRIVATE/one", "/PRIVATE/two", "", "/PRIVATE;literal"}},
			{"unix-quotes-are-literal", `"/PRIVATE/one:/PRIVATE/two"`, ':', []string{`"/PRIVATE/one`, `/PRIVATE/two"`}},
			{"windows-drives", `C:\PRIVATE roots;D:\PRIVATE roots;;\\PRIVATE\share`, ';', []string{`C:\PRIVATE roots`, `D:\PRIVATE roots`, "", `\\PRIVATE\share`}},
			{"windows-quoted-separator", `"C:\PRIVATE;roots";D:\PRIVATE roots`, ';', []string{`C:\PRIVATE;roots`, `D:\PRIVATE roots`}},
			{"windows-partial-quotes", `C:\"PRIVATE;roots";D:\PRIVATE`, ';', []string{`C:\PRIVATE;roots`, `D:\PRIVATE`}},
			{"windows-unclosed-quote", `"C:\PRIVATE;roots;D:\PRIVATE`, ';', []string{`C:\PRIVATE;roots;D:\PRIVATE`}},
			{"windows-empty-entries", `;"";;`, ';', []string{"", "", "", ""}},
		} {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				value, err := parseNativeValueWithPathListSeparator(nativeDefinitionByName(t, name), tc.raw, tc.separator)
				if err != nil || value.raw != tc.raw || !slices.Equal(value.items, tc.want) {
					t.Fatal("native path-list bytes or target-platform items changed", err)
				}
				data, err := json.Marshal(value)
				if err != nil || strings.Contains(string(data), "PRIVATE") || strings.Contains(fmt.Sprintf("%v %#v", value, value), "PRIVATE") {
					t.Fatal("native path-list diagnostics disclosed input", err)
				}
			})
		}
	}
}

func TestNativePathListsRetainBoundsBeforeDecodingQuotes(t *testing.T) {
	for _, name := range []string{"PATH", "SSL_CERT_DIR"} {
		d := nativeDefinitionByName(t, name)
		for _, raw := range []string{
			strings.Repeat(`C:\PRIVATE;`, maxNativeListItems) + `D:\PRIVATE`,
			`"` + strings.Repeat(";", 4096) + `"`,
			strings.Repeat(`"`, 4097),
			`C:\PRIVATE;" "`,
			"C:\\PRIVATE;D:\\PRIVATE\nDIR",
		} {
			value, err := parseNativeValueWithPathListSeparator(d, raw, ';')
			if !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(value, nativeValue{}) || strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
				t.Fatal("invalid native path list returned partial output or unsafe diagnostics", name, err)
			}
		}
		quoted := `"C:\PRIVATE` + strings.Repeat(";", 300) + `roots";D:\PRIVATE`
		value, err := parseNativeValueWithPathListSeparator(d, quoted, ';')
		if err != nil || !slices.Equal(value.items, []string{`C:\PRIVATE` + strings.Repeat(";", 300) + `roots`, `D:\PRIVATE`}) {
			t.Fatal("quoted separators consumed the native item budget", name, err)
		}
		limit := strings.Repeat(`C:\PRIVATE;`, maxNativeListItems-1) + `D:\PRIVATE`
		value, err = parseNativeValueWithPathListSeparator(d, limit, ';')
		if err != nil || len(value.items) != maxNativeListItems {
			t.Fatal("maximum native path item count was rejected", name, err)
		}
		limit = `"` + strings.Repeat("x", 4094) + `"`
		value, err = parseNativeValueWithPathListSeparator(d, limit, ';')
		if err != nil || !slices.Equal(value.items, []string{strings.Repeat("x", 4094)}) {
			t.Fatal("maximum raw native path item size was rejected", name, err)
		}
	}
}
