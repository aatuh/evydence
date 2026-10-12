package wiring

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestPostgresCatalogCreationNativeKeepsDistinctDuplicateSemantics(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSourceRepositoryNative(t, p)
	for _, c := range nativeCatalogCases() {
		one := catalogNativeHTTP(t, store, c, "first", c.body, 201)
		want := 409
		if c.kind == "project" {
			want = 201
		}
		two := catalogNativeHTTP(t, store, c, "second", c.body, want)
		if c.kind == "project" && one == two {
			t.Fatal("project name became a natural-key reuse")
		}
	}
	if got := catalogNativeCounts(t, p); got != [7]int{4, 5, 1, 4, 0, 4, 2} {
		t.Fatal("catalog duplicate semantics changed", got)
	}
}

func TestPostgresReleaseCreationUnsupportedIndexValueReturnsValidationNotServerFailure(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSourceRepositoryNative(t, p)
	var version strings.Builder
	for i := range 200 {
		fmt.Fprintf(&version, "%x", sha256.Sum256([]byte(fmt.Sprint(i))))
	}
	c := nativeCatalogCases()[2]
	body := `{"product_id":"product","version":"` + version.String() + `"}`
	catalogNativeHTTP(t, store, c, "index-limit", body, 400)
	if got := catalogNativeCounts(t, p); got[2] != 0 || got[3] != 0 || got[4] != 0 || got[5] != 0 {
		t.Fatal("unsupported indexed text wrote catalog effects", got)
	}
}
