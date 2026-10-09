package httpapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestProductSlugLimitCountsTrimmedUTF8Bytes(t *testing.T) {
	server, secret := testServer(t)
	for i, tc := range []struct {
		slug   string
		status int
	}{{" " + strings.Repeat("x", 1024) + " ", 201}, {strings.Repeat("界", 341) + "x", 201}, {strings.Repeat("x", 1025), 400}, {strings.Repeat("界", 342), 400}} {
		body, err := json.Marshal(map[string]string{"name": "Bounded product", "slug": tc.slug})
		if err != nil {
			t.Fatal(err)
		}
		response := postRaw(t, server, secret, "/v1/products", fmt.Sprintf("slug-limit-%d", i), body, tc.status)
		if tc.status == 201 && dataField(t, response, "slug") != strings.TrimSpace(tc.slug) {
			t.Fatal("slug truncation or trimming changed", response)
		}
		if tc.status == 400 && !strings.Contains(response, `"code":"VALIDATION_FAILED"`) {
			t.Fatal("oversized slug did not produce safe validation error", response)
		}
	}
}
