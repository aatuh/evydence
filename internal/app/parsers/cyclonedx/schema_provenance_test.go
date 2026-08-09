package cyclonedx

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

func TestVendoredSchemaResourcesMatchPinnedUpstreamGitObjects(t *testing.T) {
	for name, want := range map[string]string{
		"schema/spdx.schema.json":     "2dccc87e3cb3c3438d3f1623a3483657ee8d4189",
		"schema/jsf-0.82.schema.json": "f46bfb1e52731ad1280123ff3e2bd29bd18d4bc2",
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if got := gitBlobSHA(raw); got != want {
				t.Fatalf("%s git blob=%s want=%s", name, got, want)
			}
		})
	}
}

func gitBlobSHA(raw []byte) string {
	h := sha1.New()
	_, _ = fmt.Fprintf(h, "blob %d%c", len(raw), byte(0))
	_, _ = h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}
