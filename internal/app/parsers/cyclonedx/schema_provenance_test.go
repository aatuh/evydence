package cyclonedx

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

func TestVendoredJSFSchemaMatchesPinnedUpstreamGitObject(t *testing.T) {
	raw, err := os.ReadFile("schema/jsf-0.82.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	const want = "f46bfb1e52731ad1280123ff3e2bd29bd18d4bc2"
	if got := gitBlobSHA(raw); got != want {
		t.Fatalf("jsf schema git blob=%s want=%s", got, want)
	}
}

func gitBlobSHA(raw []byte) string {
	h := sha1.New()
	_, _ = fmt.Fprintf(h, "blob %d%c", len(raw), byte(0))
	_, _ = h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}
