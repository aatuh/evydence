package postgres

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func TestReleaseBundleManifestDecodePreservesExactNumbers(t *testing.T) {
	raw := []byte(`{"decimal":0.12345678901234567890123456789,"integer":9007199254740993,"nested":[18446744073709551615,{"negative":-9007199254740993}]}`)
	manifest, err := decodeReleaseBundleManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(encoded, raw) {
		t.Fatal("release-bundle point decoding rounded signed manifest numbers", string(encoded), err)
	}
	if manifest["integer"] != json.Number("9007199254740993") {
		t.Fatal("release-bundle manifest converted exact numbers to floating point")
	}
}

func TestReleaseBundleManifestDecodeRejectsInvalidShapeWithoutPartialData(t *testing.T) {
	for _, raw := range []string{"", "null", "[]", `"text"`, `{"secret":"private","broken":`, `{"first":1} {"second":2}`} {
		manifest, err := decodeReleaseBundleManifest([]byte(raw))
		if !errors.Is(err, packagequery.ErrReleaseBundleProjection) || manifest != nil {
			t.Fatal("invalid manifest returned partial data or private parse details", err)
		}
	}
	manifest, err := decodeReleaseBundleManifest([]byte(`{}`))
	if err != nil || manifest == nil || len(manifest) != 0 {
		t.Fatal("valid empty manifest rejected", err)
	}
}
