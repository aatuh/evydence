package app

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	"github.com/aatuh/evydence/internal/platform/redaction"
)

// Restore public retention-presence flags only for an explicit creation DTO
// with an already-public, versioned manifest matching its exact commitment.
// Unknown root fields are projected away; generic redaction stays unchanged.
func publicSignedReleaseBundleReplay(value any) (map[string]any, bool) {
	root, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	manifest, ok := root["manifest"].(map[string]any)
	if !ok {
		return nil, false
	}
	public, err := packageapp.SanitizeReleaseBundleManifest(manifest)
	if err != nil || !reflect.DeepEqual(public, manifest) {
		return nil, false
	}
	encoded, err := json.Marshal(root)
	if err != nil {
		return nil, false
	}
	var bundle domain.ReleaseBundle
	if json.Unmarshal(encoded, &bundle) != nil || bundle.State != "generated" || bundle.CreatedAt.IsZero() || bundle.PublishedAt != nil || bundle.RevokedAt != nil || len(bundle.SignatureRefs) != 1 {
		return nil, false
	}
	for _, id := range []string{bundle.ID, bundle.TenantID, bundle.ReleaseID, bundle.SignatureRefs[0]} {
		if id == "" || !validPublicMembershipText(id, 1024) || strings.TrimSpace(id) != id || redaction.RedactString(id) != id {
			return nil, false
		}
	}
	release, ok := public["release"].(map[string]any)
	if !ok || release["id"] != bundle.ReleaseID || public["bundle_id"] != bundle.ID || public["tenant_id"] != bundle.TenantID || public["generated_at"] != bundle.CreatedAt.UTC().Format(time.RFC3339Nano) {
		return nil, false
	}
	hash, err := canonicalAnyHash(public)
	if err != nil || hash != bundle.ManifestHash {
		return nil, false
	}
	// Keep JSON numbers exact rather than retaining the float64 decode used
	// only to recognize the DTO's string/time fields above.
	bundle.Manifest = public
	encoded, err = json.Marshal(bundle)
	if err != nil {
		return nil, false
	}
	var projected map[string]any
	d := json.NewDecoder(bytes.NewReader(encoded))
	d.UseNumber()
	if d.Decode(&projected) != nil {
		return nil, false
	}
	return projected, true
}
