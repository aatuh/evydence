package app

import (
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	"github.com/aatuh/evydence/internal/platform/redaction"
)

// SanitizeReleaseBundleManifest removes private fields and sensitive text
// before hashing/signing. Only the versioned retention fact's boolean presence
// flag is preserved; an actual object key is never part of this projection.
func SanitizeReleaseBundleManifest(manifest map[string]any) (map[string]any, error) {
	if manifest["manifest_version"] != packagedomain.ReleaseBundleSchemaVersion {
		return nil, ErrConflict
	}
	base := cloneBundleMap(manifest)
	proofs := base["object_lock_proofs"]
	delete(base, "object_lock_proofs")
	safe, _ := redaction.RemoveSensitive(base)
	result := safe.(map[string]any)
	switch values := proofs.(type) {
	case nil:
		result["object_lock_proofs"] = nil
	case []map[string]any:
		if len(values) > MaxBundleSnapshotRows {
			return nil, ErrConflict
		}
		var projected []map[string]any
		if values != nil {
			projected = make([]map[string]any, len(values))
		}
		for i, proof := range values {
			v, err := sanitizeReleaseRetentionProof(proof)
			if err != nil {
				return nil, err
			}
			projected[i] = v
		}
		result["object_lock_proofs"] = projected
	case []any:
		if len(values) > MaxBundleSnapshotRows {
			return nil, ErrConflict
		}
		var projected []any
		if values != nil {
			projected = make([]any, len(values))
		}
		for i, value := range values {
			if value == nil {
				continue
			}
			proof, ok := value.(map[string]any)
			if !ok {
				return nil, ErrConflict
			}
			v, err := sanitizeReleaseRetentionProof(proof)
			if err != nil {
				return nil, err
			}
			projected[i] = v
		}
		result["object_lock_proofs"] = projected
	default:
		return nil, ErrConflict
	}
	return result, nil
}

func sanitizeReleaseRetentionProof(proof map[string]any) (map[string]any, error) {
	flag, present := proof["sample_object_key_configured"]
	if present {
		_, boolean := flag.(bool)
		_, prefix := proof["object_prefix_configured"].(bool)
		id, _ := proof["id"].(string)
		if !boolean || !prefix || !graphID(id) {
			return nil, ErrConflict
		}
	}
	safe, _ := redaction.RemoveSensitive(proof)
	result := safe.(map[string]any)
	if present {
		result["sample_object_key_configured"] = flag
	}
	return result, nil
}
