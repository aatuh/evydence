package app

import "sort"

// CustomerPackageBuildOutput is the public output reference, not an artifact
// body or a statement that an attestation/signature has been verified.
type CustomerPackageBuildOutput struct{ ArtifactID, Digest string }

func CustomerPackageBuildOutputSummaries(values []CustomerPackageBuildOutput) []map[string]any {
	rows := make([]map[string]any, 0, len(values))
	for _, v := range values {
		rows = append(rows, map[string]any{"artifact_id": v.ArtifactID, "digest": v.Digest})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i]["artifact_id"].(string)+"\x00"+rows[i]["digest"].(string) < rows[j]["artifact_id"].(string)+"\x00"+rows[j]["digest"].(string)
	})
	return rows
}
