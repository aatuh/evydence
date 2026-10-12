package app

import "encoding/json"

func validIngestionMetadata(metadata map[string]any, limitations []string) bool {
	encoded, err := json.Marshal(metadata)
	if err != nil || int64(len(encoded)) > EvidenceDocumentLimit {
		return false
	}
	for _, value := range limitations {
		if !validDiffText(value, int(EvidenceDocumentLimit), false) {
			return false
		}
	}
	return true
}
