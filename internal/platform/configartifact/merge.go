package configartifact

import (
	"bytes"
	"errors"
	"unicode"
	"unicode/utf8"
)

// MaxArtifactBytes bounds both input documents and merged output. The filesystem
// adapter must apply the same limit before materializing an existing document.
const MaxArtifactBytes = 4 << 20

var errInvalidSection = errors.New("invalid generated configuration section")

// Merge replaces exactly one owned marker interior and preserves all outside
// bytes. Missing or ambiguous ownership fails without returning partial output.
func Merge(target string, original, generated []byte) ([]byte, error) {
	start, end, ok := sectionMarkers(target)
	if !ok || len(original) > MaxArtifactBytes || len(generated) == 0 || len(generated) > MaxArtifactBytes {
		return nil, errInvalidSection
	}
	if !artifactText(original) || !artifactText(generated) || bytes.Contains(generated, start) || bytes.Contains(generated, end) {
		return nil, errInvalidSection
	}
	_, contentStart, startOK := markerLine(original, start)
	contentEnd, _, endOK := markerLine(original, end)
	if !startOK || !endOK || contentStart > contentEnd {
		return nil, errInvalidSection
	}
	newlineBytes := 0
	if generated[len(generated)-1] != '\n' {
		newlineBytes = 1
	}
	size := contentStart + len(generated) + newlineBytes + len(original) - contentEnd
	if size > MaxArtifactBytes {
		return nil, errInvalidSection
	}
	result := make([]byte, 0, size)
	result = append(result, original[:contentStart]...)
	result = append(result, generated...)
	if newlineBytes != 0 {
		result = append(result, '\n')
	}
	result = append(result, original[contentEnd:]...)
	return result, nil
}

func sectionMarkers(target string) ([]byte, []byte, bool) {
	switch target {
	case ProductionEnvironmentPath:
		return []byte("# BEGIN EVYDENCE GENERATED CONFIGURATION"), []byte("# END EVYDENCE GENERATED CONFIGURATION"), true
	case ConfigurationReferencePath, HelmReferencePath:
		return []byte("<!-- BEGIN EVYDENCE GENERATED CONFIGURATION -->"), []byte("<!-- END EVYDENCE GENERATED CONFIGURATION -->"), true
	default:
		return nil, nil, false
	}
}

func markerLine(document, marker []byte) (int, int, bool) {
	if bytes.Count(document, marker) != 1 {
		return 0, 0, false
	}
	start := bytes.Index(document, marker)
	if start != 0 && document[start-1] != '\n' {
		return 0, 0, false
	}
	after := start + len(marker)
	if after == len(document) {
		return start, after, true
	}
	if document[after] == '\n' {
		return start, after + 1, true
	}
	if document[after] == '\r' && after+1 < len(document) && document[after+1] == '\n' {
		return start, after + 2, true
	}
	return 0, 0, false
}

func artifactText(body []byte) bool {
	if !utf8.Valid(body) {
		return false
	}
	for len(body) != 0 {
		r, size := utf8.DecodeRune(body)
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
		body = body[size:]
	}
	return true
}
