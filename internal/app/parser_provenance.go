package app

import (
	"sort"
	"strings"
)

// ParserProvenance is the stable metadata contract recorded for normalized
// evidence. Raw bytes remain immutable evidence; this describes only the
// parser's derived interpretation of them.
type ParserProvenance struct {
	Name             string   `json:"name"`
	Version          string   `json:"version"`
	SourceSchema     string   `json:"source_schema"`
	NormalizedSchema string   `json:"normalized_schema"`
	Warnings         []string `json:"warnings"`
	ReplayStatus     string   `json:"replay_status"`
}

const ParserReplayStatusOriginal = "original"
const ParserReplayStatusReplayed = "replayed"

func (p ParserProvenance) Valid() bool {
	if strings.TrimSpace(p.Name) == "" || strings.TrimSpace(p.Version) == "" || strings.TrimSpace(p.SourceSchema) == "" || strings.TrimSpace(p.NormalizedSchema) == "" || (p.ReplayStatus != ParserReplayStatusOriginal && p.ReplayStatus != ParserReplayStatusReplayed) {
		return false
	}
	return true
}

func (p ParserProvenance) Metadata() map[string]any {
	warnings := append([]string(nil), p.Warnings...)
	sort.Strings(warnings)
	return map[string]any{"name": p.Name, "version": p.Version, "source_schema": p.SourceSchema, "normalized_schema": p.NormalizedSchema, "warnings": warnings, "replay_status": p.ReplayStatus}
}

// WithParserProvenance copies metadata before adding the standard parser
// record, preventing caller mutation from changing an immutable evidence row.
func WithParserProvenance(metadata map[string]any, provenance ParserProvenance) map[string]any {
	if !provenance.Valid() {
		return nil
	}
	result := make(map[string]any, len(metadata)+1)
	for key, value := range metadata {
		result[key] = value
	}
	result["parser"] = provenance.Metadata()
	return result
}
