package app

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestBuildCreationRejectsUnsupportedTextAndMetadataBeforeReads(t *testing.T) {
	cycle := map[string]any{}
	cycle["self"] = cycle
	for _, tc := range []struct {
		name   string
		change func(*CreateBuildRunInput)
	}{
		{"provider NUL", func(in *CreateBuildRunInput) { in.Provider = "bad\x00provider" }},
		{"repository NUL", func(in *CreateBuildRunInput) { in.Repository = "bad\x00repository" }},
		{"invalid UTF8", func(in *CreateBuildRunInput) { in.WorkflowRef = string([]byte{255}) }},
		{"nested metadata NUL", func(in *CreateBuildRunInput) {
			in.ProviderMetadata = map[string]any{"nested": []any{map[string]any{"bad": "\x00"}}}
		}},
		{"metadata key NUL", func(in *CreateBuildRunInput) { in.ProviderMetadata = map[string]any{"\x00": true} }},
		{"cyclic metadata", func(in *CreateBuildRunInput) { in.ProviderMetadata = cycle }},
		{"non-finite metadata", func(in *CreateBuildRunInput) { in.ProviderMetadata = map[string]any{"bad": math.NaN()} }},
		{"unsupported metadata", func(in *CreateBuildRunInput) { in.ProviderMetadata = map[string]any{"bad": make(chan int)} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newServiceFixture(t)
			_, project, release := seedReleaseScope(t, f)
			in := CreateBuildRunInput{ProjectID: project.ID, ReleaseID: release.ID, Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40), Status: "passed", StartedAt: f.now}
			tc.change(&in)
			v, err := f.service.CreateBuildRun(t.Context(), f.actor, in)
			if !errors.Is(err, ErrValidation) || v.ID != "" || f.reader.calls != 0 || f.transactions.calls != 0 {
				t.Fatal("unsupported input reached dependencies", v.ID, err, f.reader.calls, f.transactions.calls)
			}
		})
	}
}

func TestBuildMetadataValidationPreservesLiteralEscapesAndNativeNumbers(t *testing.T) {
	f := newServiceFixture(t)
	metadata := map[string]any{
		"literal": `\u0000`, "integer": uint64(math.MaxUint64),
		"number": json.Number("1e999"), "nested": []any{"日本語", true, nil},
	}
	v, err := normalizeBuildInput(CreateBuildRunInput{ProjectID: "project", ReleaseID: "release", Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40), Status: "passed", StartedAt: f.now, ProviderMetadata: metadata})
	if err != nil || !reflect.DeepEqual(v.SourceIdentity, metadata) {
		t.Fatal("valid metadata changed or rejected", v.SourceIdentity, err)
	}
}
