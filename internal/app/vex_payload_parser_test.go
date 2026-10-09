package app

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
)

func TestVEXPayloadParserPreservesSharedCorpusAndProvenanceWithoutLedger(t *testing.T) {
	for _, tc := range []struct{ format, path, version string }{
		{"openvex", "parsers/vex/testdata/openvex/openvex-spec-minimal.json", ParserVersionOpenVEXJSON},
		{"cyclonedx", "parsers/vex/testdata/cyclonedx-vex/official-vex-1.4.json", ParserVersionCycloneDXVEXJSON},
	} {
		t.Run(tc.format, func(t *testing.T) {
			raw, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			source := evidenceapp.BytesPayloadSource(raw)
			parsed, err := (VEXPayloadParser{}).ParseVEX(t.Context(), tc.format, source)
			if err != nil || parsed.Format != tc.format || parsed.ParserVersion != tc.version || parsed.StatementCount <= 0 || parsed.ValidStatementCount <= 0 || len(parsed.Statements) != parsed.ValidStatementCount {
				t.Fatal("VEX normalization changed", parsed, err)
			}
			provenance, ok := parsed.Metadata["parser"].(map[string]any)
			if !ok || provenance["version"] != tc.version || provenance["normalized_schema"] != "evydence-vex.v1" || provenance["replay_status"] != ParserReplayStatusOriginal {
				t.Fatal("VEX provenance changed", provenance)
			}
			legacy, err := (ledgerEvidencePayloadParser{}).ParseVEX(t.Context(), tc.format, source)
			if err != nil || !reflect.DeepEqual(parsed, legacy) {
				t.Fatal("legacy VEX parser diverged", parsed, legacy, err)
			}
		})
	}
}

func TestVEXPayloadParserRejectsUnboundSourceClaimsAndInvalidContexts(t *testing.T) {
	raw, err := os.ReadFile("parsers/vex/testdata/openvex/openvex-spec-minimal.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"oversized-reader", "digest", "size", "open", "close", "nil-reader", "nil-context", "cancelled", "format"} {
		t.Run(kind, func(t *testing.T) {
			source := evidenceapp.BytesPayloadSource(raw)
			reader := &countedOpenAPIReader{Reader: strings.NewReader(string(raw))}
			source.Open = func() (io.ReadCloser, error) { return reader, nil }
			ctx, format, want := t.Context(), "openvex", evidenceapp.ErrValidation
			switch kind {
			case "oversized-reader":
				reader.Reader = io.MultiReader(strings.NewReader(string(raw)), strings.NewReader(strings.Repeat(" ", 1<<20)))
			case "digest":
				source.Digest = "sha256:" + strings.Repeat("f", 64)
			case "size":
				source.Size++
			case "open":
				source.Open = func() (io.ReadCloser, error) { return nil, errors.New("private VEX reader") }
			case "close":
				reader.closeErr = errors.New("private VEX close")
			case "nil-reader":
				source.Open = func() (io.ReadCloser, error) { return nil, nil }
			case "nil-context":
				ctx = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			case "format":
				format = "unsupported"
			}
			v, err := (VEXPayloadParser{}).ParseVEX(ctx, format, source)
			if !errors.Is(err, want) || v.ParserVersion != "" {
				t.Fatal("unbound VEX source accepted", v, err)
			}
			if kind != "open" && kind != "nil-reader" && kind != "nil-context" && kind != "cancelled" && (!reader.closed || int64(reader.n) > source.Size+1) {
				t.Fatal("VEX reader escaped its bound or was not closed", reader.n, reader.closed)
			}
		})
	}
}
