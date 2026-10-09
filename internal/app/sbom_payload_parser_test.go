package app

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
)

const focusedCycloneDXDocument = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"api","version":"1.0.0","purl":"pkg:generic/api@1.0.0"}]}`

func TestSBOMPayloadParserPreservesBothNormalizedFormatsWithoutLedger(t *testing.T) {
	for _, tc := range []struct{ format, raw, spec string }{{"cyclonedx", focusedCycloneDXDocument, "1.6"}, {"spdx", validSPDXUpload, "SPDX-2.3"}} {
		t.Run(tc.format, func(t *testing.T) {
			source := evidenceapp.BytesPayloadSource([]byte(tc.raw))
			v, err := (SBOMPayloadParser{}).ParseSBOM(t.Context(), tc.format, source)
			if err != nil || v.Format != tc.format || v.SpecVersion != tc.spec || v.ParserVersion == "" || len(v.Components) != 1 || v.Components[0].Name != "api" || v.Components[0].PURL != "pkg:generic/api@1.0.0" {
				t.Fatal("normalization changed", v, err)
			}
			legacy, err := (ledgerEvidencePayloadParser{}).ParseSBOM(t.Context(), tc.format, source)
			if err != nil || !reflect.DeepEqual(v, legacy) {
				t.Fatal("legacy/narrow parser diverged", v, legacy, err)
			}
		})
	}
}
func TestSBOMPayloadParserRejectsUnboundAndOversizedReaderClaims(t *testing.T) {
	for _, tc := range []struct{ format, raw string }{{"cyclonedx", focusedCycloneDXDocument}, {"spdx", validSPDXUpload}} {
		for _, kind := range []string{"oversized-reader", "digest", "size", "open", "close", "nil-reader"} {
			t.Run(tc.format+"/"+kind, func(t *testing.T) {
				source := evidenceapp.BytesPayloadSource([]byte(tc.raw))
				reader := &countedOpenAPIReader{Reader: strings.NewReader(tc.raw)}
				source.Open = func() (io.ReadCloser, error) { return reader, nil }
				switch kind {
				case "oversized-reader":
					reader.Reader = io.MultiReader(strings.NewReader(tc.raw), strings.NewReader(strings.Repeat(" ", 1<<20)))
				case "digest":
					source.Digest = "sha256:" + strings.Repeat("f", 64)
				case "size":
					source.Size++
				case "open":
					source.Open = func() (io.ReadCloser, error) { return nil, errors.New("private source") }
				case "close":
					reader.closeErr = errors.New("private close")
				case "nil-reader":
					source.Open = func() (io.ReadCloser, error) { return nil, nil }
				}
				if v, err := (SBOMPayloadParser{}).ParseSBOM(t.Context(), tc.format, source); !errors.Is(err, evidenceapp.ErrValidation) || v.ParserVersion != "" {
					t.Fatal("unbound source accepted", v, err)
				}
				if kind != "nil-reader" && kind != "open" && (!reader.closed || int64(reader.n) > source.Size+1) {
					t.Fatal("reader escaped claim or was not closed", reader.n, reader.closed, source.Size)
				}
			})
		}
	}
	p := SBOMPayloadParser{}
	//nolint:staticcheck // Deliberately exercise the parser's fail-closed nil-context boundary.
	if _, err := p.ParseSBOM(nil, "cyclonedx", evidenceapp.BytesPayloadSource([]byte(`{}`))); !errors.Is(err, evidenceapp.ErrValidation) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := p.ParseSBOM(ctx, "cyclonedx", evidenceapp.BytesPayloadSource([]byte(`{}`))); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
