package app

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestValidateAndNormalizeSPDXSourceBindsDeclaredBytes(t *testing.T) {
	raw := []byte(validSPDXUpload)
	source := BytesPayloadSource(raw)
	got, err := validateAndNormalizeSPDXSource(source)
	if err != nil {
		t.Fatal(err)
	}
	if got.SpecVersion != "SPDX-2.3" || len(got.Components) != 1 || got.Components[0].Identity != "purl:pkg:generic/api@1.0.0" {
		t.Fatalf("normalization=%#v", got)
	}

	other := []byte(strings.Replace(validSPDXUpload, "pkg:generic/api@1.0.0", "pkg:generic/other@1.0.0", 1))
	mutable := BytesPayloadSource(raw)
	mutable.Open = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(string(other))), nil }
	if _, err := validateAndNormalizeSPDXSource(mutable); !errors.Is(err, ErrValidation) {
		t.Fatalf("mutable source err=%v, want validation", err)
	}
}

func TestValidateAndNormalizeSPDXSourceRejectsOpenFailureAndReplayUsesSharedParser(t *testing.T) {
	bad := BytesPayloadSource([]byte(validSPDXUpload))
	bad.Open = func() (io.ReadCloser, error) { return nil, errors.New("unavailable") }
	if _, err := validateAndNormalizeSPDXSource(bad); !errors.Is(err, ErrValidation) {
		t.Fatalf("open failure err=%v, want validation", err)
	}
	projection, err := ParseSPDXReplayProjection([]byte(validSPDXUpload), EvidenceDocumentLimit)
	if err != nil || projection.SpecVersion != "SPDX-2.3" || len(projection.Components) != 1 {
		t.Fatalf("projection=%#v err=%v", projection, err)
	}
}
