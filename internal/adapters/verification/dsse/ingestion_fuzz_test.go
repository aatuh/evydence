package dsse

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/platform/jsonbounds"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

type ingestionFuzzChunkReader struct{ reader *bytes.Reader }

func (r ingestionFuzzChunkReader) Read(out []byte) (int, error) {
	return r.reader.Read(out[:min(len(out), 7)])
}

func FuzzBuildAttestationIngestion(f *testing.F) {
	payload, err := os.ReadFile("../../../../testdata/intoto/slsa-provenance-v1.json")
	if err != nil {
		f.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	// Deliberately invalid PAE: structural ingestion must neither require nor
	// grant signature trust. The separate verifier properties assess trust.
	baseline := signedEnvelopeWithMessage(f, payload, private, []byte("unrelated synthetic PAE"))
	for mode := uint8(0); mode < 6; mode++ {
		f.Add(baseline, mode)
	}
	f.Add([]byte(`{}`), uint8(0))
	f.Add([]byte(`{"payloadType":"unknown","payload":"e30=","signatures":[]}`), uint8(1))
	f.Add(append([]byte(`{"payloadType":"application/vnd.in-toto+json",`), baseline[1:]...), uint8(0))
	f.Add(append([]byte(`{"payload\u0054ype":"application/vnd.in-toto+json",`), baseline[1:]...), uint8(1))
	f.Add([]byte(strings.Replace(string(baseline), `"keyid":"root-1"`, `"keyid":"root-1","keyid":"ambiguous"`, 1)), uint8(2))
	f.Fuzz(func(t *testing.T, raw []byte, mode uint8) {
		if len(raw) > 64<<10 {
			return
		}
		limits := jsonbounds.Limits{MaxDepth: 24, MaxObjectKeys: 64, MaxArrayItems: 64, MaxStringBytes: 32 << 10}
		shapeErr := jsonbounds.Validate(raw, limits)
		if shapeErr != nil && !errors.Is(shapeErr, jsonbounds.ErrDuplicateObjectKey) {
			return
		}
		// Bound decoded in-toto structure before the production protobuf
		// parser runs, just as the existing DSSE verification harness does.
		var envelope struct {
			Payload string `json:"payload"`
		}
		if json.Unmarshal(raw, &envelope) == nil {
			decoded, decodeErr := base64.StdEncoding.DecodeString(envelope.Payload)
			if decodeErr == nil && json.Valid(decoded) && jsonbounds.Validate(decoded, limits) != nil {
				return
			}
		}
		parse := func(ctx context.Context, body []byte) (releaseapp.ParsedBuildAttestation, error) {
			source := releaseapp.BytesBuildAttestationPayloadSource(body)
			reader := &observedIngestionReader{Reader: ingestionFuzzChunkReader{bytes.NewReader(body)}}
			source.Open = func() (io.ReadCloser, error) { return reader, nil }
			result, err := (BuildAttestationIngestionParser{}).ParseBuildAttestation(ctx, source)
			if !reader.closed || reader.bytes != len(body) {
				t.Fatal("structural ingestion did not close and consume its bounded reader")
			}
			if err == nil && (result.PayloadHash != source.Digest || result.PayloadSize != source.Size || result.ParserVersion != releaseapp.BuildAttestationParserVersion) {
				t.Fatal("ingestion projection lost observed payload identity or parser provenance")
			}
			return result, err
		}
		before := append([]byte(nil), raw...)
		first, firstErr := parse(t.Context(), raw)
		again, againErr := parse(t.Context(), raw)
		if (firstErr == nil) != (againErr == nil) || !reflect.DeepEqual(first, again) || !bytes.Equal(raw, before) {
			t.Fatal("ingestion is not repeatable or mutated its input")
		}
		if firstErr != nil && (!errors.Is(firstErr, releaseapp.ErrValidation) || !reflect.DeepEqual(first, releaseapp.ParsedBuildAttestation{})) {
			t.Fatal("invalid envelope leaked a projection or parser error")
		}
		if shapeErr != nil && firstErr == nil {
			t.Fatal("ambiguous envelope acquired a structural projection")
		}
		positive, err := parse(t.Context(), baseline)
		if err != nil || positive.ParserVersion != releaseapp.BuildAttestationParserVersion || positive.PayloadType != testPayloadType || positive.PredicateType != testPredicate || positive.BuilderID != testBuilder || len(positive.SubjectDigests) != 1 || positive.SubjectDigests[0] != testSubject || positive.SignatureCount != 1 {
			t.Fatalf("structural positive envelope rejected: %v", err)
		}
		bad := releaseapp.BytesBuildAttestationPayloadSource(baseline)
		reader := &observedIngestionReader{Reader: bytes.NewReader(baseline)}
		opens := 0
		bad.Open = func() (io.ReadCloser, error) { opens++; return reader, nil }
		ctx := t.Context()
		want := releaseapp.ErrValidation
		wantOpens := 1
		switch mode % 6 {
		case 0:
			bad.Size++
		case 1:
			last := "0"
			if bad.Digest[len(bad.Digest)-1] == '0' {
				last = "1"
			}
			bad.Digest = bad.Digest[:len(bad.Digest)-1] + last
		case 2:
			bad.Size, wantOpens = buildAttestationIngestionLimit+1, 0
		case 3:
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			cancel()
			want, wantOpens = context.Canceled, 0
		case 4:
			want = errors.New("synthetic read failure")
			reader.err = want
		case 5:
			bad.Open, wantOpens = nil, 0
		}
		result, err := (BuildAttestationIngestionParser{}).ParseBuildAttestation(ctx, bad)
		if !errors.Is(err, want) || !reflect.DeepEqual(result, releaseapp.ParsedBuildAttestation{}) || opens != wantOpens || (opens == 1 && !reader.closed) || reader.bytes > len(baseline) {
			t.Fatal("invalid size/digest/source or cancellation acquired an ingestion projection")
		}
	})
}
