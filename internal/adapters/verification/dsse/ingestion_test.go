package dsse

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

func TestBuildAttestationIngestionParserBindsBytesWithoutAssigningSignatureTrust(t *testing.T) {
	payload, err := os.ReadFile("../../../../testdata/intoto/slsa-provenance-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	// The signature is for unrelated bytes. Structural ingestion must not turn
	// an unverified signature into a trust claim or require policy at upload.
	raw := signedEnvelopeWithMessage(t, payload, private, []byte("wrong PAE"))
	source := releaseapp.BytesBuildAttestationPayloadSource(raw)
	r := &observedIngestionReader{Reader: bytes.NewReader(raw)}
	source.Open = func() (io.ReadCloser, error) { return r, nil }
	result, err := (BuildAttestationIngestionParser{}).ParseBuildAttestation(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	want, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !r.closed || r.bytes != len(raw) || result.PayloadHash != source.Digest || result.PayloadSize != source.Size || result.ParserVersion != releaseapp.BuildAttestationParserVersion || result.PayloadType != want.PayloadType || result.PredicateType != want.PredicateType || !reflect.DeepEqual(result.SubjectDigests, want.SubjectDigests) || result.BuilderID != want.BuilderID || result.BuildType != want.BuildType || result.MaterialsCount != want.MaterialsCount || result.SignatureCount != 1 {
		t.Fatalf("parsed=%#v expected=%#v reader=%#v", result, want, r)
	}
	verification, err := Verify(t.Context(), raw, Policy{Roots: []TrustRoot{{ID: "root", KeyID: "root-1", Algorithm: "Ed25519", PublicKey: base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))}}, AllowedPredicateTypes: []string{want.PredicateType}, ExpectedBuilderIDs: []string{want.BuilderID}, ExpectedSubjectDigests: want.SubjectDigests, RequiredClaims: []string{"builder_id", "build_type"}})
	if err != nil || verification.Passed() || verification.Check("dsse_pae_signature") != CheckFailed {
		t.Fatalf("invalid signature assigned trust: %#v err=%v", verification, err)
	}
}

func TestBuildAttestationIngestionParserRejectsBadSourcesAndClosesReaders(t *testing.T) {
	for _, name := range []string{"nil context", "cancelled context", "nil opener", "zero size", "oversized declared size", "invalid digest", "oversized digest", "invalid hex", "open failure", "nil reader", "read failure", "read cancellation", "size mismatch", "digest mismatch", "malformed JSON", "trailing JSON", "overlong stream"} {
		t.Run(name, func(t *testing.T) {
			raw := []byte(`{"payload":"private raw input"}`)
			source := releaseapp.BytesBuildAttestationPayloadSource(raw)
			r := &observedIngestionReader{Reader: bytes.NewReader(raw)}
			opens := 0
			source.Open = func() (io.ReadCloser, error) { opens++; return r, nil }
			ctx := context.Background()
			want := releaseapp.ErrValidation
			wantOpens := 1
			switch name {
			case "nil context":
				ctx = nil
				wantOpens = 0
			case "cancelled context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want, wantOpens = context.Canceled, 0
			case "nil opener":
				source.Open, wantOpens = nil, 0
			case "zero size":
				source.Size, wantOpens = 0, 0
			case "oversized declared size":
				source.Size, wantOpens = (20<<20)+1, 0
			case "invalid digest":
				source.Digest, wantOpens = "not-a-digest", 0
			case "oversized digest":
				source.Digest, wantOpens = "sha256:"+strings.Repeat("a", 100000), 0
			case "invalid hex":
				source.Digest, wantOpens = "sha256:"+strings.Repeat("g", 64), 0
			case "open failure":
				want = errors.New("open failed")
				source.Open = func() (io.ReadCloser, error) { opens++; return nil, want }
			case "nil reader":
				source.Open = func() (io.ReadCloser, error) { opens++; return nil, nil }
			case "read failure":
				want = errors.New("read failed")
				r.err = want
			case "read cancellation":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				r.onRead = cancel
				want = context.Canceled
			case "size mismatch":
				source.Size++
			case "digest mismatch":
				source.Digest = "sha256:" + strings.Repeat("b", 64)
			case "trailing JSON":
				raw = append(raw, []byte(` {}`)...)
				source = releaseapp.BytesBuildAttestationPayloadSource(raw)
				r.Reader = bytes.NewReader(raw)
				source.Open = func() (io.ReadCloser, error) { opens++; return r, nil }
			case "overlong stream":
				r.Reader = io.LimitReader(repeatedIngestionByte{}, 21<<20)
			}
			result, err := (BuildAttestationIngestionParser{}).ParseBuildAttestation(ctx, source)
			if !errors.Is(err, want) || !reflect.DeepEqual(result, releaseapp.ParsedBuildAttestation{}) || opens != wantOpens {
				t.Fatalf("result=%#v err=%v want=%v opens=%d want=%d", result, err, want, opens, wantOpens)
			}
			if opens == 1 && name != "open failure" && name != "nil reader" && !r.closed {
				t.Fatal("opened payload reader was not closed")
			}
			if r.bytes > (20<<20)+1 {
				t.Fatalf("unbounded stream read: %d", r.bytes)
			}
		})
	}
}

type observedIngestionReader struct {
	io.Reader
	bytes  int
	closed bool
	err    error
	onRead func()
}

func (r *observedIngestionReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	n, err := r.Reader.Read(p)
	r.bytes += n
	if r.onRead != nil {
		r.onRead()
	}
	return n, err
}
func (r *observedIngestionReader) Close() error { r.closed = true; return nil }

type repeatedIngestionByte struct{}

func (repeatedIngestionByte) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}
