package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"testing"
	"testing/iotest"

	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
)

type sourceFuzzReader struct {
	io.Reader
	read   int
	closed bool
}

func (r *sourceFuzzReader) Read(out []byte) (int, error) {
	n, err := r.Reader.Read(out)
	r.read += n
	return n, err
}
func (r *sourceFuzzReader) Close() error { r.closed = true; return nil }

func replayFuzzSourceProperties(t *testing.T, c replayFuzzCase, raw []byte, mode uint8, requireSuccess bool) {
	t.Helper()
	type call func(context.Context, evidenceapp.PayloadSource) (any, error)
	var calls []call
	switch c.evidenceType {
	case "sbom":
		calls = append(calls, func(ctx context.Context, source evidenceapp.PayloadSource) (any, error) {
			return (SBOMPayloadParser{}).ParseSBOM(ctx, c.subtype, source)
		})
	case "vex":
		calls = append(calls, func(ctx context.Context, source evidenceapp.PayloadSource) (any, error) {
			return (VEXPayloadParser{}).ParseVEX(ctx, c.subtype, source)
		})
	case "openapi_contract":
		calls = append(calls, func(ctx context.Context, source evidenceapp.PayloadSource) (any, error) {
			return (OpenAPIContractPayloadParser{}).ParseOpenAPIContract(ctx, source)
		})
	case "vulnerability_scan":
		calls = append(calls,
			func(ctx context.Context, source evidenceapp.PayloadSource) (any, error) {
				return (VulnerabilityScanPayloadParser{}).ParseVulnerabilityScan(ctx, source)
			},
			func(ctx context.Context, source evidenceapp.PayloadSource) (any, error) {
				return (VulnerabilityScanPayloadParser{}).ProbeVulnerabilityScanScope(ctx, source)
			})
	default:
		t.Fatal("unknown source parser family")
	}
	for _, parse := range calls {
		invoke := func(body []byte) (any, error) {
			source := evidenceapp.BytesPayloadSource(body)
			reader := &sourceFuzzReader{Reader: iotest.HalfReader(bytes.NewReader(body))}
			source.Open = func() (io.ReadCloser, error) { return reader, nil }
			value, err := parse(t.Context(), source)
			if !reader.closed || reader.read > len(body) || err == nil && reader.read != len(body) {
				t.Fatal("source parser lost bounded reader ownership or complete digest binding")
			}
			return value, err
		}
		first, err := invoke(raw)
		again, againErr := invoke(raw)
		if (err == nil) != (againErr == nil) || !reflect.DeepEqual(first, again) {
			t.Fatal("ingestion source projection is not repeatable")
		}
		if err != nil {
			if requireSuccess || !errors.Is(err, evidenceapp.ErrValidation) || !reflect.DeepEqual(first, reflect.Zero(reflect.TypeOf(first)).Interface()) {
				t.Fatal("known source rejected or invalid source leaked a projection", err)
			}
			continue
		}
		bad := evidenceapp.BytesPayloadSource(raw)
		reader := &sourceFuzzReader{Reader: bytes.NewReader(raw)}
		opens := 0
		bad.Open = func() (io.ReadCloser, error) { opens++; return reader, nil }
		ctx := t.Context()
		want := evidenceapp.ErrValidation
		wantOpens := 1
		switch mode % 4 {
		case 0:
			bad.Size++
		case 1:
			last := "0"
			if bad.Digest[len(bad.Digest)-1] == '0' {
				last = "1"
			}
			bad.Digest = bad.Digest[:len(bad.Digest)-1] + last
		case 2:
			bad.Open, wantOpens = nil, 0
		case 3:
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			cancel()
			want, wantOpens = context.Canceled, 0
		}
		value, err := parse(ctx, bad)
		if !errors.Is(err, want) || !reflect.DeepEqual(value, reflect.Zero(reflect.TypeOf(value)).Interface()) || opens != wantOpens || opens > 0 && !reader.closed {
			t.Fatal("unbound or canceled source acquired an ingestion projection")
		}
	}
}
