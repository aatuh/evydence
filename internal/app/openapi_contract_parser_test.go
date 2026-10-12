package app

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
)

const focusedOpenAPIDocument = `{"openapi":"3.0.3","info":{"title":"API","version":"1"},"paths":{"/health":{"get":{"operationId":"health","responses":{"200":{"description":"OK"}}}}}}`

type countedOpenAPIReader struct {
	io.Reader
	n        int
	closed   bool
	closeErr error
}

func (r *countedOpenAPIReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.n += n
	return n, err
}
func (r *countedOpenAPIReader) Close() error { r.closed = true; return r.closeErr }
func TestOpenAPIContractPayloadParserHasNoLedgerAndPreservesProjection(t *testing.T) {
	source := evidenceapp.BytesPayloadSource([]byte(focusedOpenAPIDocument))
	p := OpenAPIContractPayloadParser{}
	v, err := p.ParseOpenAPIContract(t.Context(), source)
	if err != nil || v.PathCount != 1 || len(v.Operations) != 1 || v.Operations[0].Path != "/health" || v.Operations[0].Method != "GET" || !reflect.DeepEqual(v.Operations[0].ResponseStatuses, []string{"200"}) || v.ParserVersion != ParserVersionOpenAPIJSON || v.SourceSchema != "openapi-3.0.3" {
		t.Fatal(v, err)
	}
	legacy, err := (ledgerEvidencePayloadParser{}).ParseOpenAPIContract(t.Context(), source)
	if err != nil || !reflect.DeepEqual(legacy, v) {
		t.Fatal("parser compatibility changed", legacy, v, err)
	}
}
func TestOpenAPIContractPayloadParserRejectsUnboundSourcesAndExternalReferences(t *testing.T) {
	p := OpenAPIContractPayloadParser{}
	for _, kind := range []string{"digest", "size", "nil-reader", "open", "close", "oversized-reader"} {
		t.Run(kind, func(t *testing.T) {
			source := evidenceapp.BytesPayloadSource([]byte(focusedOpenAPIDocument))
			reader := &countedOpenAPIReader{Reader: bytes.NewReader([]byte(focusedOpenAPIDocument))}
			source.Open = func() (io.ReadCloser, error) { return reader, nil }
			switch kind {
			case "digest":
				source.Digest = "sha256:" + strings.Repeat("f", 64)
			case "size":
				source.Size++
			case "nil-reader":
				source.Open = func() (io.ReadCloser, error) { return nil, nil }
			case "open":
				source.Open = func() (io.ReadCloser, error) { return nil, errors.New("private source") }
			case "close":
				reader.closeErr = errors.New("private close")
			case "oversized-reader":
				reader.Reader = io.MultiReader(strings.NewReader(focusedOpenAPIDocument), strings.NewReader(strings.Repeat(" ", 1<<20)))
			}
			if v, err := p.ParseOpenAPIContract(t.Context(), source); !errors.Is(err, evidenceapp.ErrValidation) || v.ParserVersion != "" {
				t.Fatal("unbound source trusted", v, err)
			}
			if kind != "nil-reader" && kind != "open" && (!reader.closed || int64(reader.n) > source.Size+1) {
				t.Fatal("reader escaped bound or was not closed", reader.n, reader.closed)
			}
		})
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(500) }))
	defer server.Close()
	raw := strings.Replace(focusedOpenAPIDocument, `{"description":"OK"}`, `{"$ref":"`+server.URL+`/untrusted.json"}`, 1)
	if _, err := p.ParseOpenAPIContract(t.Context(), evidenceapp.BytesPayloadSource([]byte(raw))); !errors.Is(err, evidenceapp.ErrValidation) || calls != 0 {
		t.Fatal("external reference fetched", calls, err)
	}
}
