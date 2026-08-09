package cyclonedx

import (
	"errors"
	"io"
	"strings"
	"testing"
)

type singleByteCountingReader struct {
	raw []byte
	off int
}

func (r *singleByteCountingReader) Read(p []byte) (int, error) {
	if r.off >= len(r.raw) {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = r.raw[r.off]
	r.off++
	return 1, nil
}

func TestParseBoundedReaderRejectsExcessiveDepthBeforeConsumingTail(t *testing.T) {
	limits := DefaultLimits(1 << 20)
	raw := []byte(strings.Repeat("[", limits.MaxDepth+1) + "0" + strings.Repeat("]", limits.MaxDepth+1) + strings.Repeat(" ", 32<<10))
	reader := &singleByteCountingReader{raw: raw}

	if _, err := ParseBoundedReader(reader, limits); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err=%v, want invalid", err)
	}
	if reader.off > limits.MaxDepth+8 {
		t.Fatalf("read %d bytes before rejecting excessive depth", reader.off)
	}
}
