package app

import (
	"bytes"
	"io"
)

// PayloadSource provides repeatable, bounded access to an already-hashed raw
// payload. Callers can spool an HTTP request to a temporary file and expose it
// here, allowing validation and object-store staging to read the payload
// without retaining a second full in-memory copy.
type PayloadSource struct {
	Digest string
	Size   int64
	Open   func() (io.ReadCloser, error)
}

// BytesPayloadSource preserves the byte-slice API used by in-process callers
// while routing it through the same size, digest, and staging logic as a
// streamed HTTP payload.
func BytesPayloadSource(raw []byte) PayloadSource {
	return PayloadSource{
		Digest: hashBytes(raw),
		Size:   int64(len(raw)),
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(raw)), nil
		},
	}
}

func validatePayloadSource(source PayloadSource, limit int64) error {
	if !ValidPayloadSize(source.Size, limit) || !validDigest(source.Digest) || source.Open == nil {
		return ErrValidation
	}
	return nil
}
