package app

import (
	"encoding/hex"
	"strings"
	"testing"
)

func FuzzValidDigest(f *testing.F) {
	f.Add("")
	f.Add("sha256:")
	f.Add("sha256:" + strings.Repeat("0", 64))
	f.Add("sha256:" + strings.Repeat("g", 64))
	f.Add("md5:" + strings.Repeat("0", 32))

	f.Fuzz(func(t *testing.T, value string) {
		got := validDigest(value)
		if !got {
			return
		}
		if !strings.HasPrefix(value, "sha256:") {
			t.Fatalf("valid digest without sha256 prefix: %q", value)
		}
		digest := strings.TrimPrefix(value, "sha256:")
		if len(digest) != 64 {
			t.Fatalf("valid digest with length %d", len(digest))
		}
		decoded, err := hex.DecodeString(digest)
		if err != nil {
			t.Fatalf("valid digest did not decode: %v", err)
		}
		if len(decoded) != 32 {
			t.Fatalf("valid digest decoded to %d bytes", len(decoded))
		}
	})
}

func FuzzHashBytesProducesValidDigest(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("release-evidence"))
	f.Add([]byte(`{"password":"not-a-secret-hash-input","payload":"content"}`))

	f.Fuzz(func(t *testing.T, body []byte) {
		if digest := hashBytes(body); !validDigest(digest) {
			t.Fatalf("hashBytes produced invalid digest: %q", digest)
		}
	})
}
