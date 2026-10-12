package application

import (
	"crypto/rand"
	"encoding/hex"
)

// NewID generates an opaque, 128-bit random record identifier using the
// existing prefix-and-hex wire format.
func NewID(prefix string) string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(value[:])
}
