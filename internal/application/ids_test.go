package application

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestNewIDPreservesOpaqueRecordFormatAndUniqueness(t *testing.T) {
	first := NewID("prod")
	second := NewID("prod")
	for _, id := range []string{first, second} {
		if !strings.HasPrefix(id, "prod_") || len(id) != len("prod_")+32 {
			t.Fatalf("invalid record ID %q", id)
		}
		if _, err := hex.DecodeString(strings.TrimPrefix(id, "prod_")); err != nil {
			t.Fatalf("invalid ID entropy %q: %v", id, err)
		}
	}
	if first == second {
		t.Fatal("random record IDs collided")
	}
}
