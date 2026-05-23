package s3

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/app"
)

func TestNewRejectsIncompleteConfigWithoutNetwork(t *testing.T) {
	_, err := New(context.Background(), Config{Endpoint: "localhost:9000", Bucket: "evydence"})
	if !errors.Is(err, app.ErrValidation) {
		t.Fatalf("err = %v, want validation", err)
	}
}
