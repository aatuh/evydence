//go:build !unix

package config

import (
	"context"
	"errors"
	"testing"
)

func TestSecretFileReadUnsupportedPlatformFailsClosed(t *testing.T) {
	secret, err := readSecretFile(context.Background(), "PRIVATE_UNSUPPORTED_REFERENCE", 64)
	if !errors.Is(err, ErrSecretResolution) || secret.IsSet() {
		t.Fatal("unsupported private-file policy returned secret material", err)
	}
}
