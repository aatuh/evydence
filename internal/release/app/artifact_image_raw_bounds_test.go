package app

import (
	"errors"
	"strings"
	"testing"
)

func TestArtifactImageRegistrationBoundsRawTextBeforeTransaction(t *testing.T) {
	for _, bad := range []string{strings.Repeat(" ", 65537) + "name", "bad\x00name", string([]byte{0xff})} {
		f := newServiceFixture(t)
		if _, err := f.service.RegisterArtifact(t.Context(), f.actor, RegisterArtifactInput{Name: bad, MediaType: "text/plain", Digest: testSHA256('a'), Size: 1}); !errors.Is(err, ErrValidation) || f.transactions.calls != 0 {
			t.Fatal("artifact text escaped raw bound", err, f.transactions.calls)
		}
		if _, err := f.service.RegisterContainerImage(t.Context(), f.actor, RegisterContainerImageInput{Repository: bad, Digest: testSHA256('a')}); !errors.Is(err, ErrValidation) || f.transactions.calls != 0 {
			t.Fatal("image text escaped raw bound", err, f.transactions.calls)
		}
	}
}
