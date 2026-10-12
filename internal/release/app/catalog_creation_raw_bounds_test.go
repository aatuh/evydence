package app

import (
	"errors"
	"strings"
	"testing"
)

func TestCatalogCreationRejectsRawPaddingAndNULBeforeTransactions(t *testing.T) {
	f := newServiceFixture(t)
	p, _, _ := seedReleaseScope(t, f)
	for _, bad := range []string{strings.Repeat(" ", 65537) + "name", "bad\x00name", string([]byte{0xff})} {
		if _, err := f.service.CreateProduct(t.Context(), f.actor, CreateProductInput{Name: bad, Slug: "new"}); !errors.Is(err, ErrValidation) || f.transactions.calls != 0 {
			t.Fatal("product raw text escaped preflight", err, f.transactions.calls)
		}
		if _, err := f.service.CreateProject(t.Context(), f.actor, CreateProjectInput{ProductID: p.ID, Name: bad}); !errors.Is(err, ErrValidation) || f.transactions.calls != 0 {
			t.Fatal("project raw text escaped preflight", err, f.transactions.calls)
		}
		if _, err := f.service.CreateRelease(t.Context(), f.actor, CreateReleaseInput{ProductID: p.ID, Version: bad}); !errors.Is(err, ErrValidation) || f.transactions.calls != 0 {
			t.Fatal("release raw text escaped preflight", err, f.transactions.calls)
		}
	}
}
