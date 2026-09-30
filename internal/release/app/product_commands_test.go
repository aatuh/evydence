package app

import (
	"context"
	"errors"
	"testing"
	"time"

	application "github.com/aatuh/evydence/internal/application"
)

func TestStandaloneProductCommandsShareAuthorizedTransactionalRules(t *testing.T) {
	fixture := newServiceFixture(t)
	commands, err := NewProductCommands(ProductCommandConfig{
		Authorizer:   fixture.authorizer,
		Transactions: releaseProductTransactions{runner: fixture.transactions},
		Clock:        application.ClockFunc(func() time.Time { return fixture.now }),
		IDs:          application.IDGeneratorFunc(func(prefix string) string { return prefix + "_standalone" }),
	})
	if err != nil {
		t.Fatalf("new product commands: %v", err)
	}
	product, err := commands.CreateProduct(context.Background(), fixture.actor, CreateProductInput{Name: " Standalone ", Slug: " standalone "})
	if err != nil || product.ID != "prod_standalone" || product.Name != "Standalone" || product.Slug != "standalone" {
		t.Fatalf("created product=%#v err=%v", product, err)
	}
	if len(fixture.transactions.state.products) != 1 || len(fixture.transactions.state.audit) != 1 {
		t.Fatalf("product and audit were not committed together: %#v", fixture.transactions.state)
	}
	if _, err := commands.CreateProduct(context.Background(), fixture.actor, CreateProductInput{Name: "Duplicate", Slug: "standalone"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate slug err=%v, want conflict", err)
	}
	fixture.authorizer.err = errDenied
	before := fixture.transactions.calls
	if _, err := commands.CreateProduct(context.Background(), fixture.actor, CreateProductInput{Name: "Denied", Slug: "denied"}); !errors.Is(err, errDenied) {
		t.Fatalf("denied create err=%v", err)
	}
	if fixture.transactions.calls != before {
		t.Fatal("denied actor opened a product transaction")
	}
}
