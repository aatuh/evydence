package wiring

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

func TestPostgresProductSlugRejectsIndexOversizeBeforeWrite(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,name)VALUES('tenant','Slug limits')`); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildProductCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"product:write"}}
	var text strings.Builder
	for i := 0; i < 128; i++ {
		fmt.Fprintf(&text, "%x", sha256.Sum256([]byte(fmt.Sprint(i))))
	}
	if v, err := commands.CreateProduct(t.Context(), actor, releaseapp.CreateProductInput{Name: "Product", Slug: text.String()}); !errors.Is(err, releaseapp.ErrValidation) || v.ID != "" {
		t.Fatal("oversized natural identity was not rejected before database write", v.ID, err)
	}
	var products, audits int
	if err := pool.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM products),(SELECT count(*)FROM audit_chain_entries)`).Scan(&products, &audits); err != nil || products != 0 || audits != 0 {
		t.Fatal("oversized slug committed effects", products, audits, err)
	}
}
