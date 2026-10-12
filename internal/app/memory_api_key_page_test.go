package app

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	identityquery "github.com/aatuh/evydence/internal/identity/query"
)

func TestMemoryAPIKeyPagesExcludeHashesAndProjectOnlySelectedOwnedMetadata(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	// Replace the target-reader fixture's deliberately incomplete credential.
	delete(tx.state.APIKeys, "tenant-key")
	r, ok := tx.Repositories().Identity.(identityquery.APIKeyReader)
	if !ok {
		t.Fatal("memory identity lacks native API-key metadata page")
	}
	at := fixedNow()
	for _, id := range []string{"a", "b", "c"} {
		tx.state.APIKeys[id] = domain.APIKey{ID: id, TenantID: "tenant", Name: "Key " + id, Prefix: "evy_test1234", Hash: strings.Repeat("private-hash", 100000), Scopes: []string{"evidence:read"}, ExpiresAt: &at, CreatedAt: at}
	}
	tx.state.APIKeys["foreign"] = domain.APIKey{ID: "foreign", TenantID: "foreign", Name: strings.Repeat("unselected", 100000)}
	req := identityquery.APIKeyPageRequest{TenantID: "tenant", Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}}
	page, err := r.PageAPIKeys(t.Context(), req)
	want := tx.state.APIKeys["a"]
	want.Hash = ""
	if err != nil || len(page.Items) != 1 || !reflect.DeepEqual(page.Items[0], identitydomain.APIKey(want)) || page.Next == nil || page.Next.ID != "a" {
		t.Fatal("metadata page lost fields, leaked hash/foreign data or lost keyset", page, err)
	}
	page.Items[0].Scopes[0] = "mutated"
	*page.Items[0].ExpiresAt = at.AddDate(1, 0, 0)
	if tx.state.APIKeys["a"].Scopes[0] != "evidence:read" || !tx.state.APIKeys["a"].ExpiresAt.Equal(at) {
		t.Fatal("public metadata page aliases state")
	}
	req.After = page.Next
	page, err = r.PageAPIKeys(t.Context(), req)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != "b" {
		t.Fatal("API-key cursor failed to advance", page, err)
	}
	bad := tx.state.APIKeys["a"]
	bad.Name = strings.Repeat("x", 65537)
	tx.state.APIKeys["a"] = bad
	req.After = nil
	req.Page.Direction = appquery.Descending
	if _, err := r.PageAPIKeys(t.Context(), req); err != nil {
		t.Fatal("unselected corrupt name affected metadata page", err)
	}
	req.Page.Direction = appquery.Ascending
	if v, err := r.PageAPIKeys(t.Context(), req); !errors.Is(err, identityquery.ErrInvalidProjection) || !reflect.DeepEqual(v, appquery.Result[identitydomain.APIKey]{}) {
		t.Fatal("corrupt selected key returned partial page", v, err)
	}
}
