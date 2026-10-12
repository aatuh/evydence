package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func memorySigningKeyPageFixture(t *testing.T) (*memoryUnitOfWork, verificationquery.SigningKeyReader) {
	t.Helper()
	_, tx := memoryGovernanceReadFixture(t)
	reader, ok := tx.Repositories().Signatures.(verificationquery.SigningKeyReader)
	if !ok {
		t.Fatal("memory signatures lack the native public signing-key page")
	}
	return tx, reader
}

func memorySigningKeyPageRecord(id string) domain.SigningKey {
	at := fixedNow()
	return domain.SigningKey{ID: id, TenantID: "tenant", KID: "kid-" + id, Version: 7, Provider: "local_ed25519", Algorithm: "Ed25519", Status: "revoked", PublicKey: "public", PublicKeyFingerprint: "fingerprint", Private: []byte("private-key"), ValidFrom: at.Add(-time.Hour), ValidUntil: &at, CreatedAt: at.Add(-2 * time.Hour), RevokedAt: &at, RevocationReason: "reviewed", RevocationSemantics: "compromise", HistoricalValidityPolicy: "reject_since_compromise", CompromisedAt: &at}
}

func TestMemorySigningKeyPagesRetainPublicLifecycleAndNeverAliasPrivateState(t *testing.T) {
	tx, reader := memorySigningKeyPageFixture(t)
	for _, id := range []string{"a", "b", "c"} {
		v := memorySigningKeyPageRecord(id)
		v.Private = []byte(strings.Repeat("ignored-private", 100000))
		tx.state.SigningKeys[id] = v
	}
	foreign := memorySigningKeyPageRecord("foreign")
	foreign.TenantID, foreign.Status = "foreign", "invalid"
	tx.state.SigningKeys[foreign.ID] = foreign
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	req := verificationquery.SigningKeyPageRequest{TenantID: "tenant", Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}}
	page, err := reader.PageSigningKeys(t.Context(), req)
	want := tx.state.SigningKeys["a"]
	status, _ := verificationdomain.ParseSigningKeyStatus(want.Status)
	model := verificationdomain.SigningKey{ID: want.ID, TenantID: want.TenantID, KID: want.KID, Version: want.Version, Provider: want.Provider, Algorithm: want.Algorithm, Status: status, PublicKey: want.PublicKey, PublicKeyFingerprint: want.PublicKeyFingerprint, ValidFrom: want.ValidFrom, ValidUntil: want.ValidUntil, CreatedAt: want.CreatedAt, RevokedAt: want.RevokedAt, RevocationReason: want.RevocationReason, RevocationSemantics: want.RevocationSemantics, HistoricalValidityPolicy: want.HistoricalValidityPolicy, CompromisedAt: want.CompromisedAt}
	if err != nil || len(page.Items) != 1 || !reflect.DeepEqual(page.Items[0], model) || page.Next == nil || page.Next.ID != "a" {
		t.Fatal("public page lost lifecycle, tenant isolation or cursor", page, err)
	}
	*page.Items[0].ValidUntil = fixedNow().AddDate(1, 0, 0)
	*page.Items[0].RevokedAt = fixedNow().AddDate(2, 0, 0)
	*page.Items[0].CompromisedAt = fixedNow().AddDate(3, 0, 0)
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("public page aliases or mutates private repository state")
	}
	bad := tx.state.SigningKeys["c"]
	bad.Status = "invalid"
	tx.state.SigningKeys["c"] = bad
	if _, err := reader.PageSigningKeys(t.Context(), req); err != nil {
		t.Fatal("unselected corrupt metadata affected the bounded page", err)
	}
	req.After = page.Next
	if v, err := reader.PageSigningKeys(t.Context(), req); err == nil || !reflect.DeepEqual(v, appquery.Result[verificationdomain.SigningKey]{}) {
		t.Fatal("corrupt lookahead returned a partial public page", v, err)
	}
}

func TestMemorySigningKeyPagesTraverseMoreThanFiveHundredKeysInEveryOrder(t *testing.T) {
	tx, reader := memorySigningKeyPageFixture(t)
	for i := range 501 {
		v := memorySigningKeyPageRecord(fmt.Sprintf("key-%03d", i))
		v.CreatedAt = v.CreatedAt.Add(time.Duration((501-i)/3) * time.Minute)
		tx.state.SigningKeys[v.ID] = v
	}
	for _, sortBy := range []appquery.Sort{appquery.SortID, appquery.SortCreatedAt} {
		for _, direction := range []appquery.Direction{appquery.Ascending, appquery.Descending} {
			t.Run(string(sortBy)+"/"+string(direction), func(t *testing.T) {
				req := verificationquery.SigningKeyPageRequest{TenantID: "tenant", Page: appquery.PageRequest{PageSize: 7, Sort: sortBy, Direction: direction}}
				var got []string
				for count := 0; count < 80; count++ {
					page, err := reader.PageSigningKeys(t.Context(), req)
					if err != nil || len(page.Items) > 7 {
						t.Fatal("keyset page failed", err)
					}
					for _, v := range page.Items {
						got = append(got, v.ID)
						if v.TenantID != "tenant" {
							t.Fatal("page included foreign key")
						}
					}
					if page.Next == nil {
						break
					}
					last := page.Items[len(page.Items)-1]
					if *page.Next != appquery.RecordSortKey(last.ID, last.CreatedAt, sortBy) {
						t.Fatal("cursor does not identify the last returned key")
					}
					req.After = page.Next
				}
				want := make([]string, 501)
				for i := range want {
					want[i] = fmt.Sprintf("key-%03d", i)
				}
				if sortBy == appquery.SortCreatedAt {
					slices.SortFunc(want, func(a, b string) int {
						comparison := tx.state.SigningKeys[a].CreatedAt.Compare(tx.state.SigningKeys[b].CreatedAt)
						if comparison == 0 {
							comparison = strings.Compare(a, b)
						}
						return comparison
					})
				}
				if direction == appquery.Descending {
					slices.Reverse(want)
				}
				if !slices.Equal(got, want) {
					t.Fatal("keyset traversal omitted, duplicated or misordered records", len(got))
				}
			})
		}
	}
}

func TestMemorySigningKeyPageRejectsInvalidContextAndClosedTransaction(t *testing.T) {
	tx, reader := memorySigningKeyPageFixture(t)
	req := verificationquery.SigningKeyPageRequest{TenantID: "tenant", Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}}
	var missingContext context.Context // Deliberate invalid-input characterization.
	if v, err := reader.PageSigningKeys(missingContext, req); err == nil || !reflect.DeepEqual(v, appquery.Result[verificationdomain.SigningKey]{}) {
		t.Fatal("nil context returned a public page", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reader.PageSigningKeys(ctx, req); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation was not propagated", err)
	}
	req.TenantID = "missing"
	if _, err := reader.PageSigningKeys(t.Context(), req); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing tenant was accepted", err)
	}
	req.TenantID = "tenant"
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.PageSigningKeys(t.Context(), req); err == nil {
		t.Fatal("closed transaction returned signing keys")
	}
}

func TestMemorySigningKeyPageUsesNativeCursorValidation(t *testing.T) {
	_, reader := memorySigningKeyPageFixture(t)
	for _, tc := range []struct {
		name string
		req  verificationquery.SigningKeyPageRequest
		want error
	}{
		{"invalid page", verificationquery.SigningKeyPageRequest{TenantID: "tenant"}, appquery.ErrInvalidPage},
		{"mismatched ID cursor", verificationquery.SigningKeyPageRequest{TenantID: "tenant", Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}, After: &appquery.SortKey{ID: "a", Value: "b"}}, appquery.ErrInvalidCursor},
		{"malformed time", verificationquery.SigningKeyPageRequest{TenantID: "tenant", Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}, After: &appquery.SortKey{ID: "a", Value: "not-time"}}, appquery.ErrInvalidCursor},
		{"noncanonical time", verificationquery.SigningKeyPageRequest{TenantID: "tenant", Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}, After: &appquery.SortKey{ID: "a", Value: "2026-10-09T12:00:00+00:00"}}, appquery.ErrInvalidCursor},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := reader.PageSigningKeys(t.Context(), tc.req)
			if !errors.Is(err, tc.want) || !reflect.DeepEqual(v, appquery.Result[verificationdomain.SigningKey]{}) {
				t.Fatal("invalid cursor/page returned data or wrong error", err)
			}
		})
	}
}
