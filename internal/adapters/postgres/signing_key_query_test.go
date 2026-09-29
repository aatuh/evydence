package postgres

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func TestPostgresSigningKeyQueryPagesTenantPublicMetadata(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for _, tenant := range []string{"tenant_keys", "tenant_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct {
		id, tenant, status string
		createdAt          time.Time
	}{
		{"key_a", "tenant_keys", "revoked", now},
		{"key_b", "tenant_keys", "retiring", now},
		{"key_c", "tenant_keys", "active", now.Add(time.Second)},
		{"key_other", "tenant_other", "active", now},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO signing_keys (id, tenant_id, kid, algorithm, status, public_key, encrypted_private_key, created_at, version, provider, valid_from) VALUES ($1, $2, $1, 'Ed25519', $3, 'public-key', decode('deadbeef', 'hex'), $4, 1, 'local_ed25519', $4)`, row.id, row.tenant, row.status, row.createdAt); err != nil {
			t.Fatal(err)
		}
	}
	request := verificationquery.SigningKeyPageRequest{TenantID: "tenant_keys", Page: appquery.PageRequest{PageSize: 2, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}}
	first, err := store.PageSigningKeys(ctx, request)
	if err != nil || len(first.Items) != 2 || first.Items[0].ID != "key_a" || first.Items[1].ID != "key_b" || first.Next == nil || first.Items[0].PublicKey != "public-key" {
		t.Fatalf("first key page=%#v error=%v", first, err)
	}
	request.After = first.Next
	second, err := store.PageSigningKeys(ctx, request)
	if err != nil || len(second.Items) != 1 || second.Items[0].ID != "key_c" || second.Next != nil || second.Items[0].Status.String() != "active" {
		t.Fatalf("second key page=%#v error=%v", second, err)
	}
	request.After = nil
	request.Page.Sort, request.Page.Direction = appquery.SortID, appquery.Descending
	byID, err := store.PageSigningKeys(ctx, request)
	if err != nil || len(byID.Items) != 2 || byID.Items[0].ID != "key_c" || byID.Items[1].ID != "key_b" {
		t.Fatalf("descending ID page=%#v error=%v", byID, err)
	}
	request.After = &appquery.SortKey{Value: "key_b", ID: "key_a"}
	if _, err := store.PageSigningKeys(ctx, request); !errors.Is(err, appquery.ErrInvalidCursor) {
		t.Fatalf("malformed cursor error=%v", err)
	}
	request.After = nil
	request.TenantID = "tenant_other"
	other, err := store.PageSigningKeys(ctx, request)
	if err != nil || len(other.Items) != 1 || other.Items[0].ID != "key_other" {
		t.Fatalf("foreign tenant page=%#v error=%v", other, err)
	}
}

func TestPostgresSigningKeyQueryIndexMigrationRoundTrip(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	check := func(want bool) {
		t.Helper()
		rows, err := store.pool.Query(t.Context(), `SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = current_schema() AND indexname IN ('signing_keys_tenant_created_id_idx', 'signing_keys_tenant_id_idx')`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		indexes := map[string]string{}
		for rows.Next() {
			var name, definition string
			if err := rows.Scan(&name, &definition); err != nil {
				t.Fatal(err)
			}
			indexes[name] = definition
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		for name, columns := range map[string]string{
			"signing_keys_tenant_created_id_idx": "(tenant_id, created_at, id)",
			"signing_keys_tenant_id_idx":         "(tenant_id, id)",
		} {
			if want && !strings.Contains(indexes[name], columns) {
				t.Fatalf("missing signing key index %q: %q", name, indexes[name])
			}
			if !want && indexes[name] != "" {
				t.Fatalf("down migration retained signing key index %q", name)
			}
		}
	}
	check(true)
	for _, migration := range []struct {
		file string
		want bool
	}{
		{file: "../../../migrations/20260929000100_signing_key_list_indexes.down.sql"},
		{file: "../../../migrations/20260929000100_signing_key_list_indexes.up.sql", want: true},
	} {
		statement, err := os.ReadFile(migration.file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(t.Context(), string(statement)); err != nil {
			t.Fatalf("run signing key index migration %q: %v", migration.file, err)
		}
		check(migration.want)
	}
}
