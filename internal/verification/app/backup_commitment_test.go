package app

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestBackupStateDigesterCanonicalizesRowsWithoutNumericPrecisionLoss(t *testing.T) {
	resources := []BackupCommitmentResource{{Name: "products", Columns: []string{"id", "tenant_id", "metadata"}}}
	digest := func(raw string) string {
		t.Helper()
		d, err := NewBackupStateDigester("tenant", resources)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.Append("products", "product", []byte(raw)); err != nil {
			t.Fatal(err)
		}
		h, rows, bytes, err := d.Finish()
		if err != nil || rows != 1 || bytes < 1 {
			t.Fatal(h, rows, bytes, err)
		}
		return h
	}
	a := digest(`{"id":"product","tenant_id":"tenant","metadata":{"number":9007199254740992,"a":true}}`)
	if digest(`{"metadata":{"a":true,"number":9007199254740992},"tenant_id":"tenant","id":"product"}`) != a {
		t.Fatal("JSON key order changes commitment")
	}
	if digest(`{"id":"product","tenant_id":"tenant","metadata":{"number":9007199254740993,"a":true}}`) == a {
		t.Fatal("adjacent large integers collapse")
	}
	for _, raw := range []string{`null`, `[]`, `{} {}`, `{"tenant_id":"other"}`, `{"tenant_id":"tenant","unexpected":true}`} {
		d, _ := NewBackupStateDigester("tenant", resources)
		if err := d.Append("products", "product", []byte(raw)); !errors.Is(err, ErrConflict) {
			t.Fatal(raw, err)
		}
		if _, _, _, err := d.Finish(); !errors.Is(err, ErrConflict) {
			t.Fatal("partial digest published", err)
		}
	}
}

func TestBackupStateDigesterNeverPublishesOverflowPrefix(t *testing.T) {
	d, err := NewBackupStateDigester("tenant", []BackupCommitmentResource{{Name: "products", Columns: []string{"id", "tenant_id"}}})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxBackupStateCommitmentRows; i++ {
		key := fmt.Sprintf("r%06d", i)
		if err := d.Append("products", key, []byte(fmt.Sprintf(`{"id":%q,"tenant_id":"tenant"}`, key))); err != nil {
			t.Fatal(i, err)
		}
	}
	if err := d.Append("products", "z", []byte(`{"id":"z","tenant_id":"tenant"}`)); !errors.Is(err, ErrConflict) {
		t.Fatal("row budget bypass", err)
	}
	if hash, _, _, err := d.Finish(); !errors.Is(err, ErrConflict) || hash != "" {
		t.Fatal("partial digest published", hash, err)
	}
	d, _ = NewBackupStateDigester("tenant", []BackupCommitmentResource{{Name: "products", Columns: []string{"id", "tenant_id", "name"}}})
	for i := 0; ; i++ {
		key := fmt.Sprintf("r%06d", i)
		err := d.Append("products", key, []byte(fmt.Sprintf(`{"id":%q,"tenant_id":"tenant","name":%q}`, key, strings.Repeat("x", 4096))))
		if err != nil {
			if !errors.Is(err, ErrConflict) || d.rows >= MaxBackupStateCommitmentRows {
				t.Fatal("encoded byte budget bypass", i, err)
			}
			break
		}
	}
	if hash, _, _, err := d.Finish(); !errors.Is(err, ErrConflict) || hash != "" {
		t.Fatal("byte-truncated digest published", hash, err)
	}
}
func TestBackupStateDigesterRejectsBadOrderBoundsAndIncompleteRows(t *testing.T) {
	resources := []BackupCommitmentResource{{Name: "products", Columns: []string{"id", "tenant_id"}}, {Name: "releases", Columns: []string{"id", "tenant_id"}}}
	for _, tc := range []struct{ resource, key, body string }{{"unknown", "a", `{"id":"a","tenant_id":"tenant"}`}, {"products", "", `{"id":"a","tenant_id":"tenant"}`}, {"products", "a", `{"tenant_id":"tenant"}`}, {"products", "a", `{"id":"a","tenant_id":"tenant","hash":"secret"}`}} {
		d, _ := NewBackupStateDigester("tenant", resources)
		if err := d.Append(tc.resource, tc.key, []byte(tc.body)); !errors.Is(err, ErrConflict) {
			t.Fatal(tc, err)
		}
	}
	for _, key := range []string{"a", "b"} {
		d, _ := NewBackupStateDigester("tenant", resources)
		_ = d.Append("products", "b", []byte(`{"id":"b","tenant_id":"tenant"}`))
		if err := d.Append("products", key, []byte(`{"id":"a","tenant_id":"tenant"}`)); !errors.Is(err, ErrConflict) {
			t.Fatal("duplicate or descending key", key, err)
		}
	}
	d, _ := NewBackupStateDigester("tenant", resources)
	_ = d.Append("releases", "a", []byte(`{"id":"a","tenant_id":"tenant"}`))
	if err := d.Append("products", "b", []byte(`{"id":"b","tenant_id":"tenant"}`)); !errors.Is(err, ErrConflict) {
		t.Fatal("descending resource", err)
	}
	d, _ = NewBackupStateDigester("tenant", resources)
	if err := d.Append("products", "a", []byte(strings.Repeat("x", MaxBackupStateCommitmentBytes+1))); !errors.Is(err, ErrConflict) {
		t.Fatal("oversized row", err)
	}
	for _, bad := range [][]BackupCommitmentResource{nil, {{Name: "products"}}, {{Name: "products", Columns: []string{"id", "id"}}}, {{Name: "products", Columns: []string{"id"}}, {Name: "products", Columns: []string{"id"}}}} {
		if d, err := NewBackupStateDigester("tenant", bad); !errors.Is(err, ErrValidation) || d != nil {
			t.Fatal(d, err)
		}
	}
}
